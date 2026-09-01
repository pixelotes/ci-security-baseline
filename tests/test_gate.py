"""Tests del gate: es la pieza que decide, así que es la que se prueba."""
import importlib.util
import json
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gate", ROOT / "actions" / "gate" / "gate.py")
gate = importlib.util.module_from_spec(spec)
sys.modules["gate"] = gate   # dataclasses lo necesita registrado
spec.loader.exec_module(gate)


def sarif(tool, results):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool}}, "results": results}],
    }


def result(rule, level="error", sev=None, path="src/App.java", line=10, msg="x"):
    props = {}
    if sev is not None:
        props["security-severity"] = str(sev)
    return {
        "ruleId": rule,
        "level": level,
        "properties": props,
        "message": {"text": msg},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line}}}],
    }


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "reports").mkdir()
    return tmp_path


def write_sarif(ws, name, doc):
    (ws / "reports" / f"{name}.sarif").write_text(json.dumps(doc))


def run(ws, args=()):
    return subprocess.run(
        [sys.executable, str(ROOT / "actions" / "gate" / "gate.py"),
         "--reports", "reports",
         "--config", ".security-baseline.yml",
         "--severity-map", str(ROOT / "policy" / "severity-map.yml"),
         "--repo", ".", *args],
        cwd=ws, capture_output=True, text=True,
    )


# ---------------------------------------------------------------- severidad

def test_cvss_manda_sobre_el_level():
    smap = {"levels": {"warning": "medium"}}
    sev = gate.normalize_severity("trivy", "CVE-1", "warning", {"security-severity": "9.4"}, smap)
    assert sev == "critical"


def test_override_por_herramienta_manda_sobre_cvss():
    smap = {"overrides": {"trufflehog": {"*": "critical"}}}
    sev = gate.normalize_severity("trufflehog", "AWS", "note", {"security-severity": "1.0"}, smap)
    assert sev == "critical", "un secreto verificado es crítico pase lo que pase"


def test_level_como_ultimo_recurso():
    sev = gate.normalize_severity("semgrep", "r", "error", {}, {})
    assert sev == "high"


# ---------------------------------------------------------------- decisión

def test_bloquea_por_encima_del_umbral(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-1", sev=9.8)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\ngate:\n  severity: high\n")
    r = run(workspace)
    assert r.returncode == 1
    assert "bloquean este PR" in (workspace / "reports" / "gate-summary.md").read_text()


def test_no_bloquea_por_debajo_del_umbral(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-2", sev=5.0)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\ngate:\n  severity: high\n")
    assert run(workspace).returncode == 0


def test_sin_hallazgos_pasa(workspace):
    write_sarif(workspace, "semgrep", sarif("semgrep", []))
    (workspace / ".security-baseline.yml").write_text("version: 1\n")
    assert run(workspace).returncode == 0


# ---------------------------------------------------------------- excepciones

def test_excepcion_vigente_desbloquea(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-3", sev=9.8, path="pom.xml")]))
    futuro = (date.today() + timedelta(days=30)).isoformat()
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\n"
        "gate:\n  severity: high\n"
        "exceptions:\n"
        "  - id: CVE-3\n"
        "    tool: trivy\n"
        "    scope: 'pom.xml'\n"
        "    reason: 'no explotable'\n"
        "    owner: '@equipo'\n"
        f"    expires: '{futuro}'\n"
    )
    assert run(workspace).returncode == 0


def test_excepcion_vencida_hace_fallar_el_gate(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-4", sev=9.8, path="pom.xml")]))
    pasado = (date.today() - timedelta(days=1)).isoformat()
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\ngate:\n  severity: high\n"
        "exceptions:\n  - id: CVE-4\n    owner: '@equipo'\n"
        f"    expires: '{pasado}'\n"
    )
    r = run(workspace)
    assert r.returncode == 1
    assert "venció" in (workspace / "reports" / "gate-summary.md").read_text()


def test_excepcion_sin_caducidad_es_error_de_configuracion(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-5", sev=2.0)]))
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\ngate:\n  severity: high\n"
        "exceptions:\n  - id: CVE-5\n    owner: '@equipo'\n"
    )
    r = run(workspace)
    assert r.returncode == 1, "sin expires el gate debe fallar aunque no haya bloqueantes"
    assert "obligatorio" in (workspace / "reports" / "gate-summary.md").read_text()


def test_excepcion_respeta_el_scope(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-6", sev=9.8, path="src/Otro.java")]))
    futuro = (date.today() + timedelta(days=30)).isoformat()
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\ngate:\n  severity: high\n"
        "exceptions:\n  - id: CVE-6\n    scope: 'pom.xml'\n    owner: '@e'\n"
        f"    expires: '{futuro}'\n"
    )
    assert run(workspace).returncode == 1, "el scope no casa: no debe aplicarse la excepción"


# ---------------------------------------------------------------- fecha de corte

def test_cutoff_degrada_lo_antiguo_a_aviso(workspace):
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=workspace, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=workspace, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=workspace, check=True)
    (workspace / "viejo.py").write_text("\n".join(f"linea {i}" for i in range(20)))
    subprocess.run(["git", "add", "-A"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "inicial", "--date", "2020-01-01T00:00:00"],
        cwd=workspace, check=True,
        env={"GIT_AUTHOR_DATE": "2020-01-01T00:00:00", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00",
             "PATH": "/usr/bin:/bin", "HOME": str(workspace)},
    )
    write_sarif(workspace, "semgrep",
                sarif("semgrep", [result("r1", sev=9.9, path="viejo.py", line=3)]))
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\ngate:\n  severity: high\n  cutoff: '2026-01-01'\n"
    )
    r = run(workspace)
    summary = (workspace / "reports" / "gate-summary.md").read_text()
    assert r.returncode == 0, summary
    assert "anteriores a la fecha de corte" in summary


def test_sin_cutoff_lo_antiguo_tambien_bloquea(workspace):
    write_sarif(workspace, "semgrep", sarif("semgrep", [result("r2", sev=9.9)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\ngate:\n  severity: high\n")
    assert run(workspace).returncode == 1


# ---------------------------------------------------------------- robustez

def test_sarif_corrupto_no_tumba_el_gate(workspace):
    (workspace / "reports" / "roto.sarif").write_text("{ esto no es json")
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-7", sev=1.0)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\n")
    assert run(workspace).returncode == 0


def test_sin_fichero_de_configuracion_usa_defectos(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-8", sev=9.9)]))
    assert run(workspace).returncode == 1, "por defecto bloquea high y superior"


def test_resultado_json_es_consumible(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-9", sev=9.9)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\n")
    run(workspace)
    data = json.loads((workspace / "reports" / "gate-result.json").read_text())
    assert data["severity_threshold"] == "high"
    assert data["findings"][0]["severity"] == "critical"
    assert data["findings"][0]["status"] == "blocking"
