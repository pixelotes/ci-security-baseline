"""Gate tests: it is the piece that decides, so it is the one under test."""
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
sys.modules["gate"] = gate   # dataclasses needs it registered
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


# ---------------------------------------------------------------- severity

def test_cvss_wins_over_level():
    smap = {"levels": {"warning": "medium"}}
    sev = gate.normalize_severity("trivy", "CVE-1", "warning", {"security-severity": "9.4"}, smap)
    assert sev == "critical"


def test_per_tool_override_wins_over_cvss():
    smap = {"overrides": {"trufflehog": {"*": "critical"}}}
    sev = gate.normalize_severity("trufflehog", "AWS", "note", {"security-severity": "1.0"}, smap)
    assert sev == "critical", "a verified secret is critical no matter what"


def test_level_is_the_last_resort():
    sev = gate.normalize_severity("semgrep", "r", "error", {}, {})
    assert sev == "high"


# ---------------------------------------------------------------- decision

def test_blocks_above_the_threshold(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-1", sev=9.8)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\ngate:\n  severity: high\n")
    r = run(workspace)
    assert r.returncode == 1
    assert "block this PR" in (workspace / "reports" / "gate-summary.md").read_text()


def test_does_not_block_below_the_threshold(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-2", sev=5.0)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\ngate:\n  severity: high\n")
    assert run(workspace).returncode == 0


def test_no_findings_passes(workspace):
    write_sarif(workspace, "semgrep", sarif("semgrep", []))
    (workspace / ".security-baseline.yml").write_text("version: 1\n")
    assert run(workspace).returncode == 0


# ---------------------------------------------------------------- exceptions

def test_active_exception_unblocks(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-3", sev=9.8, path="pom.xml")]))
    future = (date.today() + timedelta(days=30)).isoformat()
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\n"
        "gate:\n  severity: high\n"
        "exceptions:\n"
        "  - id: CVE-3\n"
        "    tool: trivy\n"
        "    scope: 'pom.xml'\n"
        "    reason: 'not exploitable'\n"
        "    owner: '@team'\n"
        f"    expires: '{future}'\n"
    )
    assert run(workspace).returncode == 0


def test_expired_exception_fails_the_gate(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-4", sev=9.8, path="pom.xml")]))
    past = (date.today() - timedelta(days=1)).isoformat()
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\ngate:\n  severity: high\n"
        "exceptions:\n  - id: CVE-4\n    owner: '@team'\n"
        f"    expires: '{past}'\n"
    )
    r = run(workspace)
    assert r.returncode == 1
    assert "expired" in (workspace / "reports" / "gate-summary.md").read_text()


def test_exception_without_expiry_is_a_configuration_error(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-5", sev=2.0)]))
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\ngate:\n  severity: high\n"
        "exceptions:\n  - id: CVE-5\n    owner: '@team'\n"
    )
    r = run(workspace)
    assert r.returncode == 1, "without expires the gate must fail even with no blocking findings"
    assert "mandatory" in (workspace / "reports" / "gate-summary.md").read_text()


def test_exception_respects_the_scope(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-6", sev=9.8, path="src/Other.java")]))
    future = (date.today() + timedelta(days=30)).isoformat()
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\ngate:\n  severity: high\n"
        "exceptions:\n  - id: CVE-6\n    scope: 'pom.xml'\n    owner: '@e'\n"
        f"    expires: '{future}'\n"
    )
    assert run(workspace).returncode == 1, "the scope does not match: the exception must not apply"


# ---------------------------------------------------------------- cutoff date

def test_cutoff_downgrades_old_findings_to_warnings(workspace):
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=workspace, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=workspace, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=workspace, check=True)
    (workspace / "old.py").write_text("\n".join(f"line {i}" for i in range(20)))
    subprocess.run(["git", "add", "-A"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "initial", "--date", "2020-01-01T00:00:00"],
        cwd=workspace, check=True,
        env={"GIT_AUTHOR_DATE": "2020-01-01T00:00:00", "GIT_COMMITTER_DATE": "2020-01-01T00:00:00",
             "PATH": "/usr/bin:/bin", "HOME": str(workspace)},
    )
    write_sarif(workspace, "semgrep",
                sarif("semgrep", [result("r1", sev=9.9, path="old.py", line=3)]))
    (workspace / ".security-baseline.yml").write_text(
        "version: 1\ngate:\n  severity: high\n  cutoff: '2026-01-01'\n"
    )
    r = run(workspace)
    summary = (workspace / "reports" / "gate-summary.md").read_text()
    assert r.returncode == 0, summary
    assert "before the cutoff date" in summary


def test_without_cutoff_old_findings_also_block(workspace):
    write_sarif(workspace, "semgrep", sarif("semgrep", [result("r2", sev=9.9)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\ngate:\n  severity: high\n")
    assert run(workspace).returncode == 1


# ---------------------------------------------------------------- robustness

def test_corrupt_sarif_does_not_crash_the_gate(workspace):
    (workspace / "reports" / "broken.sarif").write_text("{ this is not json")
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-7", sev=1.0)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\n")
    assert run(workspace).returncode == 0


def test_missing_config_file_uses_defaults(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-8", sev=9.9)]))
    assert run(workspace).returncode == 1, "by default it blocks high and above"


def test_json_result_is_consumable(workspace):
    write_sarif(workspace, "trivy", sarif("trivy", [result("CVE-9", sev=9.9)]))
    (workspace / ".security-baseline.yml").write_text("version: 1\n")
    run(workspace)
    data = json.loads((workspace / "reports" / "gate-result.json").read_text())
    assert data["severity_threshold"] == "high"
    assert data["findings"][0]["severity"] == "critical"
    assert data["findings"][0]["status"] == "blocking"


def test_overrides_match_the_tool_name_loosely():
    """SARIF files carry "Semgrep OSS", "Opengrep OSS"...; the key is `semgrep`."""
    smap = {"overrides": {"semgrep": {"*.security.*": "high"},
                          "opengrep": {"*.security.*": "high"}}}
    for tool in ("Semgrep OSS", "SEMGREP", "Opengrep OSS"):
        sev = gate.normalize_severity(tool, "python.lang.security.x", "note", {}, smap)
        assert sev == "high", tool
    # a tool without an override follows the normal path
    assert gate.normalize_severity("Trivy", "python.lang.security.x", "note", {}, smap) == "low"


def test_shipped_severity_map_covers_opengrep_like_semgrep():
    import yaml
    from pathlib import Path
    smap = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / "policy" / "severity-map.yml").read_text())
    assert smap["overrides"]["opengrep"] == smap["overrides"]["semgrep"]


def test_duplicate_results_are_collapsed(tmp_path):
    """osv-scanner emits every result twice."""
    res = {"ruleId": "CVE-2020-1747", "level": "warning",
           "message": {"text": "pyyaml@5.3 is vulnerable"},
           "locations": [{"physicalLocation": {
               "artifactLocation": {"uri": "requirements.txt"},
               "region": {"startLine": 1}}}]}
    other = dict(res, message={"text": "otro-paquete@1 is vulnerable"})
    doc = {"runs": [{"tool": {"driver": {"name": "osv-scanner"}},
                     "results": [res, dict(res), other]}]}
    path = tmp_path / "osv.sarif"
    path.write_text(json.dumps(doc))
    assert len(gate.parse_sarif(path, {})) == 2
