#!/usr/bin/env python3
"""
gate.py — agregador de hallazgos del security baseline.

Lee todos los SARIF producidos por los escáneres, normaliza la severidad entre
herramientas, aplica las excepciones declaradas en .security-baseline.yml y la
fecha de corte, y decide si el pull request se bloquea.

Es el único punto del pipeline que decide. Los escáneres solo reportan.

Salida:
  - reports/gate-summary.md   resumen en markdown (comentario del PR + job summary)
  - reports/gate-result.json  resultado estructurado (para el backend central)
  - exit 0 / 1
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("gate: falta PyYAML (pip install pyyaml)")

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

# ---------------------------------------------------------------- modelo


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str
    message: str
    path: str = ""
    line: int = 0
    # estado asignado por el gate
    status: str = "blocking"          # blocking | excepted | pre-cutoff | below-threshold
    note: str = ""
    introduced: str = ""              # fecha ISO según git blame, si se pudo calcular

    @property
    def key(self) -> str:
        return f"{self.tool}:{self.rule_id}:{self.path}:{self.line}"


@dataclass
class Config:
    severity: str = "high"
    cutoff: str | None = None
    exceptions: list = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "Config":
        if not path.exists():
            return cls()
        raw = yaml.safe_load(path.read_text()) or {}
        gate = raw.get("gate") or {}
        return cls(
            severity=str(gate.get("severity", "high")).lower(),
            cutoff=str(gate["cutoff"]) if gate.get("cutoff") else None,
            exceptions=raw.get("exceptions") or [],
        )


# ---------------------------------------------------------------- severidad


def load_severity_map(path: Path) -> dict:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def normalize_severity(tool: str, rule_id: str, level: str, props: dict, smap: dict) -> str:
    """Cada herramienta usa su propia escala. Esto las lleva a una sola."""
    overrides = (smap.get("overrides") or {}).get(tool) or {}
    for pattern, sev in overrides.items():
        if fnmatch.fnmatch(rule_id, pattern):
            return sev.lower()

    # CVSS embebido: es la señal más fiable cuando existe (trivy, grype, semgrep)
    raw_cvss = props.get("security-severity")
    if raw_cvss is not None:
        try:
            score = float(raw_cvss)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score > 0:
                return "low"

    # etiqueta textual propia de la herramienta
    tag = str(props.get("severity") or props.get("problem.severity") or "").lower()
    if tag in RANK:
        return tag

    defaults = smap.get("levels") or {"error": "high", "warning": "medium", "note": "low"}
    return defaults.get(str(level).lower(), "medium")


# ---------------------------------------------------------------- SARIF


def parse_sarif(path: Path, smap: dict) -> list[Finding]:
    try:
        doc = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"gate: aviso — no se pudo leer {path.name}: {exc}", file=sys.stderr)
        return []

    findings: list[Finding] = []
    for run in doc.get("runs", []):
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool = driver.get("name") or path.stem

        # las reglas traen metadatos que los resultados no repiten
        rules: dict[str, dict] = {}
        for rule in driver.get("rules") or []:
            if rule.get("id"):
                rules[rule["id"]] = rule

        for res in run.get("results") or []:
            rule_id = res.get("ruleId") or res.get("rule", {}).get("id") or "unknown"
            props = dict((rules.get(rule_id) or {}).get("properties") or {})
            props.update(res.get("properties") or {})

            severity = normalize_severity(
                tool, rule_id, res.get("level", "warning"), props, smap
            )

            loc_path, loc_line = "", 0
            for loc in res.get("locations") or []:
                phys = (loc.get("physicalLocation") or {})
                loc_path = (phys.get("artifactLocation") or {}).get("uri", "")
                loc_line = int((phys.get("region") or {}).get("startLine") or 0)
                break

            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    severity=severity,
                    message=((res.get("message") or {}).get("text") or "").strip()[:400],
                    path=loc_path.removeprefix("file://").lstrip("/"),
                    line=loc_line,
                )
            )
    return findings


# ---------------------------------------------------------------- políticas


def match_exception(f: Finding, exc: dict) -> bool:
    if str(exc.get("id", "")) not in ("", f.rule_id):
        # también se admite el CVE dentro del mensaje (trivy lo pone en el ruleId,
        # pero otras herramientas lo dejan solo en el texto)
        if str(exc.get("id")) not in f.message:
            return False
    tool = exc.get("tool")
    if tool and tool.lower() not in f.tool.lower():
        return False
    scope = exc.get("scope")
    if scope and not fnmatch.fnmatch(f.path, scope):
        return False
    return True


def apply_exceptions(findings: list[Finding], cfg: Config) -> list[str]:
    """Devuelve la lista de errores de configuración encontrados."""
    problems: list[str] = []
    today = date.today()

    for i, exc in enumerate(cfg.exceptions):
        where = exc.get("id") or exc.get("scope") or f"#{i}"
        expires = exc.get("expires")
        if not expires:
            problems.append(f"excepción `{where}` sin campo `expires` — es obligatorio")
            continue
        if not exc.get("owner"):
            problems.append(f"excepción `{where}` sin `owner`")
        try:
            exp = datetime.strptime(str(expires), "%Y-%m-%d").date()
        except ValueError:
            problems.append(f"excepción `{where}` con fecha `{expires}` no válida (YYYY-MM-DD)")
            continue
        if exp < today:
            problems.append(
                f"excepción `{where}` venció el {exp.isoformat()} — renuévala o corrige el hallazgo"
            )
            continue
        for f in findings:
            if f.status == "blocking" and match_exception(f, exc):
                f.status = "excepted"
                f.note = f"excepción de {exc.get('owner')} hasta {exp.isoformat()}"
    return problems


def blame_date(repo: Path, path: str, line: int) -> str:
    if not path or line <= 0:
        return ""
    try:
        out = subprocess.run(
            ["git", "blame", "-L", f"{line},{line}", "--porcelain", "--", path],
            cwd=repo, capture_output=True, text=True, timeout=15,
        )
        if out.returncode != 0:
            return ""
        for row in out.stdout.splitlines():
            if row.startswith("author-time "):
                ts = int(row.split()[1])
                return datetime.utcfromtimestamp(ts).date().isoformat()
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""
    return ""


def apply_cutoff(findings: list[Finding], cfg: Config, repo: Path) -> None:
    """Lo introducido antes de la fecha de corte se degrada a aviso.

    Sin esto, aplicar el gate de golpe sobre un parque con años de deuda
    bloquea todos los PRs la primera semana y alguien acaba desactivando
    el required check.
    """
    if not cfg.cutoff:
        return
    try:
        cutoff = datetime.strptime(cfg.cutoff, "%Y-%m-%d").date()
    except ValueError:
        print(f"gate: aviso — cutoff `{cfg.cutoff}` no válido, se ignora", file=sys.stderr)
        return

    for f in findings:
        if f.status != "blocking":
            continue
        f.introduced = blame_date(repo, f.path, f.line)
        if f.introduced and date.fromisoformat(f.introduced) < cutoff:
            f.status = "pre-cutoff"
            f.note = f"introducido el {f.introduced}, anterior al corte {cutoff.isoformat()}"


def apply_threshold(findings: list[Finding], cfg: Config) -> None:
    limit = RANK.get(cfg.severity, RANK["high"])
    for f in findings:
        if f.status == "blocking" and RANK[f.severity] > limit:
            f.status = "below-threshold"


# ---------------------------------------------------------------- salida


ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪", "info": "⚪"}


def render(findings: list[Finding], cfg: Config, problems: list[str]) -> str:
    blocking = [f for f in findings if f.status == "blocking"]
    excepted = [f for f in findings if f.status == "excepted"]
    precut = [f for f in findings if f.status == "pre-cutoff"]

    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}

    out = ["<!-- baseline-security-baseline-gate -->", "## Security baseline", ""]

    if problems:
        out += ["### ⛔ Configuración inválida", ""]
        out += [f"- {p}" for p in problems] + [""]

    if blocking:
        out.append(f"**{len(blocking)} hallazgo(s) bloquean este PR** "
                   f"(umbral: `{cfg.severity}` y superior)")
    elif problems:
        out.append("**El gate falla por errores en `.security-baseline.yml`** (ver arriba)")
    else:
        out.append("**Sin hallazgos bloqueantes.**")
    out.append("")

    out += [
        "| " + " | ".join(f"{ICON[s]} {s}" for s in SEVERITIES) + " |",
        "|" + "---|" * len(SEVERITIES),
        "| " + " | ".join(str(counts[s]) for s in SEVERITIES) + " |",
        "",
    ]

    if blocking:
        out += ["### Bloqueantes", "",
                "| Sev | Herramienta | Regla | Ubicación | Detalle |",
                "|---|---|---|---|---|"]
        for f in sorted(blocking, key=lambda x: RANK[x.severity])[:40]:
            loc = f"`{f.path}:{f.line}`" if f.path else "—"
            out.append(f"| {ICON[f.severity]} {f.severity} | {f.tool} | `{f.rule_id}` "
                       f"| {loc} | {f.message[:160]} |")
        if len(blocking) > 40:
            out.append(f"\n_… y {len(blocking) - 40} más. Ver los artefactos SARIF del job._")
        out.append("")

    if precut:
        out += [f"<details><summary>{len(precut)} hallazgo(s) anteriores a la fecha de corte "
                f"`{cfg.cutoff}` — avisan, no bloquean</summary>", ""]
        for f in sorted(precut, key=lambda x: RANK[x.severity])[:30]:
            out.append(f"- {ICON[f.severity]} `{f.rule_id}` en `{f.path}:{f.line}` — {f.note}")
        out += ["", "</details>", ""]

    if excepted:
        out += [f"<details><summary>{len(excepted)} hallazgo(s) con excepción activa</summary>", ""]
        for f in excepted:
            out.append(f"- `{f.rule_id}` en `{f.path or '—'}` — {f.note}")
        out += ["", "</details>", ""]

    out.append("<sub>Generado por `__ORG__/security-baseline` · "
               "las excepciones se declaran en `.security-baseline.yml` y caducan siempre.</sub>")
    return "\n".join(out)


# ---------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--config", default=".security-baseline.yml")
    ap.add_argument("--severity-map", default="policy/severity-map.yml")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--severity", default="", help="sobreescribe gate.severity del repo")
    ap.add_argument("--cutoff", default="", help="sobreescribe gate.cutoff del repo")
    args = ap.parse_args()

    reports = Path(args.reports)
    cfg = Config.load(Path(args.config))
    if args.severity:
        cfg.severity = args.severity.lower()
    if args.cutoff:
        cfg.cutoff = args.cutoff
    smap = load_severity_map(Path(args.severity_map))

    sarifs = sorted(reports.glob("**/*.sarif"))
    findings: list[Finding] = []
    for s in sarifs:
        findings.extend(parse_sarif(s, smap))

    print(f"gate: {len(sarifs)} fichero(s) SARIF, {len(findings)} hallazgo(s) en bruto")

    apply_threshold(findings, cfg)
    problems = apply_exceptions(findings, cfg)
    apply_cutoff(findings, cfg, Path(args.repo))

    summary = render(findings, cfg, problems)
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "gate-summary.md").write_text(summary)
    (reports / "gate-result.json").write_text(json.dumps({
        "severity_threshold": cfg.severity,
        "cutoff": cfg.cutoff,
        "config_problems": problems,
        "findings": [asdict(f) for f in findings],
    }, indent=2))

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a") as fh:
            fh.write(summary + "\n")

    blocking = [f for f in findings if f.status == "blocking"]
    if gh_out := os.environ.get("GITHUB_OUTPUT"):
        with open(gh_out, "a") as fh:
            fh.write(f"blocking-count={len(blocking)}\n")
            fh.write(f"passed={'false' if (blocking or problems) else 'true'}\n")

    if problems:
        print(f"gate: {len(problems)} error(es) de configuración", file=sys.stderr)
    if blocking:
        print(f"gate: {len(blocking)} hallazgo(s) bloqueante(s)", file=sys.stderr)
    return 1 if (blocking or problems) else 0


if __name__ == "__main__":
    sys.exit(main())
