#!/usr/bin/env python3
"""
gate.py — findings aggregator of the security baseline.

Reads every SARIF file produced by the scanners, normalizes severity across
tools, applies the exceptions declared in .security-baseline.yml and the
cutoff date, and decides whether the pull request is blocked.

It is the only point in the pipeline that decides. Scanners only report.

Output:
  - reports/gate-summary.md   markdown summary (PR comment + job summary)
  - reports/gate-result.json  structured result (for a central backend)
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
    sys.exit("gate: PyYAML is missing (pip install pyyaml)")

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

# ---------------------------------------------------------------- model


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str
    message: str
    path: str = ""
    line: int = 0
    # status assigned by the gate
    status: str = "blocking"          # blocking | excepted | pre-cutoff | below-threshold
    note: str = ""
    introduced: str = ""              # ISO date from git blame, when it could be computed

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


# ---------------------------------------------------------------- severity


def load_severity_map(path: Path) -> dict:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def normalize_severity(tool: str, rule_id: str, level: str, props: dict, smap: dict) -> str:
    """Each tool uses its own scale. This brings them all to a single one."""
    # The name each tool puts in its SARIF is not the key of the table
    # ("Semgrep OSS", "Opengrep OSS", "Checkov"...), so it is compared
    # case-insensitively and by containment: the key `semgrep` matches
    # "Semgrep OSS". With an exact comparison the overrides never applied.
    tool_l = tool.lower()
    for key, overrides in (smap.get("overrides") or {}).items():
        if str(key).lower() not in tool_l:
            continue
        for pattern, sev in (overrides or {}).items():
            if fnmatch.fnmatch(rule_id, pattern):
                return sev.lower()

    # Embedded CVSS: the most reliable signal when present (trivy, grype, semgrep)
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

    # the tool's own textual label
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
        print(f"gate: warning — could not read {path.name}: {exc}", file=sys.stderr)
        return []

    findings: list[Finding] = []
    seen: set[tuple] = set()
    for run in doc.get("runs", []):
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool = driver.get("name") or path.stem

        # rules carry metadata that results do not repeat
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

            finding = Finding(
                tool=tool,
                rule_id=rule_id,
                severity=severity,
                message=((res.get("message") or {}).get("text") or "").strip()[:400],
                path=loc_path.removeprefix("file://").lstrip("/"),
                line=loc_line,
            )
            # Some scanners (osv-scanner) emit every result twice: without
            # this the count and the PR table come out inflated.
            ident = (finding.tool, finding.rule_id, finding.path, finding.line, finding.message)
            if ident in seen:
                continue
            seen.add(ident)
            findings.append(finding)
    return findings


# ---------------------------------------------------------------- policies


def match_exception(f: Finding, exc: dict) -> bool:
    if str(exc.get("id", "")) not in ("", f.rule_id):
        # the CVE is also accepted inside the message (trivy puts it in the ruleId,
        # but other tools leave it only in the text)
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
    """Return the list of configuration errors found."""
    problems: list[str] = []
    today = date.today()

    for i, exc in enumerate(cfg.exceptions):
        where = exc.get("id") or exc.get("scope") or f"#{i}"
        expires = exc.get("expires")
        if not expires:
            problems.append(f"exception `{where}` has no `expires` field — it is mandatory")
            continue
        if not exc.get("owner"):
            problems.append(f"exception `{where}` has no `owner`")
        try:
            exp = datetime.strptime(str(expires), "%Y-%m-%d").date()
        except ValueError:
            problems.append(f"exception `{where}` has an invalid date `{expires}` (YYYY-MM-DD)")
            continue
        if exp < today:
            problems.append(
                f"exception `{where}` expired on {exp.isoformat()} — renew it or fix the finding"
            )
            continue
        for f in findings:
            if f.status == "blocking" and match_exception(f, exc):
                f.status = "excepted"
                f.note = f"exception by {exc.get('owner')} until {exp.isoformat()}"
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
    """Anything introduced before the cutoff date is downgraded to a warning.

    Without this, applying the gate all at once to an estate with years of
    debt blocks every PR in the first week and someone ends up disabling
    the required check.
    """
    if not cfg.cutoff:
        return
    try:
        cutoff = datetime.strptime(cfg.cutoff, "%Y-%m-%d").date()
    except ValueError:
        print(f"gate: warning — cutoff `{cfg.cutoff}` is invalid, ignoring it", file=sys.stderr)
        return

    for f in findings:
        if f.status != "blocking":
            continue
        f.introduced = blame_date(repo, f.path, f.line)
        if f.introduced and date.fromisoformat(f.introduced) < cutoff:
            f.status = "pre-cutoff"
            f.note = f"introduced on {f.introduced}, before the cutoff {cutoff.isoformat()}"


def apply_threshold(findings: list[Finding], cfg: Config) -> None:
    limit = RANK.get(cfg.severity, RANK["high"])
    for f in findings:
        if f.status == "blocking" and RANK[f.severity] > limit:
            f.status = "below-threshold"


# ---------------------------------------------------------------- output


ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪", "info": "⚪"}


def render(findings: list[Finding], cfg: Config, problems: list[str]) -> str:
    blocking = [f for f in findings if f.status == "blocking"]
    excepted = [f for f in findings if f.status == "excepted"]
    precut = [f for f in findings if f.status == "pre-cutoff"]

    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}

    out = ["<!-- baseline-security-baseline-gate -->", "## Security baseline", ""]

    if problems:
        out += ["### ⛔ Invalid configuration", ""]
        out += [f"- {p}" for p in problems] + [""]

    if blocking:
        out.append(f"**{len(blocking)} finding(s) block this PR** "
                   f"(threshold: `{cfg.severity}` and above)")
    elif problems:
        out.append("**The gate fails because of errors in `.security-baseline.yml`** (see above)")
    else:
        out.append("**No blocking findings.**")
    out.append("")

    out += [
        "| " + " | ".join(f"{ICON[s]} {s}" for s in SEVERITIES) + " |",
        "|" + "---|" * len(SEVERITIES),
        "| " + " | ".join(str(counts[s]) for s in SEVERITIES) + " |",
        "",
    ]

    if blocking:
        out += ["### Blocking", "",
                "| Sev | Tool | Rule | Location | Details |",
                "|---|---|---|---|---|"]
        for f in sorted(blocking, key=lambda x: RANK[x.severity])[:40]:
            loc = f"`{f.path}:{f.line}`" if f.path else "—"
            out.append(f"| {ICON[f.severity]} {f.severity} | {f.tool} | `{f.rule_id}` "
                       f"| {loc} | {f.message[:160]} |")
        if len(blocking) > 40:
            out.append(f"\n_… and {len(blocking) - 40} more. See the job's SARIF artifacts._")
        out.append("")

    if precut:
        out += [f"<details><summary>{len(precut)} finding(s) before the cutoff date "
                f"`{cfg.cutoff}` — warn, do not block</summary>", ""]
        for f in sorted(precut, key=lambda x: RANK[x.severity])[:30]:
            out.append(f"- {ICON[f.severity]} `{f.rule_id}` in `{f.path}:{f.line}` — {f.note}")
        out += ["", "</details>", ""]

    if excepted:
        out += [f"<details><summary>{len(excepted)} finding(s) with an active exception</summary>", ""]
        for f in excepted:
            out.append(f"- `{f.rule_id}` in `{f.path or '—'}` — {f.note}")
        out += ["", "</details>", ""]

    out.append("<sub>Generated by `pixelotes/ci-security-baseline` · "
               "exceptions are declared in `.security-baseline.yml` and always expire.</sub>")
    return "\n".join(out)


# ---------------------------------------------------------------- main


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--config", default=".security-baseline.yml")
    ap.add_argument("--severity-map", default="policy/severity-map.yml")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--severity", default="", help="overrides the repo's gate.severity")
    ap.add_argument("--cutoff", default="", help="overrides the repo's gate.cutoff")
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

    print(f"gate: {len(sarifs)} SARIF file(s), {len(findings)} raw finding(s)")

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
        print(f"gate: {len(problems)} configuration error(s)", file=sys.stderr)
    if blocking:
        print(f"gate: {len(blocking)} blocking finding(s)", file=sys.stderr)
    return 1 if (blocking or problems) else 0


if __name__ == "__main__":
    sys.exit(main())
