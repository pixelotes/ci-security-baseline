#!/usr/bin/env python3
"""Evaluate the Dependency-Track result and decide whether CD continues.

Only NON-suppressed findings count: a suppression in DT carries a
justification, an owner and a history, which is exactly what a flat Trivy
threshold lacks.
"""
import argparse
import json
import os
import pathlib
import sys

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"]


def load(path: str) -> list:
    p = pathlib.Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text() or "[]")
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--violations", required=True)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--fail-on", default="high")
    args = ap.parse_args()

    findings = [f for f in load(args.findings) if not f.get("analysis", {}).get("isSuppressed")]
    violations = [v for v in load(args.violations) if not v.get("analysis", {}).get("suppressed")]

    counts = {s: 0 for s in ORDER}
    for f in findings:
        sev = str(f.get("vulnerability", {}).get("severity", "UNASSIGNED")).upper()
        counts[sev] = counts.get(sev, 0) + 1

    lines = ["## Dependency-Track", ""]
    lines.append(" | ".join(f"{s.title()}: {counts.get(s, 0)}" for s in ORDER[:4]))
    lines.append("")
    if violations:
        lines.append(f"**{len(violations)} active policy violation(s)**")
        for v in violations[:20]:
            comp = v.get("component", {})
            lines.append(
                f"- `{comp.get('name')}@{comp.get('version')}` — "
                f"{v.get('type')} / {v.get('policyCondition', {}).get('policy', {}).get('name')}"
            )
        lines.append("")

    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        pathlib.Path(summary).open("a").write("\n".join(lines) + "\n")
    print("\n".join(lines))

    threshold = args.fail_on.upper()
    if threshold == "NONE":
        return 0
    limit = ORDER.index(threshold) if threshold in ORDER else ORDER.index("HIGH")
    blocking = sum(counts.get(s, 0) for s in ORDER[: limit + 1])

    if violations:
        print(f"dtrack: {len(violations)} policy violation(s) — stopping the publication",
              file=sys.stderr)
        return 1
    if blocking:
        print(f"dtrack: {blocking} unsuppressed finding(s) >= {threshold} — stopping the publication",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
