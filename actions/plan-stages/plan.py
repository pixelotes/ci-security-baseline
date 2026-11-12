#!/usr/bin/env python3
"""
plan.py — decide which pipeline stages run.

Reads the optional `stages:` list from .security-baseline.yml and writes the
result to $GITHUB_OUTPUT as `stages=,lint,sast,` (comma-wrapped, so that the
workflows can test membership with contains(..., ',lint,') without matching
substrings).

Rules:
  - no config file, or no `stages` key  -> every stage runs
  - `all` is accepted as a shortcut for every stage
  - an unknown stage name FAILS the plan. A typo must never silently turn a
    security stage off; the gate refuses to pass when the plan failed.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("plan: PyYAML is missing (pip install pyyaml)")

# canonical order; also the order used in the summary
STAGES = {
    "build":          "build and tests",
    "lint":           "linters and formatters",
    "sast":           "Opengrep",
    "secret-scan":    "Gitleaks on the PR diff",
    "sca":            "OSV-Scanner (plus govulncheck for Go)",
    "container-scan": "image build and Trivy image scan",
    "iac-scan":       "Checkov and Trivy config",
    "quality":        "complexity and duplication report (informational)",
}
DEFAULT = list(STAGES)


def resolve(config: Path) -> tuple[list[str], list[str]]:
    """Return (enabled stages in canonical order, error messages)."""
    if not config.exists():
        return list(DEFAULT), []

    raw = yaml.safe_load(config.read_text()) or {}
    if not isinstance(raw, dict) or "stages" not in raw or raw["stages"] is None:
        return list(DEFAULT), []

    listed = raw["stages"]
    if not isinstance(listed, list) or not all(isinstance(s, str) for s in listed):
        return [], ["`stages` must be a list of stage names"]

    names = [s.strip().lower() for s in listed]
    unknown = sorted({n for n in names if n != "all" and n not in STAGES})
    if unknown:
        valid = ", ".join(["all", *STAGES])
        return [], [f"unknown stage(s): {', '.join(unknown)} (valid: {valid})"]

    wanted = set(names)
    if "all" in wanted:
        wanted |= set(DEFAULT)
    return [s for s in STAGES if s in wanted], []


def summary(enabled: list[str]) -> str:
    rows = ["## Security baseline · stage plan", "",
            "| Stage | Runs | What |", "|---|---|---|"]
    for name, what in STAGES.items():
        mark = "✅" if name in enabled else "⏭️ skipped"
        rows.append(f"| `{name}` | {mark} | {what} |")
    rows += ["", "<sub>Stages come from `stages:` in `.security-baseline.yml`; "
                 "that file is protected by CODEOWNERS.</sub>"]
    return "\n".join(rows) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=".security-baseline.yml")
    args = ap.parse_args()

    enabled, errors = resolve(Path(args.config))
    if errors:
        for e in errors:
            print(f"::error::plan: {e}")
        return 1

    skipped = [s for s in DEFAULT if s not in enabled]
    if skipped:
        print(f"::notice::plan: skipped stages: {', '.join(skipped)}")
    if not enabled:
        print("::warning::plan: no stage enabled, only the gate will run")
    print(f"plan: enabled stages: {', '.join(enabled) or '(none)'}")

    out = os.environ.get("GITHUB_OUTPUT")
    value = "," + ",".join(enabled) + "," if enabled else ","
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"stages={value}\n")
    else:
        print(f"stages={value}")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary(enabled))
    return 0


if __name__ == "__main__":
    sys.exit(main())
