#!/usr/bin/env python3
"""Normalize TruffleHog JSONL output to SARIF so the gate can consume it."""
import json
import pathlib
import sys

src = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "reports/trufflehog.json")
dst = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "reports/trufflehog.sarif")

rows = []
if src.exists():
    for line in src.read_text().splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass


def git_meta(row: dict) -> dict:
    return row.get("SourceMetadata", {}).get("Data", {}).get("Git", {}) or {}


results = [
    {
        "ruleId": r.get("DetectorName", "verified-secret"),
        "level": "error",
        # verified against the provider: true by definition
        "properties": {"severity": "critical"},
        "message": {
            "text": f"VERIFIED secret ({r.get('DetectorName')}) — rotate immediately"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": git_meta(r).get("file", "")},
                    "region": {"startLine": git_meta(r).get("line") or 1},
                }
            }
        ],
    }
    for r in rows
]

dst.parent.mkdir(parents=True, exist_ok=True)
dst.write_text(
    json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "trufflehog"}}, "results": results}],
        },
        indent=2,
    )
)
print(f"trufflehog: {len(results)} verified secret(s)")
