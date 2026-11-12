#!/usr/bin/env python3
"""
quality.py — turn lizard (complexity) and jscpd (duplication) output into a
short markdown report for the PR comment.

Informational only: nothing here feeds the gate or can block a merge. Standard
library only, so the action needs no extra install for this step.

  lizard --csv  columns: NLOC, CCN, tokens, params, length, "name@start-end@file",
                         file, function, long_name, start, end
  jscpd json    statistics.total {percentage, clones, duplicatedLines, lines, sources}
                duplicates[] {lines, firstFile{name,start,end}, secondFile{...}}
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def read_lizard(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        for r in csv.reader(fh):
            if len(r) < 11:
                continue
            try:
                rows.append({
                    "nloc": int(r[0]), "ccn": int(r[1]), "params": int(r[3]),
                    "file": r[6].removeprefix("./"), "name": r[7],
                    "start": int(r[9]), "end": int(r[10]),
                })
            except ValueError:
                continue
    return rows


def read_jscpd(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def esc(text: str) -> str:
    """Keep a function or file name from breaking a markdown table."""
    return text.replace("|", "\\|").replace("`", "'")


def build(rows: list[dict], jscpd: dict | None, ccn_limit: int, top: int) -> str:
    out = ["<!-- baseline-quality -->",
           "## Code quality", "",
           "_Informational: this does not block the merge._", ""]

    over = sorted((r for r in rows if r["ccn"] > ccn_limit),
                  key=lambda r: (-r["ccn"], -r["nloc"]))

    out += ["| Metric | Value |", "|---|---|"]
    if jscpd and jscpd.get("statistics", {}).get("total"):
        t = jscpd["statistics"]["total"]
        out.append(f"| Duplication | **{t.get('percentage', 0):.1f}%** "
                   f"({t.get('clones', 0)} clones, "
                   f"{t.get('duplicatedLines', 0)} of {t.get('lines', 0)} lines) |")
    else:
        out.append("| Duplication | not available |")
    if rows:
        avg = sum(r["ccn"] for r in rows) / len(rows)
        out.append(f"| Functions analysed | {len(rows)} |")
        out.append(f"| Average cyclomatic complexity | {avg:.1f} |")
        out.append(f"| Functions over CCN {ccn_limit} | **{len(over)}** |")
    else:
        out.append("| Complexity | no supported source files found |")
    out.append("")

    if over:
        out += [f"### Most complex functions (CCN > {ccn_limit})", "",
                "| CCN | Lines | Function | Location |", "|---|---|---|---|"]
        for r in over[:top]:
            out.append(f"| {r['ccn']} | {r['nloc']} | `{esc(r['name'])}` | "
                       f"`{esc(r['file'])}:{r['start']}` |")
        if len(over) > top:
            out.append(f"| | | _…and {len(over) - top} more_ | |")
        out.append("")

    clones = sorted((jscpd or {}).get("duplicates") or [],
                    key=lambda d: -int(d.get("lines", 0)))
    if clones:
        out += ["### Largest duplicated blocks", "",
                "| Lines | Between |", "|---|---|"]
        for d in clones[:top]:
            a, b = d.get("firstFile", {}), d.get("secondFile", {})
            out.append(f"| {d.get('lines', 0)} | `{esc(str(a.get('name')))}:{a.get('start')}-{a.get('end')}` "
                       f"↔ `{esc(str(b.get('name')))}:{b.get('start')}-{b.get('end')}` |")
        if len(clones) > top:
            out.append(f"| | _…and {len(clones) - top} more_ |")
        out.append("")

    out.append("<sub>lizard (complexity) · jscpd (duplication)</sub>")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lizard-csv", default="reports/lizard.csv")
    ap.add_argument("--jscpd-json", default="reports/jscpd/jscpd-report.json")
    ap.add_argument("--ccn", type=int, default=15)
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--output", default="reports/quality-summary.md")
    args = ap.parse_args()

    report = build(read_lizard(Path(args.lizard_csv)),
                   read_jscpd(Path(args.jscpd_json)), args.ccn, args.top)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"quality: report written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
