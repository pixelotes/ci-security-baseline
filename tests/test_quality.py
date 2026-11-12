"""Tests for actions/scan-quality/quality.py."""

import json
import subprocess
import sys
from pathlib import Path

QUALITY = Path(__file__).resolve().parent.parent / "actions" / "scan-quality" / "quality.py"

# lizard --csv: NLOC,CCN,tokens,params,length,"name@start-end@file",file,function,long_name,start,end
LIZARD = "\n".join([
    '44,11,247,0,47,"main@23-69@./cmd/main.go","./cmd/main.go","main","main",23,69',
    '120,32,900,2,125,"Search@10-135@./pkg/search.go","./pkg/search.go","Search","Search q string",10,135',
    '30,18,200,1,31,"a|b@1-31@./pkg/x.go","./pkg/x.go","a|b","a|b",1,31',
    '6,2,17,1,6,"tiny@1-6@./pkg/t.go","./pkg/t.go","tiny","tiny",1,6',
    "not,a,row",
])
JSCPD = {
    "statistics": {"total": {"percentage": 4.25, "clones": 2, "duplicatedLines": 40, "lines": 940}},
    "duplicates": [
        {"lines": 12, "firstFile": {"name": "a.go", "start": 1, "end": 12},
         "secondFile": {"name": "b.go", "start": 5, "end": 16}},
        {"lines": 28, "firstFile": {"name": "c.go", "start": 10, "end": 37},
         "secondFile": {"name": "d.go", "start": 50, "end": 77}},
    ],
}


def run(tmp_path, lizard=LIZARD, jscpd=JSCPD, *extra):
    liz = tmp_path / "lizard.csv"
    js = tmp_path / "jscpd.json"
    out = tmp_path / "out" / "summary.md"
    if lizard is not None:
        liz.write_text(lizard)
    if jscpd is not None:
        js.write_text(json.dumps(jscpd))
    proc = subprocess.run(
        [sys.executable, str(QUALITY), "--lizard-csv", str(liz), "--jscpd-json", str(js),
         "--output", str(out), *extra],
        capture_output=True, text=True)
    return proc, out.read_text() if out.exists() else None


def test_report_has_metrics_and_hotspots(tmp_path):
    proc, md = run(tmp_path)
    assert proc.returncode == 0
    assert "**4.2%**" in md or "**4.3%**" in md
    assert "| Functions analysed | 4 |" in md
    assert "| Functions over CCN 15 | **2** |" in md
    # sorted by complexity, highest first, with file:line
    assert md.index("`Search`") < md.index("`a\\|b`")
    assert "`pkg/search.go:10`" in md
    # the simple function is not listed
    assert "`tiny`" not in md


def test_largest_duplicates_first(tmp_path):
    _, md = run(tmp_path)
    assert md.index("c.go:10-37") < md.index("a.go:1-12")


def test_threshold_and_top_are_configurable(tmp_path):
    _, md = run(tmp_path, LIZARD, JSCPD, "--ccn", "30", "--top", "1")
    assert "Functions over CCN 30 | **1**" in md
    assert "`a\\|b`" not in md


def test_pipe_in_names_does_not_break_the_table(tmp_path):
    _, md = run(tmp_path)
    assert "`a\\|b`" in md


def test_missing_tool_output_degrades_gracefully(tmp_path):
    proc, md = run(tmp_path, lizard=None, jscpd=None)
    assert proc.returncode == 0
    assert "Duplication | not available" in md
    assert "no supported source files found" in md


def test_report_is_marked_informational(tmp_path):
    _, md = run(tmp_path)
    assert "does not block" in md
