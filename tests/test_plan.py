"""Tests for actions/plan-stages/plan.py."""

import subprocess
import sys
from pathlib import Path

PLAN = Path(__file__).resolve().parent.parent / "actions" / "plan-stages" / "plan.py"
DEFAULT = ",build,lint,sast,secret-scan,sca,container-scan,iac-scan,"


def run_plan(tmp_path, policy=None):
    config = tmp_path / ".security-baseline.yml"
    if policy is not None:
        config.write_text(policy)
    out = tmp_path / "output"
    summary = tmp_path / "summary.md"
    proc = subprocess.run(
        [sys.executable, str(PLAN), "--config", str(config)],
        capture_output=True, text=True,
        env={"GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary),
             "PATH": "/usr/bin:/bin"},
    )
    stages = None
    if out.exists():
        stages = out.read_text().strip().removeprefix("stages=")
    return proc, stages, summary


def test_no_config_runs_every_default_stage(tmp_path):
    proc, stages, _ = run_plan(tmp_path)
    assert proc.returncode == 0
    assert stages == DEFAULT


def test_config_without_stages_runs_defaults(tmp_path):
    proc, stages, _ = run_plan(tmp_path, "version: 1\n")
    assert proc.returncode == 0
    assert stages == DEFAULT


def test_codeql_is_opt_in(tmp_path):
    assert "codeql" not in run_plan(tmp_path, "version: 1\n")[1]


def test_selected_stages_only(tmp_path):
    proc, stages, _ = run_plan(
        tmp_path, "stages:\n  - lint\n  - secret-scan\n  - codeql\n")
    assert proc.returncode == 0
    # canonical order, not the order they were listed in
    assert stages == ",lint,secret-scan,codeql,"
    assert "skipped stages" in proc.stdout


def test_all_keyword_plus_codeql(tmp_path):
    _, stages, _ = run_plan(tmp_path, "stages: [all, codeql]\n")
    assert stages == DEFAULT + "codeql,"


def test_names_are_case_insensitive(tmp_path):
    _, stages, _ = run_plan(tmp_path, "stages: [Lint, SAST]\n")
    assert stages == ",lint,sast,"


def test_unknown_stage_fails_and_writes_nothing(tmp_path):
    proc, stages, _ = run_plan(tmp_path, "stages: [lint, secret-sacn]\n")
    assert proc.returncode == 1
    assert "secret-sacn" in proc.stdout
    assert stages is None


def test_stages_must_be_a_list(tmp_path):
    proc, _, _ = run_plan(tmp_path, "stages: lint\n")
    assert proc.returncode == 1


def test_empty_list_runs_nothing_but_is_allowed(tmp_path):
    proc, stages, _ = run_plan(tmp_path, "stages: []\n")
    assert proc.returncode == 0
    assert stages == ","
    assert "only the gate will run" in proc.stdout


def test_summary_lists_skipped_stages(tmp_path):
    _, _, summary = run_plan(tmp_path, "stages: [lint]\n")
    text = summary.read_text()
    assert "`lint` | ✅" in text
    assert "`sast` | ⏭️ skipped" in text
