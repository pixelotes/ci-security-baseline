"""Structural checks on how the stage plan is wired into the reusable workflows."""

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "actions" / "plan-stages"))
from plan import STAGES  # noqa: E402

MODULES = sorted((ROOT / ".github" / "workflows").glob("ci-*.yml"))
# jobs that are not a stage by themselves
NOT_STAGES = {"plan", "gate", "detect", "container", "iac"}


def jobs_of(path):
    return yaml.safe_load(path.read_text())["jobs"]


def as_list(needs):
    return needs if isinstance(needs, list) else [needs]


def test_every_module_has_a_plan_job():
    for path in MODULES:
        plan = jobs_of(path)["plan"]
        uses = [s.get("uses", "") for s in plan["steps"]]
        assert any("/actions/plan-stages@" in u for u in uses), path.name


def test_every_stage_job_is_gated_by_a_known_stage():
    seen = set()
    for path in MODULES:
        for name, job in jobs_of(path).items():
            if name in NOT_STAGES:
                continue
            assert "plan" in as_list(job.get("needs", [])), f"{path.name}:{name}"
            m = re.search(r"',([a-z-]+),'\)", job.get("if", ""))
            assert m, f"{path.name}:{name} has no stage condition"
            assert m.group(1) in STAGES, f"{path.name}:{name} -> {m.group(1)}"
            seen.add(m.group(1))
    # every stage the plan accepts is implemented by at least one module
    assert seen == set(STAGES)


def test_gate_waits_for_the_plan_and_fails_when_it_failed():
    for path in MODULES:
        gate = jobs_of(path)["gate"]
        assert "plan" in as_list(gate["needs"]), path.name
        assert "always()" in gate["if"], path.name
        first = gate["steps"][0]
        assert first["if"] == "needs.plan.result != 'success'", path.name
        assert "exit 1" in first["run"], path.name


def test_gate_needs_every_stage_job_of_the_module():
    for path in MODULES:
        jobs = jobs_of(path)
        stage_jobs = {n for n in jobs if n not in NOT_STAGES}
        needs = set(as_list(jobs["gate"]["needs"]))
        assert stage_jobs <= needs, f"{path.name}: gate misses {stage_jobs - needs}"
