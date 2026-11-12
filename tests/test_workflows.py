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


def declared_inputs(path):
    doc = yaml.safe_load(path.read_text())
    return (doc.get(True) or doc.get("on") or {})["workflow_call"].get("inputs", {})


def test_run_container_and_run_iac_are_real_in_every_language_module():
    """An input that no job reads is a silent no-op: it must have its job, wired
    to the gate, and it must call the module by full reference (a relative
    ./ path is resolved against the caller's repository)."""
    modules = [p for p in MODULES if p.stem not in ("ci-container", "ci-iac", "ci-scripts")]
    assert modules
    for path in modules:
        inputs = declared_inputs(path)
        jobs = jobs_of(path)
        for flag, job, target in (("run-container", "container", "ci-container.yml"),
                                  ("run-iac", "iac", "ci-iac.yml")):
            assert flag in inputs, f"{path.name} lacks input {flag}"
            assert jobs[job]["if"] == f"inputs.{flag}", path.name
            uses = jobs[job]["uses"]
            assert uses.endswith(f"/.github/workflows/{target}@v1"), (path.name, uses)
            assert not uses.startswith("./"), (path.name, uses)
            assert job in as_list(jobs["gate"]["needs"]), f"{path.name}: gate does not wait for {job}"
