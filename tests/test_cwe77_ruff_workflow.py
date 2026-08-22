"""Verify that the Ruff workflow remains read-only and fork-safe.

The vulnerability: the workflow uses pull_request trigger with
  repository: ${{ github.event.pull_request.head.repo.full_name }}
which checks out the fork's code directly. An attacker can poison
pyproject.toml or inject malicious ruff plugins to achieve code execution
with the workflow's contents:write GITHUB_TOKEN.

The enforced boundary: use the default pull-request merge ref, avoid
project-aware installers, grant no write permissions, and report Ruff
violations without rewriting or pushing repository content.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, Tuple

import yaml

# Resolve the repo root (one level up from tests/)
REPO_ROOT: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW_PATH: str = os.path.join(REPO_ROOT, ".github", "workflows", "ruff.yml")

# Commands that resolve and execute the project's own build backend /
# pyproject.toml hooks. These must NOT run on untrusted fork PR code.
PROJECT_INSTALL_COMMANDS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:^|[\s;&|])uv\s+sync(?:$|[\s;&|])"),
    re.compile(
        r"(?:^|[\s;&|])uv\s+pip\s+install\b[^\n;&|]*?"
        r"(?:\s\.|(?:-e\s+\.|--editable(?:=|\s+)\.))(?=$|[\s;&|])"
    ),
    re.compile(
        r"(?:^|[\s;&|])(?:python\s+-m\s+)?pip3?\s+install\b[^\n;&|]*?"
        r"(?:\s\.|(?:-e\s+\.|--editable(?:=|\s+)\.))(?=$|[\s;&|])"
    ),
    re.compile(r"(?:^|[\s;&|])poetry\s+install(?:$|[\s;&|])"),
)

# Commands that change the checked-out repository or push changes upstream.
# Ruff validation may inspect files, but it must never rewrite or publish them.
REPOSITORY_MUTATION_COMMANDS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"\bruff\s+check\b[^\n]*\s--fix(?:\s|$)"),
    re.compile(r"\bruff\s+format\b(?![^\n]*--check)"),
    re.compile(r"\bgit\s+(?:add|commit|push)\b"),
)


def load_workflow(path: str) -> Tuple[Dict[str, Any], str]:
    """Load a workflow file and return (parsed_yaml, raw_text)."""
    with open(path, "r") as f:
        raw: str = f.read()
    parsed: Dict[str, Any] = yaml.safe_load(raw)
    return parsed, raw


def _job_has_write_permission(job: Dict[str, Any]) -> bool:
    """Return True if a job grants any write-scoped permission."""
    perms: Any = job.get("permissions", {})
    if isinstance(perms, str):
        return perms == "write-all"
    if isinstance(perms, dict):
        return any(v == "write" for v in perms.values())
    return False


def _workflow_has_write_permission(wf: Dict[str, Any]) -> bool:
    """Return True if the top-level workflow grants any write-scoped permission."""
    perms: Any = wf.get("permissions", {})
    if isinstance(perms, str):
        return perms == "write-all"
    if isinstance(perms, dict):
        return any(v == "write" for v in perms.values())
    return False


def _runs_project_install(run_cmd: str) -> bool:
    """Return True when a shell command installs the local project."""
    return any(pattern.search(run_cmd) for pattern in PROJECT_INSTALL_COMMANDS)


def test_project_install_matcher_detects_common_variants() -> None:
    """Project install detection must catch common pip and uv variants."""
    assert _runs_project_install("python -m pip install .")
    assert _runs_project_install("pip3 install .")
    assert _runs_project_install("uv pip install --editable .")
    assert _runs_project_install("uv pip install --editable=.")
    assert _runs_project_install("pip install -e .")
    assert _runs_project_install("uv sync")
    assert _runs_project_install("poetry install")

    assert not _runs_project_install("python -m pip install -r requirements.txt")
    assert not _runs_project_install("pip3 install ruff")


def test_no_fork_repo_checkout() -> None:
    """Checkout step must NOT reference github.event.pull_request.head.repo.full_name
    as the repository parameter, which would check out attacker-controlled fork code."""
    wf, _raw = load_workflow(WORKFLOW_PATH)

    jobs: Dict[str, Any] = wf.get("jobs", {})
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses: str = step.get("uses", "")
            if "actions/checkout" in uses:
                with_params: Dict[str, Any] = step.get("with", {})
                repo_param: str = str(with_params.get("repository", ""))

                # Must NOT reference the fork's repo
                assert "pull_request.head.repo" not in repo_param, (
                    f"Job '{job_name}' checkout uses fork repository: {repo_param}. "
                    "This allows attacker-controlled code execution."
                )


def test_workflow_has_no_project_install_commands() -> None:
    """Ruff CI must not execute project-controlled build or install hooks."""
    wf, _raw = load_workflow(WORKFLOW_PATH)

    jobs: Dict[str, Any] = wf.get("jobs", {})
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run_cmd: str = str(step.get("run", ""))
            assert not _runs_project_install(run_cmd), (
                f"Job '{job_name}' runs a project-aware install "
                f"({run_cmd.strip().splitlines()[0]!r}) "
                "and could execute attacker-controlled pyproject.toml/build hooks."
            )


def test_workflow_permissions_are_read_only() -> None:
    """The Ruff workflow must never receive a write-scoped token."""
    wf, _raw = load_workflow(WORKFLOW_PATH)

    workflow_permissions: Any = wf.get("permissions")
    assert isinstance(workflow_permissions, dict), (
        "Ruff workflow must declare permissions explicitly"
    )
    assert workflow_permissions.get("contents") == "read", (
        "Ruff workflow must explicitly limit repository contents to read access"
    )

    workflow_has_write: bool = _workflow_has_write_permission(wf)
    assert not workflow_has_write, "Ruff workflow grants top-level write permission"

    jobs: Dict[str, Any] = wf.get("jobs", {})

    for job_name, job in jobs.items():
        job_has_write: bool = _job_has_write_permission(job)
        assert not job_has_write, (
            f"Ruff job '{job_name}' grants write permission; lint validation "
            "must be read-only"
        )


def test_workflow_has_no_repository_mutation_commands() -> None:
    """Ruff CI must report violations without rewriting or pushing code."""
    wf, _raw = load_workflow(WORKFLOW_PATH)

    jobs: Dict[str, Any] = wf.get("jobs", {})
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            run_cmd: str = str(step.get("run", ""))
            for pattern in REPOSITORY_MUTATION_COMMANDS:
                assert not pattern.search(run_cmd), (
                    f"Ruff job '{job_name}' contains repository mutation command: "
                    f"{run_cmd.strip().splitlines()[0]!r}"
                )


def test_push_trigger_runs_ruff_validation() -> None:
    """If the workflow listens for pushes to main, the validation job must run."""
    wf, _raw = load_workflow(WORKFLOW_PATH)

    workflow_on: Any = wf.get("on", wf.get(True, {}))
    push_event: Any = (
        workflow_on.get("push", {}) if isinstance(workflow_on, dict) else {}
    )
    push_branches: Any = (
        push_event.get("branches", []) if isinstance(push_event, dict) else []
    )
    assert not push_branches or "main" in push_branches

    ruff_job: Dict[str, Any] = wf.get("jobs", {}).get("ruff", {})
    assert ruff_job, "Ruff workflow is missing its validation job"
    ruff_if: str = " ".join(str(ruff_job.get("if", "")).split())
    assert not ruff_if or "github.event_name == 'push'" in ruff_if


if __name__ == "__main__":
    tests = [
        test_project_install_matcher_detects_common_variants,
        test_no_fork_repo_checkout,
        test_workflow_has_no_project_install_commands,
        test_workflow_permissions_are_read_only,
        test_workflow_has_no_repository_mutation_commands,
        test_push_trigger_runs_ruff_validation,
    ]

    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS: {test.__name__}")
        except AssertionError as e:
            print(f"  FAIL: {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {test.__name__}: {e}")
            failed += 1

    if failed:
        print(f"\n{failed} test(s) failed")
        sys.exit(1)
    else:
        print("\nAll tests passed")
        sys.exit(0)
