"""Mutation tests for the complete generated manual workflow contract."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "packaged_release", ROOT / ".github/scripts/packaged_release.py"
)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def document():
    return json.loads((ROOT / r.WORKFLOW).read_text())


def test_workflow_exists_and_matches_reviewed_contract():
    assert r.validate_workflow(document()) == {"workflow": "valid"}


def test_manual_jobs_have_exact_authority_and_order():
    d = document()
    assert set(d["on"]) == {"workflow_dispatch"}
    assert set(d["on"]["workflow_dispatch"]["inputs"]) == {"source_sha"}
    assert d["permissions"] == {}
    assert d["concurrency"] == {
        "group": "manual-container-publication",
        "cancel-in-progress": False,
    }
    assert list(d["jobs"]) == ["validate", "build-test", "publish", "verify-published"]
    for name, minutes in [
        ("validate", 5),
        ("build-test", 30),
        ("publish", 15),
        ("verify-published", 30),
    ]:
        job = d["jobs"][name]
        assert job["runs-on"] == "ubuntu-24.04" and job["timeout-minutes"] == minutes
        if name != "publish":
            assert "write" not in job["permissions"].values()
    assert d["jobs"]["publish"]["permissions"] == {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d["on"].update(push={}),
        lambda d: d["on"].update(pull_request={}),
        lambda d: d["on"].update(schedule=[]),
        lambda d: d["on"]["workflow_dispatch"]["inputs"].update(
            base={"type": "string"}
        ),
        lambda d: d["concurrency"].update({"cancel-in-progress": True}),
        lambda d: d["jobs"]["build-test"]["permissions"].update(packages="write"),
        lambda d: d["jobs"]["verify-published"]["permissions"].update(
            **{"id-token": "write"}
        ),
        lambda d: d["jobs"]["publish"].pop("needs"),
        lambda d: d["jobs"]["publish"].pop("timeout-minutes"),
        lambda d: d["jobs"]["publish"].update({"runs-on": "self-hosted"}),
        lambda d: d["jobs"]["publish"]["steps"][0].update(uses="actions/checkout@main"),
        lambda d: d["jobs"]["publish"]["steps"].append({"run": "docker run arbitrary"}),
        lambda d: d["jobs"]["verify-published"]["steps"].append(
            {"run": "docker build ."}
        ),
        lambda d: d["jobs"]["publish"]["steps"].reverse(),
        lambda d: d["jobs"]["publish"]["steps"].pop(),
        lambda d: d["jobs"]["verify-published"].update({"if": "always()"}),
    ],
)
def test_mutations_are_rejected(mutation):
    d = document()
    mutation(d)
    with pytest.raises(r.ReleaseError):
        r.validate_workflow(d)


def test_preserved_publisher_and_helper_are_byte_identical():
    import hashlib

    for name, expected in [
        (
            ".github/workflows/docker-publish.yml",
            "9c36838635781bce73528b5c716e22d9efd87423",
        ),
        (
            ".github/scripts/container_release.py",
            "3b3ad9c2be03cae0bb0546b8118c9f9c290c5a3d",
        ),
    ]:
        body = (ROOT / name).read_bytes()
        assert (
            hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()
            == expected
        )
