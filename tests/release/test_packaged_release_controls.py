"""Adversarial contracts for the separate paired publisher; no provider calls."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "packaged_release", ROOT / ".github/scripts/packaged_release.py"
)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def digest(label):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def case_report(cases):
    return {
        "sha256": digest("report"),
        "cases": cases,
        "passed": len(cases),
        "skipped": 0,
        "failed": 0,
    }


@pytest.fixture
def example():
    files = {name: digest(name) for name in release.SOURCE_FILES}
    files.update(release.FIXED_FILES)
    expected = {
        "repository": release.REPOSITORY,
        "runId": "1234567",
        "runAttempt": "1",
        "workflow": {"path": release.WORKFLOW, "commit": "abcde12345" * 4},
        "overlay": {"commit": "abcde12345" * 4, "tree": "bcdef12345" * 4},
        "sourceFiles": files,
        "baseDiffIds": [digest("base-layer")],
    }
    report = {
        "schemaVersion": 1,
        **{k: v for k, v in expected.items() if k != "baseDiffIds"},
        "base": copy.deepcopy(release.BASE),
        "images": {
            "runtime": {
                "configDigest": digest("runtime"),
                "diffIds": [digest("base-layer"), digest("r-layer")],
            },
            "migration": {
                "configDigest": digest("migration"),
                "diffIds": [digest("base-layer"), digest("r-layer"), digest("m-layer")],
            },
        },
        "archiveSha256": digest("archive"),
        "tools": {
            "docker": "28.0.0",
            "buildkit": "v0.20.0",
            "python": "3.11.15",
            "node": "v22.23.2",
            "scanner": "0.74.0",
        },
        "evidence": {
            "tests": {
                key: case_report(value) for key, value in release.REQUIRED_CASES.items()
            },
            "scans": {
                role: digest(role + "-scan")
                for role in ("source", "runtime", "migration")
            },
            "layers": digest("layers"),
            "rehearsal": {
                "sha256": digest("rehearsal"),
                "stages": list(release.STAGES),
                "faults": list(release.FAULTS),
                "cleanup": {
                    kind: {"owned": n, "absent": n, "present": 0, "unknown": 0}
                    for kind, n in [("containers", 45), ("volumes", 5)]
                },
            },
        },
    }
    report["evidence"]["tests"]["nonIntegration"] = case_report(["test_one"])
    return copy.deepcopy(report), copy.deepcopy(expected)


def test_matching_build_receipt_passes(example):
    report, expected = example
    assert release.validate_build_receipt(report, digest("archive"), expected) == report


@pytest.mark.parametrize(
    "event,ref,s,w,g",
    [
        ("push", "refs/heads/main", "a" * 40, "a" * 40, "a" * 40),
        ("workflow_dispatch", "refs/heads/topic", "a" * 40, "a" * 40, "a" * 40),
        ("workflow_dispatch", "refs/heads/main", "a" * 40, "b" * 40, "b" * 40),
        ("workflow_dispatch", "refs/heads/main", "main", "a" * 40, "a" * 40),
    ],
)
def test_invalid_invocation_fails(event, ref, s, w, g):
    with pytest.raises(release.ReleaseError):
        release.validate_invocation(event, ref, s, w, g)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d["base"].update(configDigest=digest("other")),
        lambda d: d.update(repository="foreign/repository"),
        lambda d: d.update(runAttempt="2"),
        lambda d: d["workflow"].update(commit="f" * 40),
        lambda d: d["overlay"].update(tree="d" * 40),
        lambda d: d["images"].update(extra=d["images"]["runtime"]),
        lambda d: d["images"].pop("migration"),
        lambda d: d["images"]["runtime"].update(configDigest="sha256:" + "1" * 64),
        lambda d: d["images"]["runtime"].update(configDigest="bad"),
        lambda d: d["images"]["migration"]["diffIds"].reverse(),
        lambda d: d["images"]["migration"]["diffIds"].append(digest("extra")),
        lambda d: d["images"]["migration"].update(
            configDigest=d["images"]["runtime"]["configDigest"]
        ),
        lambda d: d["sourceFiles"].update(
            {"docker/runtime_launcher.py": digest("changed")}
        ),
        lambda d: d.update(unknown=True),
        lambda d: d["tools"].update(node="v18.0.0"),
        lambda d: d["evidence"]["tests"]["linuxRuntime"].update(skipped=1),
        lambda d: d["evidence"]["tests"]["linuxMigration"]["cases"].pop(),
        lambda d: d["evidence"]["tests"]["runtimeImage"]["cases"].append("extra"),
        lambda d: d["evidence"]["rehearsal"]["stages"].pop(),
        lambda d: d["evidence"]["rehearsal"]["stages"].append("migration"),
        lambda d: d["evidence"]["rehearsal"]["faults"].pop(),
        lambda d: d["evidence"]["rehearsal"]["cleanup"]["containers"].update(unknown=1),
        lambda d: d["evidence"]["rehearsal"]["cleanup"]["volumes"].update(absent=0),
        lambda d: d["evidence"]["rehearsal"]["cleanup"].update(verifiedAbsent=True),
    ],
)
def test_mutated_build_receipt_is_rejected(example, mutation):
    report, expected = copy.deepcopy(example)
    mutation(report)
    with pytest.raises(release.ReleaseError):
        release.validate_build_receipt(report, digest("archive"), expected)


def test_archive_swap_is_rejected(example):
    with pytest.raises(release.ReleaseError):
        release.validate_build_receipt(example[0], digest("other-archive"), example[1])


@pytest.mark.parametrize(
    "raw",
    ['{"a":1,"a":2}', '{"x":NaN}', "[" * 1000 + "]" * 1000, "x" * 1048577],
    ids=["duplicate-key", "nonfinite", "excess-depth", "oversized"],
)
def test_ambiguous_or_unbounded_json_is_rejected(raw):
    with pytest.raises(release.ReleaseError):
        release.loads(raw)


def registry_fixture(role, report):
    image = report["images"][role]
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": image["diffIds"]},
            "config": {
                "User": "1000:1000",
                "Entrypoint": [
                    "/usr/local/bin/python3.11",
                    "-I",
                    "-S",
                    "/opt/mcp-runtime/runtime_launcher.py",
                ],
                "Cmd": ["run"],
            },
        }
    ).encode()
    image["configDigest"] = release.hash_bytes(config)
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": image["configDigest"], "size": len(config)},
            "layers": [
                {"digest": digest("compressed" + str(i)), "size": 100}
                for i in range(len(image["diffIds"]))
            ],
        }
    ).encode()
    return manifest, config


def test_raw_registry_bytes_and_config_are_independently_bound(example):
    report, _ = example
    raw, config = registry_fixture("runtime", report)
    actual = release.hash_bytes(raw)
    assert (
        release.validate_manifest(raw, config, actual, report["images"]["runtime"])
        == actual
    )
    for bad_raw, bad_config, bad_digest in [
        (raw + b" ", config, actual),
        (raw, config + b" ", actual),
        (raw, config, digest("different")),
    ]:
        with pytest.raises(release.ReleaseError):
            release.validate_manifest(
                bad_raw, bad_config, bad_digest, report["images"]["runtime"]
            )


def pair_fixture(report):
    return release.create_pair_record(
        report,
        release.hash_bytes(release.canonical(report)),
        {role: digest(role + "manifest") for role in release.ROLES},
    )


def verified_statement(pair, role, standard=False):
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": release.IMAGE_NAME,
                "digest": {"sha256": pair["images"][role]["manifestDigest"][7:]},
            }
        ],
        "predicateType": release.STANDARD if standard else release.PREDICATE,
        "predicate": {"role": role, "pair": copy.deepcopy(pair)},
    }
    if standard:
        statement["predicate"] = {
            "runDetails": {
                "metadata": {
                    "invocationId": f"https://github.com/{release.REPOSITORY}/actions/runs/{pair['runId']}/attempts/{pair['runAttempt']}"
                }
            }
        }
    return [{"verificationResult": {"statement": statement}}]


def test_attestation_requires_both_exact_subject_and_complete_pair(example):
    pair = pair_fixture(example[0])
    for role in release.ROLES:
        for standard in (True, False):
            assert release.validate_attestation(
                verified_statement(pair, role, standard), pair, role, standard=standard
            )
    for field in ["runAttempt", "workflowCommit"]:
        evidence = verified_statement(pair, "runtime")
        evidence[0]["verificationResult"]["statement"]["predicate"]["pair"][field] = (
            "wrong"
        )
        with pytest.raises(release.ReleaseError):
            release.validate_attestation(evidence, pair, "runtime")
    for role in release.ROLES:
        with pytest.raises(release.ReleaseError):
            release.validate_attestation(
                verified_statement(pair, role),
                pair,
                "migration" if role == "runtime" else "runtime",
            )


def test_pair_record_cannot_swap_mate_or_receipt(example):
    report, _ = example
    pair = pair_fixture(report)
    release.validate_pair_record(
        pair, report, release.hash_bytes(release.canonical(report))
    )
    pair["images"]["migration"]["configDigest"] = digest("substitute")
    with pytest.raises(release.ReleaseError):
        release.validate_pair_record(
            pair, report, release.hash_bytes(release.canonical(report))
        )


def test_all_six_parametrized_image_cases_are_required():
    assert len(release.REQUIRED_CASES["runtimeImage"]) == 6


def test_junit_parser_rejects_skips_missing_or_duplicate_cases(tmp_path):
    cases = release.REQUIRED_CASES["runtimeImage"]
    good = (
        "<testsuites><testsuite>"
        + "".join(f'<testcase name="{name}"/>' for name in cases)
        + "</testsuite></testsuites>"
    )
    path = tmp_path / "cases.xml"
    path.write_text(good)
    assert release.test_summary(path, "runtimeImage")["passed"] == 6
    for raw in [
        good.replace("/>", "><skipped/></testcase>", 1),
        good.replace(f'<testcase name="{cases[0]}"/>', ""),
        good.replace(cases[-1], cases[0]),
    ]:
        path.write_text(raw)
        with pytest.raises(release.ReleaseError):
            release.test_summary(path, "runtimeImage")


def test_host_parameter_ids_are_bounded_hashes_without_collapsing_cases(tmp_path):
    names = ["test_fixture[" + "x" * 2000 + suffix + "]" for suffix in ("a", "b")]
    path = tmp_path / "host.xml"
    path.write_text(
        "<testsuite>"
        + "".join(f'<testcase classname="fixture" name="{name}"/>' for name in names)
        + "</testsuite>"
    )
    result = release.test_summary(path, "nonIntegration")
    expected = sorted(
        "node-" + release.hash_bytes(("fixture::" + name).encode()) for name in names
    )
    assert result["cases"] == expected and result["passed"] == 2
    assert max(map(len, result["cases"])) <= release.CASE["maxLength"]


def test_companion_schema_matches_all_validator_constraints():
    document = json.loads(
        (ROOT / ".github/scripts/packaged-release.schema.json").read_text()
    )
    assert document.pop("$schema") == "https://json-schema.org/draft/2020-12/schema"
    assert document == release.build_schema()


def test_linux_parser_requires_each_case_and_cleanup(tmp_path):
    cases = release.REQUIRED_CASES["linuxRuntime"]
    text = "\n".join(f"{case} (__main__.RuntimeTests.{case}) ... ok" for case in cases)
    text += f"\nRan {len(cases)} tests in 0.3s\n\nOK\n"
    text += json.dumps(
        {
            "unitContainer": "packaged-unit-11111111-2222-4333-8444-555555555555",
            "cleanup": "verified-absent",
        }
    )
    path = tmp_path / "unit.txt"
    path.write_text(text)
    assert release.test_summary(path, "linuxRuntime")["passed"] == len(cases)
    for raw in [
        text.replace("verified-absent", "unknown"),
        text.replace(" ... ok", " ... skipped 'fixture'", 1),
    ]:
        path.write_text(raw)
        with pytest.raises(release.ReleaseError):
            release.test_summary(path, "linuxRuntime")


def test_acceptance_requires_all_four_verifications_and_post_pull_reports(example):
    report, expected = example
    pair = pair_fixture(report)
    post = copy.deepcopy(report["evidence"])
    post["tests"] = {
        key: post["tests"][key] for key in ("runtimeImage", "migrationImage")
    }
    post["scans"].pop("source")
    verifications = {
        role: {
            kind: verified_statement(pair, role, kind == "standard")
            for kind in ("standard", "custom")
        }
        for role in release.ROLES
    }
    accepted = release.accept_pair(
        report, pair, release.hash_bytes(release.canonical(report)), post, verifications
    )
    assert accepted["status"] == "accepted" and accepted["liveReady"] is False
    verifications["migration"].pop("standard")
    with pytest.raises(release.ReleaseError):
        release.accept_pair(
            report,
            pair,
            release.hash_bytes(release.canonical(report)),
            post,
            verifications,
        )
