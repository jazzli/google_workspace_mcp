"""No registry writes: exercise only pure pipeline boundaries and synthetic tar."""

import importlib
import io
import json
from pathlib import Path
import sys
import tarfile
from types import SimpleNamespace

import pytest
from test_packaged_release_controls import example as example
from test_packaged_release_controls import registry_fixture, verified_statement

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".github/scripts"))
pipeline = importlib.import_module("packaged_pipeline")


def test_host_cannot_accidentally_invoke_github_publication(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(
        pipeline, "run", lambda *a, **kw: pytest.fail("unexpected command")
    )
    with pytest.raises(pipeline.r.ReleaseError):
        pipeline.github_guard("publish")


@pytest.mark.parametrize(
    "key,value",
    [
        ("GITHUB_EVENT_NAME", "push"),
        ("GITHUB_REF", "refs/heads/feature"),
        ("GITHUB_REPOSITORY", "someone/else"),
        ("GITHUB_RUN_ATTEMPT", "2"),
    ],
)
def test_wrong_run_envelope_cannot_reach_publication(monkeypatch, key, value):
    for k, v in {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": pipeline.r.REPOSITORY,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "SOURCE_SHA": "abcde12345" * 4,
        "GITHUB_SHA": "abcde12345" * 4,
        "GITHUB_WORKFLOW_SHA": "abcde12345" * 4,
    }.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv(key, value)
    with pytest.raises(pipeline.r.ReleaseError):
        pipeline.github_guard("publish")


def test_archive_config_bytes_are_bound_without_extracting_or_loading(tmp_path):
    configs = {
        role: json.dumps({"synthetic": role}).encode() for role in pipeline.r.ROLES
    }
    images = {
        role: {"configDigest": pipeline.r.hash_bytes(body)}
        for role, body in configs.items()
    }
    archive = tmp_path / "pair.tar"
    with tarfile.open(archive, "w") as tar:
        for role, body in configs.items():
            entry = tarfile.TarInfo(images[role]["configDigest"][7:] + ".json")
            entry.size = len(body)
            tar.addfile(entry, io.BytesIO(body))
    assert pipeline.archive_configs(archive, images) == configs
    images["runtime"]["configDigest"] = pipeline.r.hash_bytes(b"wrong")
    with pytest.raises(pipeline.r.ReleaseError):
        pipeline.archive_configs(archive, images)


def test_corrupt_archive_rejected_before_any_docker_load(tmp_path, monkeypatch):
    archive = tmp_path / "pair.tar"
    archive.write_bytes(b"corrupt-archive")
    monkeypatch.setattr(
        pipeline, "run", lambda *a, **kw: pytest.fail("must reject before Docker")
    )
    with pytest.raises(pipeline.r.ReleaseError):
        pipeline.check_archive(archive, pipeline.r.hash_bytes(b"expected"), {})


def test_command_errors_never_echo_raw_output(monkeypatch):
    def failed(*a, **kw):
        return type(
            "Result",
            (),
            {"returncode": 1, "stdout": b"PRIVATE-VALUE", "stderr": b"PRIVATE-VALUE"},
        )()

    monkeypatch.setattr(pipeline.subprocess, "run", failed)
    with pytest.raises(pipeline.r.ReleaseError) as error:
        pipeline.run(["gh", "attestation", "verify"], timeout=30)
    assert "PRIVATE-VALUE" not in str(error.value)


def test_publish_never_builds_or_executes_candidate_code():
    import ast

    tree = ast.parse((ROOT / ".github/scripts/packaged_pipeline.py").read_text())
    publish = next(
        (
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "publish"
        ),
        None,
    )
    assert publish is not None
    # Inspect parsed command values/call targets, independent of quote style.
    for node in ast.walk(publish):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value not in {"run", "exec", "build"}
            assert "pytest" not in node.value and "rehearse" not in node.value
        if isinstance(node, ast.Call):
            target = node.func
            if isinstance(target, ast.Name):
                assert target.id != "qualify"
            if isinstance(target, ast.Attribute):
                assert target.attr not in {"build", "qualify"}


TAG = (
    "ghcr.io/jazzli/google_workspace_mcp:packaged-r-run-123-1-sha-"
    "abcde12345abcde12345abcde12345abcde12345"
)


@pytest.mark.parametrize(
    "message", ["manifest unknown\n", "no such manifest: " + TAG + "\n"]
)
def test_tag_preflight_accepts_only_classified_missing_manifest(monkeypatch, message):
    def docker(argv, **kwargs):
        assert argv == pipeline.builder.DOCKER + ["manifest", "inspect", TAG]
        assert kwargs == {"capture_output": True, "text": True, "timeout": 30}
        return SimpleNamespace(returncode=1, stdout="", stderr=message)

    monkeypatch.setattr(pipeline.subprocess, "run", docker)
    pipeline.require_unused_tag(TAG)


@pytest.mark.parametrize(
    "status,output,error",
    [
        (0, "{}", ""),
        (0, "", "manifest unknown"),
        (1, "", "network timeout"),
        (1, "", "unauthorized"),
        (1, "", "denied"),
        (1, "", "not found"),
        (1, "", "404 Not Found"),
        (1, "", "manifest unknown\nunauthorized"),
        (1, "", "manifest unknown: network timeout"),
        (1, "", "no such manifest: another-tag"),
        (1, "{}", "manifest unknown"),
        (1, "{}", "no such manifest: " + TAG),
        (2, "", "manifest unknown"),
        (-9, "", "no such manifest: " + TAG),
    ],
)
def test_tag_preflight_rejects_present_network_auth_or_ambiguous_outcomes(
    monkeypatch, status, output, error
):
    monkeypatch.setattr(
        pipeline.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(
            returncode=status, stdout=output, stderr=error
        ),
    )
    with pytest.raises(
        pipeline.r.ReleaseError, match="tag-exists-or-availability-unknown"
    ):
        pipeline.require_unused_tag(TAG)


@pytest.mark.parametrize(
    "error",
    [
        OSError("PRIVATE-VALUE"),
        pipeline.subprocess.TimeoutExpired(["PRIVATE-VALUE"], 30),
        pipeline.subprocess.CalledProcessError(1, ["PRIVATE-VALUE"]),
    ],
)
def test_tag_preflight_unavailable_command_is_not_absence(monkeypatch, error):
    def unavailable(*a, **kw):
        raise error

    monkeypatch.setattr(pipeline.subprocess, "run", unavailable)
    with pytest.raises(pipeline.r.ReleaseError, match="^tag-availability-unknown$"):
        pipeline.require_unused_tag(TAG)


@pytest.mark.parametrize(
    "error,category",
    [
        (
            pipeline.r.ReleaseError("tag-exists-or-availability-unknown"),
            "tag-exists-or-availability-unknown",
        ),
        (pipeline.r.ReleaseError("external-command-failed"), "external-command-failed"),
        (pipeline.r.ReleaseError("new-PRIVATE-VALUE"), "release-validation-failed"),
        (
            pipeline.r.ReleaseError("tag-availability-unknown PRIVATE-VALUE"),
            "release-validation-failed",
        ),
        (
            pipeline.r.ReleaseError("tag-availability-unknown", "PRIVATE-VALUE"),
            "release-validation-failed",
        ),
        (pipeline.original.ReleaseError("PRIVATE-VALUE"), "source-validation-failed"),
        (OSError("PRIVATE-VALUE"), "io-failed"),
        (
            pipeline.subprocess.TimeoutExpired(["PRIVATE-VALUE"], 30),
            "external-command-unavailable",
        ),
        (ValueError("PRIVATE-VALUE"), "invalid-release-data"),
        (KeyError("PRIVATE-VALUE"), "invalid-release-data"),
        (TypeError("PRIVATE-VALUE"), "invalid-release-data"),
    ],
)
def test_cli_failure_reports_phase_and_allowlisted_category_without_values(
    monkeypatch, capsys, error, category
):
    def guard(phase):
        assert phase == "publish"
        raise error

    monkeypatch.setattr(pipeline, "github_guard", guard)
    assert pipeline.main(["publish"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "packaged-pipeline-failed:incomplete-not-accepted "
        f"phase=publish category={category}\n"
    )


@pytest.mark.parametrize("second_error", ["manifest unknown", "unauthorized"])
def test_publish_checks_both_tags_before_any_tag_or_push_and_retains_failure_state(
    tmp_path, monkeypatch, example, second_error
):
    report, _ = example
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    events = []
    images = {image["configDigest"]: image for image in report["images"].values()}

    def command(argv, **kwargs):
        args = argv[len(pipeline.builder.DOCKER) :]
        events.append(tuple(args[:2]))
        if args[:2] == ["image", "inspect"]:
            image = images[args[2]]
            return json.dumps(
                [
                    {
                        "Os": "linux",
                        "Architecture": "amd64",
                        "Config": {"User": "1000:1000"},
                        "Id": image["configDigest"],
                        "RootFS": {"Layers": image["diffIds"]},
                    }
                ]
            ).encode()
        if args[:2] in (["image", "load"], ["image", "tag"]):
            return b""
        if args[:2] == ["image", "push"]:
            raise pipeline.r.ReleaseError("external-command-failed")
        pytest.fail("unexpected command")

    def manifest(argv, **kwargs):
        args = argv[len(pipeline.builder.DOCKER) :]
        assert args[:2] == ["manifest", "inspect"]
        assert kwargs["timeout"] == 30
        events.append(tuple(args[:2]))
        is_runtime = ":packaged-r-" in args[2]
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="manifest unknown" if is_runtime else second_error,
        )

    monkeypatch.setattr(pipeline, "run", command)
    monkeypatch.setattr(pipeline.subprocess, "run", manifest)
    category = (
        "external-command-failed"
        if second_error == "manifest unknown"
        else "tag-exists-or-availability-unknown"
    )
    with pytest.raises(pipeline.r.ReleaseError, match="^" + category + "$"):
        pipeline.publish(tmp_path, report, {})
    expected = [
        ("image", "load"),
        ("image", "inspect"),
        ("image", "inspect"),
        ("manifest", "inspect"),
        ("manifest", "inspect"),
    ]
    if second_error == "manifest unknown":
        expected += [("image", "tag"), ("image", "push")]
    assert events == expected
    publication = tmp_path / "packaged-published"
    assert pipeline.r.load(publication / "publication-state.json") == {
        "status": "incomplete-not-accepted",
        "runId": "1234567",
        "runAttempt": "1",
        "knownDigests": {},
    }
    assert not (publication / "pair.json").exists()
    assert not (publication / "accepted-pair.json").exists()


@pytest.mark.parametrize("invalid_last_attestation", [False, True])
def test_verifier_pulls_only_after_both_attestations_then_logs_out_before_tests(
    tmp_path, monkeypatch, example, invalid_last_attestation
):
    report, _ = example
    registry = {role: registry_fixture(role, report) for role in pipeline.r.ROLES}
    pipeline.r.write(tmp_path / "build-receipt.json", report)
    pair = pipeline.r.create_pair_record(
        report,
        pipeline.r.hash_file(tmp_path / "build-receipt.json"),
        {role: pipeline.r.hash_bytes(raw) for role, (raw, _) in registry.items()},
    )
    publication = tmp_path / "packaged-published"
    publication.mkdir()
    pipeline.r.write(publication / "pair.json", pair)
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_WORKFLOW_SHA", report["workflow"]["commit"])
    targets = {}
    for role, image in pair["images"].items():
        monkeypatch.setenv(role.upper() + "_DIGEST", image["manifestDigest"])
        targets[pipeline.r.IMAGE_NAME + "@" + image["manifestDigest"]] = role
    events = []

    def command(argv, **kwargs):
        if argv[:3] == ["gh", "attestation", "verify"]:
            role = targets[argv[3].removeprefix("oci://")]
            standard = argv[argv.index("--predicate-type") + 1] == pipeline.r.STANDARD
            events.append(("verify", role, standard))
            result = verified_statement(pair, role, standard)
            if invalid_last_attestation and role == "migration" and not standard:
                result[0]["verificationResult"]["statement"]["subject"] = []
            return json.dumps(result).encode()
        args = argv[len(pipeline.builder.DOCKER) :]
        if args[:3] == ["buildx", "imagetools", "inspect"]:
            return registry[targets[args[3]]][0]
        if args[:3] == ["pull", "--platform", "linux/amd64"]:
            events.append(("pull", targets[args[3]]))
            return b""
        assert args == ["logout", "ghcr.io"]
        events.append(("logout",))
        return b""

    def image_inspect(target):
        image = report["images"][targets[target]]
        return {
            "Id": image["configDigest"],
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"User": "1000:1000"},
            "RootFS": {"Layers": image["diffIds"]},
        }

    def qualify(images, directory, base_source, context, *, full):
        assert images == report["images"] and context == "default" and full is False
        events.append(("qualify",))
        evidence = report["evidence"]
        return {
            **evidence,
            "tests": {
                k: v for k, v in evidence["tests"].items() if k.endswith("Image")
            },
            "scans": {k: v for k, v in evidence["scans"].items() if k != "source"},
        }

    monkeypatch.setattr(pipeline, "run", command)
    monkeypatch.setattr(pipeline, "inspect", image_inspect)
    monkeypatch.setattr(pipeline, "qualify", qualify)
    configs = {role: config for role, (_, config) in registry.items()}
    if invalid_last_attestation:
        with pytest.raises(pipeline.r.ReleaseError):
            pipeline.verify_published(tmp_path, report, configs)
        assert not (publication / "accepted-pair.json").exists()
    else:
        pipeline.verify_published(tmp_path, report, configs)
        accepted = pipeline.r.load(publication / "accepted-pair.json")
        assert accepted["status"] == "accepted" and accepted["liveReady"] is False
    assert events == [
        ("verify", "runtime", True),
        ("verify", "runtime", False),
        ("verify", "migration", True),
        ("verify", "migration", False),
    ] + (
        []
        if invalid_last_attestation
        else [("pull", "runtime"), ("pull", "migration"), ("logout",), ("qualify",)]
    )
    for flag in (
        "--bundle-from-oci",
        "--signer-workflow",
        "--source-ref",
        "--source-digest",
        "--signer-digest",
        "--deny-self-hosted-runners",
    ):
        assert flag in pipeline.verification_argv(
            pipeline.r.IMAGE_NAME + "@sha256:" + "a" * 64, standard=False, base=True
        )


def test_accepted_base_keeps_named_app_user_distinct_from_overlay():
    base = {
        "Id": pipeline.r.BASE["configDigest"],
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {"User": "app"},
    }
    pipeline.validate_base_image(base)
    for field, value in [("Id", "sha256:" + "b" * 64), ("Architecture", "arm64")]:
        bad = {**base, field: value}
        with pytest.raises(pipeline.r.ReleaseError):
            pipeline.validate_base_image(bad)


def test_parent_timeout_preserves_full_preflight_work_and_cleanup_budgets():
    assert pipeline.REHEARSAL_TIMEOUT >= 30 + 600 + 120 + 20


def test_source_scan_excludes_only_git_and_installed_test_environment(
    tmp_path, monkeypatch
):
    report = tmp_path / "scan.json"

    def fake_run(argv, **kwargs):
        assert argv.count("--skip-dirs") == 2
        assert (
            str(pipeline.r.ROOT / ".venv") in argv
            and str(pipeline.r.ROOT / ".git") in argv
        )
        report.write_text('{"SchemaVersion":2,"Results":[]}')

    monkeypatch.setattr(pipeline, "run", fake_run)
    pipeline.scan("fs", pipeline.r.ROOT, report)


def test_buildkit_version_is_read_from_the_running_engine_builder():
    assert (
        pipeline.buildkit_version(
            "Nodes:\nStatus: running\nBuildKit version: v0.31.1\n"
        )
        == "v0.31.1"
    )
    for output in (
        "github.com/docker/buildx v0.31.0",
        "Status: stopped\nBuildKit version: v0.31.1",
        "Status: running\nBuildKit version: v0.31.1\nBuildKit version: v0.30.0",
    ):
        with pytest.raises(pipeline.r.ReleaseError):
            pipeline.buildkit_version(output)
