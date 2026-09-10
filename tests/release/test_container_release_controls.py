import copy
import io
import json
import subprocess
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / ".github" / "scripts" / "container_release.py"
WORKFLOW = ROOT / ".github" / "workflows" / "docker-publish.yml"


def run_helper(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(ROOT / ".venv" / "bin" / "python"), str(HELPER), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if check:
        assert result.returncode == 0, result.stdout + result.stderr
    return result


def git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Release Test",
            "-c",
            "user.email=test@example.invalid",
            *args,
        ],
        cwd=repository,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.fixture
def reviewed_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "source"
    repository.mkdir()
    git(repository, "init", "-b", "main")
    git(
        repository,
        "remote",
        "add",
        "origin",
        "https://github.com/example/public-app.git",
    )
    (repository / ".dockerignore").write_text(".git\n.env*\ntests/\n", encoding="utf-8")
    (repository / "Dockerfile").write_text(
        "FROM scratch\nCOPY . /app\n", encoding="utf-8"
    )
    (repository / "main.py").write_text("print('reviewed')\n", encoding="utf-8")
    git(repository, "add", ".")
    git(repository, "commit", "-m", "reviewed")
    reviewed_sha = git(repository, "rev-parse", "HEAD")
    reviewed_tree = git(repository, "rev-parse", "HEAD^{tree}")
    git(repository, "branch", "reviewed-main")
    return repository, reviewed_sha, reviewed_tree


def test_source_validation_accepts_full_commit_in_reviewed_history(reviewed_repository):
    repository, reviewed_sha, _ = reviewed_repository

    result = run_helper(
        "validate-source",
        "--repository",
        str(repository),
        "--source-sha",
        reviewed_sha,
        "--reviewed-ref",
        "reviewed-main",
        "--expected-repository",
        "example/public-app",
    )

    assert json.loads(result.stdout)["source_sha"] == reviewed_sha


@pytest.mark.parametrize("source_sha", ["main", "a" * 39, "A" * 40, "g" * 40])
def test_source_validation_rejects_noncanonical_sha(reviewed_repository, source_sha):
    repository, _, _ = reviewed_repository

    result = run_helper(
        "validate-source",
        "--repository",
        str(repository),
        "--source-sha",
        source_sha,
        "--reviewed-ref",
        "reviewed-main",
        "--expected-repository",
        "example/public-app",
        check=False,
    )

    assert result.returncode != 0
    assert "full lowercase 40-hex" in result.stderr
    assert source_sha not in result.stderr


def test_source_validation_rejects_commit_outside_reviewed_history(reviewed_repository):
    repository, reviewed_sha, _ = reviewed_repository
    git(repository, "checkout", "--orphan", "unreviewed")
    (repository / "main.py").write_text("print('unreviewed')\n", encoding="utf-8")
    git(repository, "add", ".")
    git(repository, "commit", "-m", "unreviewed")
    unreviewed_sha = git(repository, "rev-parse", "HEAD")

    result = run_helper(
        "validate-source",
        "--repository",
        str(repository),
        "--source-sha",
        unreviewed_sha,
        "--reviewed-ref",
        reviewed_sha,
        "--expected-repository",
        "example/public-app",
        check=False,
    )

    assert result.returncode != 0
    assert "reviewed history" in result.stderr
    assert unreviewed_sha not in result.stderr


def test_source_validation_rejects_another_repository(reviewed_repository):
    repository, reviewed_sha, _ = reviewed_repository

    result = run_helper(
        "validate-source",
        "--repository",
        str(repository),
        "--source-sha",
        reviewed_sha,
        "--reviewed-ref",
        "reviewed-main",
        "--expected-repository",
        "another-owner/public-app",
        check=False,
    )

    assert result.returncode != 0
    assert "repository identity" in result.stderr


def test_context_validation_accepts_clean_exact_checkout(reviewed_repository):
    repository, reviewed_sha, reviewed_tree = reviewed_repository

    result = run_helper(
        "validate-context",
        "--repository",
        str(repository),
        "--source-sha",
        reviewed_sha,
    )

    assert json.loads(result.stdout) == {
        "source_sha": reviewed_sha,
        "source_tree": reviewed_tree,
        "tracked_files": 3,
    }


def test_context_validation_rejects_untracked_material(reviewed_repository):
    repository, reviewed_sha, _ = reviewed_repository
    (repository / "local-private-note").write_text("not public\n", encoding="utf-8")

    result = run_helper(
        "validate-context",
        "--repository",
        str(repository),
        "--source-sha",
        reviewed_sha,
        check=False,
    )

    assert result.returncode != 0
    assert "not clean" in result.stderr
    assert "local-private-note" not in result.stderr


def write_inventory(
    path: Path,
    names: list[str],
    *,
    directories: tuple[str, ...] = (),
    nonempty: tuple[str, ...] = (),
    symlinks: tuple[str, ...] = (),
) -> None:
    with tarfile.open(path, "w") as archive:
        for name in names:
            item = tarfile.TarInfo(name)
            if name in directories:
                item.type = tarfile.DIRTYPE
            elif name in symlinks:
                item.type = tarfile.SYMTYPE
                item.linkname = "elsewhere"
            data = b"x" if name in nonempty else b""
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))


def test_image_inventory_accepts_runtime_without_private_paths(tmp_path: Path):
    inventory = tmp_path / "rootfs.tar"
    write_inventory(
        inventory,
        ["app/main.py", "app/.venv/pyvenv.cfg", "app/core/__init__.py", "etc/passwd"],
    )

    result = run_helper("validate-image-inventory", "--archive", str(inventory))

    assert json.loads(result.stdout) == {"inventory_entries": 4}


def test_image_inventory_allows_only_empty_uv_cache_git_marker(tmp_path: Path):
    inventory = tmp_path / "rootfs.tar"
    marker = "root/.cache/uv/sdists-v9/.git"
    write_inventory(inventory, ["app/main.py", "app/.venv/pyvenv.cfg", marker])

    run_helper("validate-image-inventory", "--archive", str(inventory))

    for suffix, options, names in (
        ("directory", {"directories": (marker,)}, [marker]),
        ("nonempty", {"nonempty": (marker,)}, [marker]),
        ("symlink", {"symlinks": (marker,)}, [marker]),
        ("descendant", {}, [marker, f"{marker}/config"]),
    ):
        unsafe = tmp_path / f"rootfs-{suffix}.tar"
        write_inventory(
            unsafe,
            ["app/main.py", "app/.venv/pyvenv.cfg", *names],
            **options,
        )
        result = run_helper(
            "validate-image-inventory", "--archive", str(unsafe), check=False
        )
        assert result.returncode != 0
        assert "forbidden path" in result.stderr


@pytest.mark.parametrize(
    "private_path",
    [
        "app/.env.oauth21",
        "app/.git/config",
        "app/client_secret.json",
        "app/.credentials/token.json",
        "app/tests/test_runtime.py",
        "root/.ssh/id_rsa",
        "root/.docker/config.json",
        "home/app/.kube/config",
        "home/app/.netrc",
        "home/app/.pypirc",
    ],
)
def test_image_inventory_rejects_private_or_nonruntime_paths(
    tmp_path: Path, private_path: str
):
    inventory = tmp_path / "rootfs.tar"
    write_inventory(inventory, ["app/main.py", "app/.venv/pyvenv.cfg", private_path])

    result = run_helper(
        "validate-image-inventory", "--archive", str(inventory), check=False
    )

    assert result.returncode != 0
    assert private_path not in result.stderr
    assert "forbidden path" in result.stderr


def write_source_rootfs(
    path: Path,
    source: Path,
    *,
    changed_main: bytes | None = None,
    extra_app_path: str | None = None,
) -> None:
    with tarfile.open(path, "w") as archive:
        for relative in (".dockerignore", "Dockerfile", "main.py"):
            content = (source / relative).read_bytes()
            if relative == "main.py" and changed_main is not None:
                content = changed_main
            item = tarfile.TarInfo(f"app/{relative}")
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
        for generated in (
            "app/.venv/pyvenv.cfg",
            "app/workspace_mcp.egg-info/PKG-INFO",
        ):
            item = tarfile.TarInfo(generated)
            archive.addfile(item, io.BytesIO())
        store = tarfile.TarInfo("app/store_creds")
        store.type = tarfile.DIRTYPE
        archive.addfile(store)
        if extra_app_path:
            item = tarfile.TarInfo(extra_app_path)
            archive.addfile(item, io.BytesIO())


def test_image_source_comparison_accepts_clean_tracked_content(
    reviewed_repository, tmp_path
):
    source, _, _ = reviewed_repository
    inventory = tmp_path / "rootfs.tar"
    write_source_rootfs(inventory, source)

    result = run_helper(
        "validate-image-source",
        "--archive",
        str(inventory),
        "--source-repository",
        str(source),
    )

    assert json.loads(result.stdout)["matched_source_files"] == 3


@pytest.mark.parametrize(
    ("changed_main", "extra_app_path", "expected_error"),
    [
        (b"print('tampered')\n", None, "content differs"),
        (None, "app/private-note", "not clean tracked source"),
    ],
)
def test_image_source_comparison_rejects_changed_or_untracked_app_content(
    reviewed_repository,
    tmp_path,
    changed_main: bytes | None,
    extra_app_path: str | None,
    expected_error: str,
):
    source, _, _ = reviewed_repository
    inventory = tmp_path / "rootfs.tar"
    write_source_rootfs(
        inventory,
        source,
        changed_main=changed_main,
        extra_app_path=extra_app_path,
    )

    result = run_helper(
        "validate-image-source",
        "--archive",
        str(inventory),
        "--source-repository",
        str(source),
        check=False,
    )

    assert result.returncode != 0
    assert expected_error in result.stderr


def test_secret_scan_accepts_valid_report_with_no_findings(tmp_path: Path):
    report = tmp_path / "scan.json"
    report.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [{"Target": "source", "Class": "secret", "Secrets": []}],
            }
        ),
        encoding="utf-8",
    )

    result = run_helper("validate-scan-report", "--report", str(report))

    assert json.loads(result.stdout) == {"secret_findings": 0}


def test_secret_scan_rejects_findings_without_disclosing_them(tmp_path: Path):
    report = tmp_path / "scan.json"
    secret = "do-not-print-this-secret"
    report.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [
                    {
                        "Target": "source",
                        "Class": "secret",
                        "Secrets": [{"RuleID": "synthetic", "Match": secret}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_helper("validate-scan-report", "--report", str(report), check=False)

    assert result.returncode != 0
    assert "1 secret finding" in result.stderr
    assert secret not in result.stdout + result.stderr


@pytest.mark.parametrize("contents", ["{}", "not json", '{"SchemaVersion": 2}'])
def test_secret_scan_fails_closed_on_unusable_report(tmp_path: Path, contents: str):
    report = tmp_path / "scan.json"
    report.write_text(contents, encoding="utf-8")

    result = run_helper("validate-scan-report", "--report", str(report), check=False)

    assert result.returncode != 0
    assert "unusable" in result.stderr


def write_junit(path: Path, *, container_cases: int = 6, skipped: int = 0) -> None:
    cases = "".join(
        f'<testcase classname="tests.container.test_runtime_image" name="case_{index}"/>'
        for index in range(container_cases - skipped)
    )
    cases += "".join(
        f'<testcase classname="tests.container.test_runtime_image" name="skip_{index}"><skipped/></testcase>'
        for index in range(skipped)
    )
    path.write_text(
        f'<testsuites tests="{container_cases}" failures="0" errors="0" skipped="{skipped}">'
        f'<testsuite name="pytest" tests="{container_cases}" failures="0" errors="0" skipped="{skipped}">'
        f"{cases}</testsuite></testsuites>",
        encoding="utf-8",
    )


def synthetic_receipt() -> dict:
    return {
        "schema_version": 1,
        "source_repository": "example/public-app",
        "source_sha": "1" * 40,
        "source_tree": "2" * 40,
        "platform": "linux/amd64",
        "tested_image_id": "sha256:" + "3" * 64,
        "archive_sha256": "4" * 64,
        "tests": {
            "tests": 6,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "container_cases": 6,
            "container_skipped": 0,
        },
        "build_inputs": {
            "python_base": {
                "reference": "pkg:docker/python@3.11-slim?platform=linux%2Famd64",
                "digest": "sha256:" + "5" * 64,
            },
            "uv_version": "0.12.12",
        },
    }


def test_pytest_receipt_records_actual_totals_and_six_image_cases(tmp_path: Path):
    report = tmp_path / "pytest.xml"
    write_junit(report)

    result = run_helper(
        "validate-pytest-report",
        "--report",
        str(report),
        "--required-container-cases",
        "6",
    )

    assert json.loads(result.stdout) == {
        "errors": 0,
        "failures": 0,
        "skipped": 0,
        "tests": 6,
        "container_cases": 6,
        "container_skipped": 0,
    }


@pytest.mark.parametrize(
    ("container_cases", "skipped"),
    [(5, 0), (6, 1)],
)
def test_pytest_receipt_rejects_missing_or_skipped_image_case(
    tmp_path: Path, container_cases: int, skipped: int
):
    report = tmp_path / "pytest.xml"
    write_junit(report, container_cases=container_cases, skipped=skipped)

    result = run_helper(
        "validate-pytest-report",
        "--report",
        str(report),
        "--required-container-cases",
        "6",
        check=False,
    )

    assert result.returncode != 0
    assert "container test contract" in result.stderr


def test_build_receipt_binds_archive_source_image_and_actual_tests(tmp_path: Path):
    archive = tmp_path / "image.tar"
    archive.write_bytes(b"tested image archive")
    report = tmp_path / "pytest.xml"
    write_junit(report)
    receipt = tmp_path / "build-receipt.json"
    source_sha = "1" * 40
    source_tree = "2" * 40
    image_id = "sha256:" + "3" * 64
    base_digest = "sha256:" + "5" * 64
    build_metadata = tmp_path / "build-metadata.json"
    build_metadata.write_text(
        json.dumps(
            {
                "containerimage.config.digest": image_id,
                "buildx.build.provenance": {
                    "materials": [
                        {
                            "uri": "pkg:docker/python@3.11-slim?platform=linux%2Famd64",
                            "digest": {"sha256": base_digest.removeprefix("sha256:")},
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    uv_version = tmp_path / "uv-version.txt"
    uv_version.write_text("uv 0.12.12 (x86_64-unknown-linux-gnu)\n", encoding="utf-8")

    run_helper(
        "create-build-receipt",
        "--source-repository",
        "example/public-app",
        "--source-sha",
        source_sha,
        "--source-tree",
        source_tree,
        "--platform",
        "linux/amd64",
        "--image-id",
        image_id,
        "--archive",
        str(archive),
        "--pytest-report",
        str(report),
        "--build-metadata",
        str(build_metadata),
        "--uv-version-file",
        str(uv_version),
        "--output",
        str(receipt),
    )

    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload["source_sha"] == source_sha
    assert payload["source_tree"] == source_tree
    assert payload["tested_image_id"] == image_id
    assert payload["platform"] == "linux/amd64"
    assert payload["tests"]["tests"] == 6
    assert payload["tests"]["container_cases"] == 6
    assert payload["build_inputs"] == {
        "python_base": {
            "reference": "pkg:docker/python@3.11-slim?platform=linux%2Famd64",
            "digest": base_digest,
        },
        "uv_version": "0.12.12",
    }
    assert len(payload["archive_sha256"]) == 64

    run_helper(
        "validate-build-receipt",
        "--receipt",
        str(receipt),
        "--archive",
        str(archive),
        "--source-repository",
        "example/public-app",
        "--source-sha",
        source_sha,
        "--platform",
        "linux/amd64",
    )
    archive.write_bytes(b"substituted image archive")
    result = run_helper(
        "validate-build-receipt",
        "--receipt",
        str(receipt),
        "--archive",
        str(archive),
        "--source-repository",
        "example/public-app",
        "--source-sha",
        source_sha,
        "--platform",
        "linux/amd64",
        check=False,
    )
    assert result.returncode != 0
    assert "archive integrity" in result.stderr


@pytest.mark.parametrize("mutation", ["missing-base", "wrong-image", "bad-uv"])
def test_build_receipt_rejects_unproven_build_inputs(tmp_path: Path, mutation: str):
    archive = tmp_path / "image.tar"
    archive.write_bytes(b"tested image archive")
    report = tmp_path / "pytest.xml"
    write_junit(report)
    image_id = "sha256:" + "3" * 64
    metadata = {
        "containerimage.config.digest": image_id,
        "buildx.build.provenance": {
            "materials": [
                {
                    "uri": "pkg:docker/python@3.11-slim?platform=linux%2Famd64",
                    "digest": {"sha256": "5" * 64},
                }
            ]
        },
    }
    if mutation == "missing-base":
        metadata["buildx.build.provenance"]["materials"] = []
    elif mutation == "wrong-image":
        metadata["containerimage.config.digest"] = "sha256:" + "9" * 64
    build_metadata = tmp_path / "build-metadata.json"
    build_metadata.write_text(json.dumps(metadata), encoding="utf-8")
    uv_version = tmp_path / "uv-version.txt"
    uv_version.write_text(
        "not a uv version\n"
        if mutation == "bad-uv"
        else "uv 0.12.12 (x86_64-unknown-linux-gnu)\n",
        encoding="utf-8",
    )

    result = run_helper(
        "create-build-receipt",
        "--source-repository",
        "example/public-app",
        "--source-sha",
        "1" * 40,
        "--source-tree",
        "2" * 40,
        "--platform",
        "linux/amd64",
        "--image-id",
        image_id,
        "--archive",
        str(archive),
        "--pytest-report",
        str(report),
        "--build-metadata",
        str(build_metadata),
        "--uv-version-file",
        str(uv_version),
        "--output",
        str(tmp_path / "receipt.json"),
        check=False,
    )

    assert result.returncode != 0
    assert "build input" in result.stderr


def test_release_predicate_binds_registry_digest_to_build_receipt(tmp_path: Path):
    receipt = tmp_path / "build-receipt.json"
    receipt.write_text(json.dumps(synthetic_receipt()), encoding="utf-8")
    predicate = tmp_path / "predicate.json"
    digest = "sha256:" + "5" * 64

    run_helper(
        "create-release-predicate",
        "--build-receipt",
        str(receipt),
        "--image-name",
        "ghcr.io/example/public-app",
        "--digest",
        digest,
        "--output",
        str(predicate),
    )

    payload = json.loads(predicate.read_text(encoding="utf-8"))
    assert payload["source_sha"] == "1" * 40
    assert payload["registry_digest"] == digest
    assert payload["tested_image_id"] == "sha256:" + "3" * 64
    assert payload["tests"]["container_cases"] == 6
    assert payload["build_inputs"]["uv_version"] == "0.12.12"


def test_loaded_image_must_match_tested_image_id(tmp_path: Path):
    receipt = tmp_path / "build-receipt.json"
    receipt.write_text(json.dumps(synthetic_receipt()), encoding="utf-8")

    run_helper(
        "validate-loaded-image",
        "--receipt",
        str(receipt),
        "--image-id",
        "sha256:" + "3" * 64,
    )
    result = run_helper(
        "validate-loaded-image",
        "--receipt",
        str(receipt),
        "--image-id",
        "sha256:" + "5" * 64,
        check=False,
    )
    assert result.returncode != 0
    assert "tested image identity" in result.stderr


def test_push_receipt_and_manifest_bind_registry_digest_to_tested_config(
    tmp_path: Path,
):
    digest = "sha256:" + "6" * 64
    push_output = tmp_path / "push.log"
    push_output.write_text(
        "layer: pushed\n" + f"run-123-1-sha-{'1' * 40}: digest: {digest} size: 742\n",
        encoding="utf-8",
    )
    receipt = tmp_path / "build-receipt.json"
    receipt.write_text(json.dumps(synthetic_receipt()), encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": synthetic_receipt()["tested_image_id"],
                    "size": 5485,
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": "sha256:" + "7" * 64,
                        "size": 29792658,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_helper("extract-push-digest", "--push-output", str(push_output))
    assert json.loads(result.stdout) == {"digest": digest}
    run_helper(
        "validate-registry-manifest",
        "--manifest",
        str(manifest),
        "--receipt",
        str(receipt),
        "--digest",
        digest,
    )

    changed = json.loads(manifest.read_text(encoding="utf-8"))
    changed["config"]["digest"] = "sha256:" + "7" * 64
    manifest.write_text(json.dumps(changed), encoding="utf-8")
    mismatch = run_helper(
        "validate-registry-manifest",
        "--manifest",
        str(manifest),
        "--receipt",
        str(receipt),
        "--digest",
        digest,
        check=False,
    )
    assert mismatch.returncode != 0
    assert "tested image config" in mismatch.stderr


def test_registry_manifest_rejects_formatted_descriptor(tmp_path: Path):
    digest = "sha256:" + "6" * 64
    receipt = tmp_path / "build-receipt.json"
    receipt.write_text(json.dumps(synthetic_receipt()), encoding="utf-8")
    descriptor = tmp_path / "formatted-descriptor.json"
    descriptor.write_text(
        json.dumps(
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": digest,
                "size": 742,
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ),
        encoding="utf-8",
    )

    result = run_helper(
        "validate-registry-manifest",
        "--manifest",
        str(descriptor),
        "--receipt",
        str(receipt),
        "--digest",
        digest,
        check=False,
    )

    assert result.returncode != 0
    assert "registry manifest is unusable" in result.stderr


@pytest.mark.parametrize(
    "push_output",
    [
        "pushed without digest\n",
        "digest: sha256:" + "6" * 63 + " size: 1\n",
        "digest: sha256:"
        + "6" * 64
        + " size: 1\n"
        + "digest: sha256:"
        + "7" * 64
        + " size: 2\n",
    ],
)
def test_push_digest_extraction_fails_closed(tmp_path: Path, push_output: str):
    output = tmp_path / "push.log"
    output.write_text(push_output, encoding="utf-8")

    result = run_helper(
        "extract-push-digest", "--push-output", str(output), check=False
    )

    assert result.returncode != 0
    assert "push-derived digest" in result.stderr


@pytest.mark.parametrize(
    ("event_name", "ref", "sha", "workflow_sha", "source_sha"),
    [
        ("push", "refs/heads/main", "1" * 40, "1" * 40, "3" * 40),
        ("workflow_dispatch", "refs/heads/release", "1" * 40, "1" * 40, "3" * 40),
        ("workflow_dispatch", "refs/heads/main", "1" * 40, "2" * 40, "3" * 40),
        ("workflow_dispatch", "refs/heads/main", "1" * 40, "1" * 40, "main"),
    ],
)
def test_invocation_validation_rejects_non_main_or_untrusted_workflow(
    event_name: str, ref: str, sha: str, workflow_sha: str, source_sha: str
):
    result = run_helper(
        "validate-invocation",
        "--event-name",
        event_name,
        "--ref",
        ref,
        "--sha",
        sha,
        "--workflow-sha",
        workflow_sha,
        "--source-sha",
        source_sha,
        check=False,
    )

    assert result.returncode != 0
    assert (
        "trusted main workflow" in result.stderr
        or "full lowercase 40-hex" in result.stderr
    )


def test_invocation_validation_accepts_full_source_sha_on_trusted_main():
    workflow_sha = "1" * 40

    run_helper(
        "validate-invocation",
        "--event-name",
        "workflow_dispatch",
        "--ref",
        "refs/heads/main",
        "--sha",
        workflow_sha,
        "--workflow-sha",
        workflow_sha,
        "--source-sha",
        "2" * 40,
    )


def test_workflow_satisfies_manual_publication_policy():
    run_helper("validate-workflow", "--workflow", str(WORKFLOW))


@pytest.mark.parametrize(
    "outcome",
    ["verified", "provenance-failure", "custom-failure", "empty", "wrong-receipt"],
)
def test_verification_step_fetches_custom_bundle_from_oci_and_fails_closed(
    tmp_path: Path, outcome: str
):
    """Exercise the real shell and receipt validator; fake only the external CLI.

    Catches API-filter retrieval, weakened CLI constraints, swallowed verifier
    failures (even with plausible stdout), and bypassed receipt validation.
    This boundary test does not simulate or claim cryptographic verification.
    """
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    step = next(
        step
        for step in workflow["jobs"]["verify-published"]["steps"]
        if step.get("name")
        == "Verify registry attestations and selected source binding"
    )
    receipt = synthetic_receipt()
    artifact = tmp_path / "release-artifact"
    artifact.mkdir()
    (artifact / "build-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
    image = "ghcr.io/example/public-app"
    digest = "sha256:" + "6" * 64
    predicate_type = "https://github.com/example/public-app/manual-container-release/v1"
    statement = {
        "subject": [{"name": image, "digest": {"sha256": "6" * 64}}],
        "predicateType": predicate_type,
        "predicate": {**receipt, "image_name": image, "registry_digest": digest},
    }
    if outcome == "wrong-receipt":
        statement["predicate"]["source_tree"] = "8" * 40
    verification = (
        [] if outcome == "empty" else [{"verificationResult": {"statement": statement}}]
    )
    (tmp_path / "cli-result.json").write_text(
        json.dumps(verification), encoding="utf-8"
    )
    (tmp_path / "trusted-workflow").symlink_to(ROOT, target_is_directory=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "python3").symlink_to(sys.executable)
    gh = bin_dir / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        + textwrap.dedent("""\
        import json
        import os
        import sys
        from pathlib import Path

        args = sys.argv[1:]
        with Path("cli-calls.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps(args) + "\\n")
        custom = "--format" in args
        if custom and "--bundle-from-oci" not in args:
            sys.exit("HTTP 422: predicate_type invalid predicate type provided")
        if custom:
            print(Path("cli-result.json").read_text(encoding="utf-8"))
        if os.environ["CLI_OUTCOME"] == ("custom-failure" if custom else "provenance-failure"):
            sys.exit(1)
        """),
        encoding="utf-8",
    )
    gh.chmod(0o755)
    result = subprocess.run(
        [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-e",
            "-o",
            "pipefail",
            "-c",
            step["run"],
        ],
        cwd=tmp_path,
        env={
            "PATH": str(bin_dir),
            "RUNNER_TEMP": str(tmp_path),
            "CLI_OUTCOME": outcome,
            "GITHUB_REPOSITORY": "example/public-app",
            "GITHUB_SHA": "7" * 40,
            "SOURCE_SHA": "1" * 40,
            "PUBLISHED_IMAGE": image + "@" + digest,
            "PREDICATE_TYPE": predicate_type,
            "IMAGE_NAME": image,
            "DIGEST": digest,
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    calls = [
        json.loads(line)
        for line in (tmp_path / "cli-calls.jsonl").read_text().splitlines()
    ]
    # Hand-derived CLI contract: exact subject, signer/source and predicate;
    # both invocations must preserve it regardless of retrieval mechanism.
    assert len(calls) == (1 if outcome == "provenance-failure" else 2)
    for index, args in enumerate(calls):
        assert args[:3] == ["attestation", "verify", "oci://" + image + "@" + digest]
        flags = args[3:]
        assert "--deny-self-hosted-runners" in flags
        flags.remove("--deny-self-hosted-runners")
        assert ("--bundle-from-oci" in flags) is bool(index)
        if index:
            flags.remove("--bundle-from-oci")
        expected = {
            "--repo": "example/public-app",
            "--signer-workflow": "example/public-app/.github/workflows/docker-publish.yml",
            "--source-ref": "refs/heads/main",
            "--source-digest": "7" * 40,
            "--predicate-type": predicate_type
            if index
            else "https://slsa.dev/provenance/v1",
        }
        if index:
            expected["--format"] = "json"
        assert len(flags) == 2 * len(expected)
        assert dict(zip(flags[::2], flags[1::2], strict=True)) == expected
    if outcome == "verified":
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout) == {"attestation": "verified"}
    else:
        assert result.returncode != 0
        assert '"attestation": "verified"' not in result.stdout
        if outcome in {"empty", "wrong-receipt"}:
            assert "complete tested build receipt" in result.stderr


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("push", "manual-only"),
        ("mutable-checkout", "exact selected source"),
        ("remove-image-tests", "published image tests"),
        ("tag-only", "digest"),
        ("railway", "Railway"),
        ("unpin-action", "full commit SHA"),
        ("remove-package-read", "package read"),
        ("remove-registry-login", "read-only registry login"),
        ("remove-registry-logout", "registry credentials"),
        ("formatted-manifest", "raw OCI manifest"),
    ],
)
def test_workflow_policy_rejects_unsafe_mutations(
    tmp_path: Path, mutation: str, expected_error: str
):
    document = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    if mutation == "push":
        document["on"]["push"] = {"branches": ["main"]}
    elif mutation == "mutable-checkout":
        for step in document["jobs"]["build-and-test"]["steps"]:
            if step.get("name") == "Checkout selected source":
                step["with"]["ref"] = "main"
    elif mutation == "remove-image-tests":
        document["jobs"]["verify-published"]["steps"] = [
            step
            for step in document["jobs"]["verify-published"]["steps"]
            if step.get("id") != "test-published-image"
        ]
    elif mutation == "tag-only":
        document["jobs"]["verify-published"]["env"]["PUBLISHED_IMAGE"] = (
            "ghcr.io/example/public-app:sha-${{ inputs.source_sha }}"
        )
    elif mutation == "railway":
        document["jobs"]["publish"]["steps"].append(
            {"name": "Deploy", "run": "railway up", "env": {"RAILWAY_TOKEN": "x"}}
        )
    elif mutation == "unpin-action":
        document["jobs"]["build-and-test"]["steps"][0]["uses"] = "actions/checkout@v6"
    elif mutation == "remove-package-read":
        del document["jobs"]["verify-published"]["permissions"]["packages"]
    elif mutation == "remove-registry-login":
        document["jobs"]["verify-published"]["steps"] = [
            step
            for step in document["jobs"]["verify-published"]["steps"]
            if step.get("name") != "Log in for read-only package verification"
        ]
    elif mutation == "remove-registry-logout":
        for step in document["jobs"]["verify-published"]["steps"]:
            if step.get("name") == "Pull and inspect the exact published digest":
                step["run"] = step["run"].replace(
                    'docker logout "$REGISTRY" >/dev/null\n', ""
                )
    elif mutation == "formatted-manifest":
        for step in document["jobs"]["publish"]["steps"]:
            if step.get("id") == "promote":
                step["run"] = step["run"].replace(
                    "--raw", "--format '{{json .Manifest}}'"
                )
    candidate = tmp_path / "workflow.yml"
    candidate.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    result = run_helper("validate-workflow", "--workflow", str(candidate), check=False)

    assert result.returncode != 0
    assert expected_error in result.stderr


def test_attestation_verification_requires_digest_and_selected_source(tmp_path: Path):
    source_sha = "1" * 40
    digest = "sha256:" + "2" * 64
    image_name = "ghcr.io/example/public-app"
    predicate_type = "https://github.com/example/public-app/manual-container-release/v1"
    receipt = synthetic_receipt()
    receipt_file = tmp_path / "build-receipt.json"
    receipt_file.write_text(json.dumps(receipt), encoding="utf-8")
    verification = tmp_path / "verification.json"
    verification.write_text(
        json.dumps(
            [
                {
                    "verificationResult": {
                        "statement": {
                            "subject": [
                                {"name": image_name, "digest": {"sha256": "2" * 64}}
                            ],
                            "predicateType": predicate_type,
                            "predicate": {
                                **receipt,
                                "image_name": image_name,
                                "registry_digest": digest,
                            },
                        }
                    }
                }
            ]
        ),
        encoding="utf-8",
    )

    run_helper(
        "validate-attestation",
        "--verification",
        str(verification),
        "--build-receipt",
        str(receipt_file),
        "--predicate-type",
        predicate_type,
        "--source-repository",
        "example/public-app",
        "--source-sha",
        source_sha,
        "--image-name",
        image_name,
        "--digest",
        digest,
    )

    original = json.loads(verification.read_text(encoding="utf-8"))
    for field_path, replacement in (
        (("source_tree",), "8" * 40),
        (("tested_image_id",), "sha256:" + "8" * 64),
        (("archive_sha256",), "8" * 64),
        (("tests", "container_cases"), 5),
        (("build_inputs", "uv_version"), "9.9.9"),
        (("build_inputs", "python_base", "digest"), "sha256:" + "8" * 64),
    ):
        changed = copy.deepcopy(original)
        target = changed[0]["verificationResult"]["statement"]["predicate"]
        for key in field_path[:-1]:
            target = target[key]
        target[field_path[-1]] = replacement
        verification.write_text(json.dumps(changed), encoding="utf-8")
        result = run_helper(
            "validate-attestation",
            "--verification",
            str(verification),
            "--build-receipt",
            str(receipt_file),
            "--predicate-type",
            predicate_type,
            "--source-repository",
            "example/public-app",
            "--source-sha",
            source_sha,
            "--image-name",
            image_name,
            "--digest",
            digest,
            check=False,
        )
        assert result.returncode != 0
        assert "complete tested build receipt" in result.stderr
