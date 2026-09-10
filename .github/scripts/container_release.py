#!/usr/bin/env python3
"""Fail-closed checks and receipts for manual container publication.

The workflow executes this copy from its own reviewed commit, never from the
historical application source selected for the build.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ACTION_RE = re.compile(r"^[^\s@]+@[0-9a-f]{40}$")
PREDICATE_SUFFIX = "/manual-container-release/v1"
REQUIRED_IMAGE_PATHS = {"app/main.py", "app/.venv/pyvenv.cfg"}
EMPTY_UV_GIT_MARKER = "root/.cache/uv/sdists-v9/.git"
GENERATED_APP_PREFIXES = ("app/.venv/", "app/workspace_mcp.egg-info/")
GENERATED_APP_ENTRIES = {
    "app",
    "app/.venv",
    "app/workspace_mcp.egg-info",
    "app/store_creds",
}
PYTHON_BASE_URI = "pkg:docker/python@3.11-slim?platform=linux%2Famd64"


class ReleaseError(Exception):
    """A safe, value-free release validation failure."""


def _git(repository: Path, *arguments: str, allow_failure: bool = False) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode and not allow_failure:
        raise ReleaseError("git validation failed")
    return result.stdout.strip()


def _require_sha(value: str, label: str = "source_sha") -> None:
    if not SHA_RE.fullmatch(value):
        raise ReleaseError(f"{label} must be a full lowercase 40-hex commit SHA")


def _require_digest(value: str, label: str = "digest") -> None:
    if not DIGEST_RE.fullmatch(value):
        raise ReleaseError(f"{label} must be a canonical sha256 digest")


def _repository_from_remote(remote: str) -> str | None:
    if remote.startswith("git@github.com:"):
        candidate = remote.removeprefix("git@github.com:")
    else:
        parsed = urlparse(remote)
        if parsed.hostname != "github.com" or parsed.username or parsed.password:
            return None
        candidate = parsed.path.lstrip("/")
    candidate = candidate.removesuffix(".git")
    return (
        candidate
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", candidate)
        else None
    )


def validate_source(args: argparse.Namespace) -> dict[str, Any]:
    repository = Path(args.repository)
    _require_sha(args.source_sha)
    remote = _git(repository, "remote", "get-url", "origin")
    if _repository_from_remote(remote) != args.expected_repository:
        raise ReleaseError(
            "source repository identity does not match the requested public repository"
        )
    resolved = _git(repository, "rev-parse", f"{args.source_sha}^{{commit}}")
    if resolved != args.source_sha:
        raise ReleaseError("selected source does not resolve to the exact commit")
    membership = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            args.source_sha,
            args.reviewed_ref,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if membership.returncode != 0:
        raise ReleaseError("selected source is not in reviewed history")
    return {
        "source_sha": args.source_sha,
        "source_tree": _git(repository, "rev-parse", f"{args.source_sha}^{{tree}}"),
    }


def validate_invocation(args: argparse.Namespace) -> dict[str, Any]:
    for value, label in ((args.sha, "event SHA"), (args.workflow_sha, "workflow SHA")):
        _require_sha(value, label)
    _require_sha(args.source_sha)
    if (
        args.event_name != "workflow_dispatch"
        or args.ref != "refs/heads/main"
        or args.sha != args.workflow_sha
    ):
        raise ReleaseError("publication requires a trusted main workflow invocation")
    return {"workflow_sha": args.workflow_sha}


def validate_context(args: argparse.Namespace) -> dict[str, Any]:
    repository = Path(args.repository)
    _require_sha(args.source_sha)
    if _git(repository, "rev-parse", "HEAD") != args.source_sha:
        raise ReleaseError("build context is not checked out at the selected source")
    if _git(repository, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ReleaseError("build context is not clean")
    tracked = _git(repository, "ls-files", "-z")
    tracked_files = [name for name in tracked.split("\0") if name]
    if "Dockerfile" not in tracked_files or ".dockerignore" not in tracked_files:
        raise ReleaseError("build context is missing its reviewed container controls")
    return {
        "source_sha": args.source_sha,
        "source_tree": _git(repository, "rev-parse", "HEAD^{tree}"),
        "tracked_files": len(tracked_files),
    }


def _forbidden_image_path(
    name: str,
    *,
    is_file: bool = False,
    size: int = -1,
    uid: int = -1,
    mode: int = -1,
) -> bool:
    path = name.removeprefix("./").rstrip("/")
    lowered = path.lower()
    parts = lowered.split("/")
    basename = parts[-1]
    if lowered == EMPTY_UV_GIT_MARKER:
        return not (is_file and size == 0 and uid == 0 and mode & 0o7777 == 0o644)
    if ".git" in parts or ".ssh" in parts or ".aws" in parts or ".credentials" in parts:
        return True
    if ".kube" in parts or ".docker" in parts:
        return True
    if any(part.startswith(".env") for part in parts):
        return True
    if lowered == "app/tests" or lowered.startswith("app/tests/"):
        return True
    if basename in {"credentials.json", "client_secret.json", "client_secrets.json"}:
        return True
    if basename in {".netrc", ".npmrc", ".pypirc"}:
        return True
    if lowered.startswith("app/store_creds/"):
        return True
    return False


def validate_image_inventory(args: argparse.Namespace) -> dict[str, Any]:
    try:
        with tarfile.open(args.archive, "r:*") as archive:
            entries = [
                (
                    item.name.removeprefix("./").rstrip("/"),
                    item.isfile(),
                    item.size,
                    item.uid,
                    item.mode,
                )
                for item in archive
            ]
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError("image inventory archive is unusable") from error
    if not entries:
        raise ReleaseError("image inventory archive is unusable")
    if any(
        _forbidden_image_path(name, is_file=is_file, size=size, uid=uid, mode=mode)
        for name, is_file, size, uid, mode in entries
    ):
        raise ReleaseError("image inventory contains a forbidden path")
    names = {name for name, *_ in entries}
    if not REQUIRED_IMAGE_PATHS.issubset(names):
        raise ReleaseError("image inventory is missing required runtime paths")
    return {"inventory_entries": len(entries)}


def _sha256_stream(stream) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def validate_image_source(args: argparse.Namespace) -> dict[str, Any]:
    validate_image_inventory(args)
    source = Path(args.source_repository)
    if _git(source, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ReleaseError("clean tracked source comparison requires a clean checkout")
    tracked = set(filter(None, _git(source, "ls-files", "-z").split("\0")))
    matched = 0
    try:
        with tarfile.open(args.archive, "r:*") as archive:
            for item in archive:
                name = item.name.removeprefix("./").rstrip("/")
                if not name.startswith("app/") and name != "app":
                    continue
                if name in GENERATED_APP_ENTRIES or name.startswith(
                    GENERATED_APP_PREFIXES
                ):
                    continue
                relative = name.removeprefix("app/")
                source_path = source / relative
                if item.isdir():
                    if not any(path.startswith(relative + "/") for path in tracked):
                        raise ReleaseError(
                            "image application directory is not clean tracked source"
                        )
                    continue
                if relative not in tracked:
                    raise ReleaseError(
                        "image application file is not clean tracked source"
                    )
                if item.issym():
                    if (
                        not source_path.is_symlink()
                        or os.readlink(source_path) != item.linkname
                    ):
                        raise ReleaseError("image application source content differs")
                elif item.isfile():
                    stream = archive.extractfile(item)
                    if stream is None or _sha256_stream(stream) != _sha256_file(
                        source_path
                    ):
                        raise ReleaseError("image application source content differs")
                else:
                    raise ReleaseError("image application source type differs")
                matched += 1
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError("image source comparison archive is unusable") from error
    if matched < 2:
        raise ReleaseError("image source comparison matched too few tracked files")
    return {"matched_source_files": matched}


def _read_json(path: str | Path, error: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exception:
        raise ReleaseError(error) from exception


def validate_scan_report(args: argparse.Namespace) -> dict[str, Any]:
    document = _read_json(args.report, "secret scan report is unusable")
    if not isinstance(document, dict) or document.get("SchemaVersion") not in {1, 2}:
        raise ReleaseError("secret scan report is unusable")
    results = document.get("Results")
    if not isinstance(results, list):
        raise ReleaseError("secret scan report is unusable")
    findings = 0
    for result in results:
        if not isinstance(result, dict):
            raise ReleaseError("secret scan report is unusable")
        secrets = result.get("Secrets", [])
        if secrets is None:
            secrets = []
        if not isinstance(secrets, list):
            raise ReleaseError("secret scan report is unusable")
        findings += len(secrets)
    if findings:
        noun = "finding" if findings == 1 else "findings"
        raise ReleaseError(
            f"secret scan rejected {findings} secret {noun}; values are redacted"
        )
    return {"secret_findings": 0}


def pytest_summary(
    path: str | Path, required_container_cases: int = 6
) -> dict[str, int]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        raise ReleaseError("pytest report is unusable") from error
    cases = list(root.iter("testcase"))
    if not cases:
        raise ReleaseError("pytest report is unusable")
    failures = sum(case.find("failure") is not None for case in cases)
    errors = sum(case.find("error") is not None for case in cases)
    skipped = sum(case.find("skipped") is not None for case in cases)
    container = [
        case
        for case in cases
        if "tests.container.test_runtime_image" in case.attrib.get("classname", "")
        or case.attrib.get("file", "").endswith("tests/container/test_runtime_image.py")
    ]
    container_skipped = sum(case.find("skipped") is not None for case in container)
    if failures or errors:
        raise ReleaseError("pytest report records failed tests")
    if len(container) != required_container_cases or container_skipped:
        raise ReleaseError(
            "pytest report violates the six-case container test contract"
        )
    return {
        "errors": errors,
        "failures": failures,
        "skipped": skipped,
        "tests": len(cases),
        "container_cases": len(container),
        "container_skipped": container_skipped,
    }


def validate_pytest_report(args: argparse.Namespace) -> dict[str, Any]:
    return pytest_summary(args.report, args.required_container_cases)


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_build_receipt(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ReleaseError("build receipt is unusable")
    _require_sha(str(document.get("source_sha", "")))
    _require_sha(str(document.get("source_tree", "")), "source_tree")
    _require_digest(str(document.get("tested_image_id", "")), "tested image ID")
    if not re.fullmatch(r"[0-9a-f]{64}", str(document.get("archive_sha256", ""))):
        raise ReleaseError("build receipt has an invalid archive digest")
    if document.get("platform") != "linux/amd64":
        raise ReleaseError("build receipt has an invalid platform")
    tests = document.get("tests")
    if (
        not isinstance(tests, dict)
        or tests.get("container_cases") != 6
        or tests.get("container_skipped") != 0
    ):
        raise ReleaseError(
            "build receipt violates the six-case container test contract"
        )
    if tests.get("failures") != 0 or tests.get("errors") != 0:
        raise ReleaseError("build receipt records failed tests")
    inputs = document.get("build_inputs")
    if not isinstance(inputs, dict):
        raise ReleaseError("build receipt is missing actual build inputs")
    python_base = inputs.get("python_base")
    if (
        not isinstance(python_base, dict)
        or python_base.get("reference") != PYTHON_BASE_URI
    ):
        raise ReleaseError("build receipt has an invalid Python base input")
    _require_digest(str(python_base.get("digest", "")), "Python base input digest")
    if not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",
        str(inputs.get("uv_version", "")),
    ):
        raise ReleaseError("build receipt has an invalid uv build input")
    return document


def _write_json(path: str | Path, document: dict[str, Any]) -> None:
    Path(path).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def create_build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    _require_sha(args.source_sha)
    _require_sha(args.source_tree, "source_tree")
    _require_digest(args.image_id, "tested image ID")
    if args.platform != "linux/amd64":
        raise ReleaseError("build receipt has an invalid platform")
    metadata = _read_json(
        args.build_metadata, "actual build input metadata is unusable"
    )
    if (
        not isinstance(metadata, dict)
        or metadata.get("containerimage.config.digest") != args.image_id
    ):
        raise ReleaseError(
            "actual build input metadata does not match the tested image"
        )
    provenance = metadata.get("buildx.build.provenance")
    materials = provenance.get("materials") if isinstance(provenance, dict) else None
    base_materials = [
        material
        for material in materials or []
        if isinstance(material, dict) and material.get("uri") == PYTHON_BASE_URI
    ]
    if len(base_materials) != 1:
        raise ReleaseError("actual build input metadata lacks one resolved Python base")
    base_hex = base_materials[0].get("digest", {}).get("sha256")
    base_digest = f"sha256:{base_hex}"
    _require_digest(base_digest, "actual Python base build input")
    try:
        uv_output = Path(args.uv_version_file).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise ReleaseError("actual uv build input is unusable") from error
    uv_match = re.fullmatch(
        r"uv ([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?) \(x86_64-unknown-linux-gnu\)",
        uv_output,
    )
    if not uv_match:
        raise ReleaseError("actual uv build input is unusable")
    document = {
        "schema_version": 1,
        "source_repository": args.source_repository,
        "source_sha": args.source_sha,
        "source_tree": args.source_tree,
        "platform": args.platform,
        "tested_image_id": args.image_id,
        "archive_sha256": _sha256_file(args.archive),
        "tests": pytest_summary(args.pytest_report),
        "build_inputs": {
            "python_base": {
                "reference": PYTHON_BASE_URI,
                "digest": base_digest,
            },
            "uv_version": uv_match.group(1),
        },
    }
    _validate_build_receipt(document)
    _write_json(args.output, document)
    return {"receipt": "created"}


def validate_build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    document = _validate_build_receipt(
        _read_json(args.receipt, "build receipt is unusable")
    )
    _require_sha(args.source_sha)
    if (
        document.get("source_repository") != args.source_repository
        or document.get("source_sha") != args.source_sha
    ):
        raise ReleaseError("build receipt does not match the selected source")
    if document.get("platform") != args.platform:
        raise ReleaseError("build receipt does not match the required platform")
    if document.get("archive_sha256") != _sha256_file(args.archive):
        raise ReleaseError("build receipt archive integrity check failed")
    return {
        "archive_sha256": document["archive_sha256"],
        "tested_image_id": document["tested_image_id"],
    }


def validate_loaded_image(args: argparse.Namespace) -> dict[str, Any]:
    document = _validate_build_receipt(
        _read_json(args.receipt, "build receipt is unusable")
    )
    _require_digest(args.image_id, "loaded image ID")
    if document["tested_image_id"] != args.image_id:
        raise ReleaseError("loaded image does not match the tested image identity")
    return {"tested_image_id": args.image_id}


def extract_push_digest(args: argparse.Namespace) -> dict[str, Any]:
    try:
        lines = Path(args.push_output).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ReleaseError("push-derived digest output is unusable") from error
    matches = [
        match.group(1)
        for line in lines
        if (
            match := re.fullmatch(
                r"(?:[^\s]+: )?digest: (sha256:[0-9a-f]{64}) size: [0-9]+",
                line,
            )
        )
    ]
    if len(matches) != 1:
        raise ReleaseError("push-derived digest output is missing or ambiguous")
    return {"digest": matches[0]}


def validate_registry_manifest(args: argparse.Namespace) -> dict[str, Any]:
    _require_digest(args.digest)
    receipt = _validate_build_receipt(
        _read_json(args.receipt, "build receipt is unusable")
    )
    manifest = _read_json(args.manifest, "registry manifest is unusable")
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise ReleaseError("registry manifest is unusable")
    config = manifest.get("config")
    if (
        not isinstance(config, dict)
        or config.get("digest") != receipt["tested_image_id"]
    ):
        raise ReleaseError(
            "registry manifest does not reference the tested image config"
        )
    return {"digest": args.digest, "tested_image_id": receipt["tested_image_id"]}


def create_release_predicate(args: argparse.Namespace) -> dict[str, Any]:
    receipt = _validate_build_receipt(
        _read_json(args.build_receipt, "build receipt is unusable")
    )
    _require_digest(args.digest)
    document = {
        **receipt,
        "image_name": args.image_name,
        "registry_digest": args.digest,
    }
    _write_json(args.output, document)
    return {"predicate": "created"}


def validate_attestation(args: argparse.Namespace) -> dict[str, Any]:
    _require_sha(args.source_sha)
    _require_digest(args.digest)
    document = _read_json(
        args.verification, "attestation verification output is unusable"
    )
    expected_receipt = _validate_build_receipt(
        _read_json(args.build_receipt, "build receipt is unusable")
    )
    if not isinstance(document, list):
        raise ReleaseError("attestation verification output is unusable")
    expected_digest = args.digest.removeprefix("sha256:")
    for item in document:
        try:
            statement = item["verificationResult"]["statement"]
            predicate = statement["predicate"]
            subjects = statement["subject"]
        except (KeyError, TypeError):
            continue
        try:
            _validate_build_receipt(predicate)
        except ReleaseError:
            continue
        subject_matches = any(
            isinstance(subject, dict)
            and subject.get("name") == args.image_name
            and subject.get("digest", {}).get("sha256") == expected_digest
            for subject in subjects
        )
        if (
            statement.get("predicateType") == args.predicate_type
            and subject_matches
            and predicate.get("source_repository") == args.source_repository
            and predicate.get("source_sha") == args.source_sha
            and predicate.get("registry_digest") == args.digest
            and predicate.get("platform") == "linux/amd64"
            and predicate.get("image_name") == args.image_name
            and all(
                predicate.get(key) == value for key, value in expected_receipt.items()
            )
        ):
            return {"attestation": "verified"}
    raise ReleaseError(
        "attestation does not contain the complete tested build receipt and digest"
    )


def _workflow_strings(value: Any):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key)
            yield from _workflow_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _workflow_strings(nested)
    elif value is not None:
        yield str(value)


def _find_step(
    job: dict[str, Any], *, name: str | None = None, step_id: str | None = None
) -> dict[str, Any]:
    for step in job.get("steps", []):
        if (name is None or step.get("name") == name) and (
            step_id is None or step.get("id") == step_id
        ):
            return step
    raise ReleaseError(f"workflow is missing required {name or step_id}")


def validate_workflow(args: argparse.Namespace) -> dict[str, Any]:
    try:
        import yaml

        document = yaml.load(
            Path(args.workflow).read_text(encoding="utf-8"), Loader=yaml.BaseLoader
        )
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ReleaseError("workflow document is unusable") from error
    triggers = document.get("on") if isinstance(document, dict) else None
    expected_trigger = {
        "workflow_dispatch": {
            "inputs": {
                "source_sha": {
                    "description": "Reviewed full application commit SHA",
                    "required": "true",
                    "type": "string",
                }
            }
        }
    }
    if triggers != expected_trigger:
        raise ReleaseError(
            "container publication must be manual-only with the reviewed source_sha input"
        )
    if document.get("permissions") != {}:
        raise ReleaseError("workflow-level permissions must be empty")
    if document.get("concurrency") != {
        "group": "manual-container-publication",
        "cancel-in-progress": "false",
    }:
        raise ReleaseError("workflow concurrency contract is invalid")
    jobs = document.get("jobs", {})
    required_jobs = {"validate-source", "build-and-test", "publish", "verify-published"}
    if not required_jobs.issubset(jobs):
        raise ReleaseError("workflow is missing required publication jobs")
    for job_name in ("validate-source", "build-and-test", "verify-published"):
        permissions = jobs[job_name].get("permissions", {})
        if (
            permissions.get("packages") == "write"
            or permissions.get("attestations") == "write"
            or permissions.get("id-token") == "write"
        ):
            raise ReleaseError(
                "test/build code must not receive publication permissions"
            )
    if jobs["publish"].get("permissions") != {
        "contents": "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }:
        raise ReleaseError("publication permissions are not narrowly scoped")
    if jobs["verify-published"].get("permissions") != {
        "contents": "read",
        "attestations": "read",
        "packages": "read",
    }:
        raise ReleaseError("published verification requires narrow package read access")
    for job in jobs.values():
        for step in job.get("steps", []):
            uses = step.get("uses")
            if uses and not uses.startswith("./") and not ACTION_RE.fullmatch(uses):
                raise ReleaseError("every workflow action must use a full commit SHA")
    build_job = jobs["build-and-test"]
    selected_checkout = _find_step(build_job, name="Checkout selected source")
    if selected_checkout.get("with", {}).get("ref") != "${{ inputs.source_sha }}":
        raise ReleaseError("build must checkout the exact selected source")
    if selected_checkout.get("with", {}).get("path") != "source":
        raise ReleaseError("selected source must use an isolated checkout path")
    trusted_checkout = _find_step(build_job, name="Checkout trusted workflow controls")
    if trusted_checkout.get("with", {}).get("ref") != "${{ github.workflow_sha }}":
        raise ReleaseError(
            "helper controls must come from the trusted workflow checkout"
        )
    publish_text = "\n".join(_workflow_strings(jobs["publish"])).lower()
    all_text = "\n".join(_workflow_strings(document)).lower()
    if "railway" in all_text:
        raise ReleaseError("Railway credentials and deployment steps are forbidden")
    if (
        re.search(r"docker build(?:\s|$)", publish_text)
        or "pytest" in publish_text
        or "uv run" in publish_text
    ):
        raise ReleaseError("publication job may not rebuild or execute selected source")
    if "docker save" not in "\n".join(_workflow_strings(build_job)).lower():
        raise ReleaseError("tested image must be transferred without rebuilding")
    build_text = "\n".join(_workflow_strings(build_job)).lower()
    if (
        "--metadata-file" not in build_text
        or "buildx_metadata_provenance" not in build_text
        or "--build-metadata" not in build_text
        or "--uv-version-file" not in build_text
    ):
        raise ReleaseError(
            "actual floating build inputs must be recorded from the built image"
        )
    if (
        "validate-image-source" not in build_text
        or "--source-repository source" not in build_text
    ):
        raise ReleaseError("image inventory must be compared with clean tracked source")
    if (
        "extract-push-digest" not in publish_text
        or "validate-registry-manifest" not in publish_text
    ):
        raise ReleaseError(
            "registry digest and tested image config must come from the exact push"
        )
    promote_step = _find_step(jobs["publish"], step_id="promote")
    promote_commands = str(promote_step.get("run", ""))
    if (
        'docker buildx imagetools inspect "${IMAGE_NAME}@${digest}"'
        not in promote_commands
        or "--raw" not in promote_commands
        or "--format" in promote_commands
    ):
        raise ReleaseError(
            "registry validation must consume the raw OCI manifest for the exact push digest"
        )
    if "github_run_id" not in publish_text or "github_run_attempt" not in publish_text:
        raise ReleaseError("discovery tag must be unique to the workflow run")
    verify_job = jobs["verify-published"]
    try:
        registry_login = _find_step(
            verify_job, name="Log in for read-only package verification"
        )
    except ReleaseError as error:
        raise ReleaseError(
            "published verification requires a read-only registry login"
        ) from error
    if not str(registry_login.get("uses", "")).startswith("docker/login-action@"):
        raise ReleaseError("published verification requires a read-only registry login")
    if registry_login.get("with") != {
        "registry": "${{ env.REGISTRY }}",
        "username": "${{ github.actor }}",
        "password": "${{ github.token }}",
    }:
        raise ReleaseError("published verification requires a read-only registry login")
    verify_image = str(verify_job.get("env", {}).get("PUBLISHED_IMAGE", ""))
    if "@${{ needs.publish.outputs.digest }}" not in verify_image:
        raise ReleaseError(
            "published release identity must use the verified registry digest"
        )
    if not any(
        step.get("id") == "test-published-image" for step in verify_job.get("steps", [])
    ):
        raise ReleaseError("published image tests are required")
    verify_text = "\n".join(_workflow_strings(verify_job)).lower()
    if (
        "tests/container/test_runtime_image.py" not in verify_text
        or "docker pull" not in verify_text
    ):
        raise ReleaseError("published image tests must run against the pulled digest")
    if re.search(r"docker build(?:\s|$)", verify_text):
        raise ReleaseError("published image verification must not rebuild")
    pull_step = _find_step(
        verify_job, name="Pull and inspect the exact published digest"
    )
    pull_commands = str(pull_step.get("run", ""))
    pull_position = pull_commands.find('docker pull "$PUBLISHED_IMAGE"')
    logout_position = pull_commands.find('docker logout "$REGISTRY"')
    if pull_position < 0 or logout_position < pull_position:
        raise ReleaseError(
            "published verification must clear registry credentials before source tests"
        )
    if (
        "validate-attestation" not in verify_text
        or "gh attestation verify" not in verify_text
    ):
        raise ReleaseError("published digest and source attestation must be verified")
    if (
        "download-artifact@" not in verify_text
        or "--build-receipt" not in verify_text
        or "validate-loaded-image" not in verify_text
    ):
        raise ReleaseError(
            "published verification must retain the complete tested build receipt"
        )
    return {"workflow": "valid"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser("validate-source")
    source.add_argument("--repository", required=True)
    source.add_argument("--source-sha", required=True)
    source.add_argument("--reviewed-ref", required=True)
    source.add_argument("--expected-repository", required=True)
    source.set_defaults(handler=validate_source)

    invocation = subparsers.add_parser("validate-invocation")
    invocation.add_argument("--event-name", required=True)
    invocation.add_argument("--ref", required=True)
    invocation.add_argument("--sha", required=True)
    invocation.add_argument("--workflow-sha", required=True)
    invocation.add_argument("--source-sha", required=True)
    invocation.set_defaults(handler=validate_invocation)

    context = subparsers.add_parser("validate-context")
    context.add_argument("--repository", required=True)
    context.add_argument("--source-sha", required=True)
    context.set_defaults(handler=validate_context)

    inventory = subparsers.add_parser("validate-image-inventory")
    inventory.add_argument("--archive", required=True)
    inventory.set_defaults(handler=validate_image_inventory)

    image_source = subparsers.add_parser("validate-image-source")
    image_source.add_argument("--archive", required=True)
    image_source.add_argument("--source-repository", required=True)
    image_source.set_defaults(handler=validate_image_source)

    scan = subparsers.add_parser("validate-scan-report")
    scan.add_argument("--report", required=True)
    scan.set_defaults(handler=validate_scan_report)

    pytest_report = subparsers.add_parser("validate-pytest-report")
    pytest_report.add_argument("--report", required=True)
    pytest_report.add_argument("--required-container-cases", type=int, default=6)
    pytest_report.set_defaults(handler=validate_pytest_report)

    create_receipt = subparsers.add_parser("create-build-receipt")
    create_receipt.add_argument("--source-repository", required=True)
    create_receipt.add_argument("--source-sha", required=True)
    create_receipt.add_argument("--source-tree", required=True)
    create_receipt.add_argument("--platform", required=True)
    create_receipt.add_argument("--image-id", required=True)
    create_receipt.add_argument("--archive", required=True)
    create_receipt.add_argument("--pytest-report", required=True)
    create_receipt.add_argument("--build-metadata", required=True)
    create_receipt.add_argument("--uv-version-file", required=True)
    create_receipt.add_argument("--output", required=True)
    create_receipt.set_defaults(handler=create_build_receipt)

    receipt = subparsers.add_parser("validate-build-receipt")
    receipt.add_argument("--receipt", required=True)
    receipt.add_argument("--archive", required=True)
    receipt.add_argument("--source-repository", required=True)
    receipt.add_argument("--source-sha", required=True)
    receipt.add_argument("--platform", required=True)
    receipt.set_defaults(handler=validate_build_receipt)

    loaded_image = subparsers.add_parser("validate-loaded-image")
    loaded_image.add_argument("--receipt", required=True)
    loaded_image.add_argument("--image-id", required=True)
    loaded_image.set_defaults(handler=validate_loaded_image)

    push_digest = subparsers.add_parser("extract-push-digest")
    push_digest.add_argument("--push-output", required=True)
    push_digest.set_defaults(handler=extract_push_digest)

    registry_manifest = subparsers.add_parser("validate-registry-manifest")
    registry_manifest.add_argument("--manifest", required=True)
    registry_manifest.add_argument("--receipt", required=True)
    registry_manifest.add_argument("--digest", required=True)
    registry_manifest.set_defaults(handler=validate_registry_manifest)

    predicate = subparsers.add_parser("create-release-predicate")
    predicate.add_argument("--build-receipt", required=True)
    predicate.add_argument("--image-name", required=True)
    predicate.add_argument("--digest", required=True)
    predicate.add_argument("--output", required=True)
    predicate.set_defaults(handler=create_release_predicate)

    attestation = subparsers.add_parser("validate-attestation")
    attestation.add_argument("--verification", required=True)
    attestation.add_argument("--build-receipt", required=True)
    attestation.add_argument("--predicate-type", required=True)
    attestation.add_argument("--source-repository", required=True)
    attestation.add_argument("--source-sha", required=True)
    attestation.add_argument("--image-name", required=True)
    attestation.add_argument("--digest", required=True)
    attestation.set_defaults(handler=validate_attestation)

    workflow = subparsers.add_parser("validate-workflow")
    workflow.add_argument("--workflow", required=True)
    workflow.set_defaults(handler=validate_workflow)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        result = args.handler(args)
    except ReleaseError as error:
        print(f"release control failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
