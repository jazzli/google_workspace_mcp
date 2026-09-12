#!/usr/bin/env python3
"""Fixed paired-release job orchestration. Importing this module has no effects.

Registry mutation is available only to the manual-main Actions publish phase.
No arbitrary repository, base, Docker arguments, commands or provider operations
are accepted. Qualification helpers can also be imported for local-only testing.
"""

import argparse
import contextlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import uuid

import packaged_release as r
import container_release as original

sys.path.insert(0, str(r.ROOT / "tests/container"))
import build_packaged_images as builder
from packaged_docker import select_context
import verify_packaged_layers as layers

REHEARSAL_TIMEOUT = 780  # 30s preflight + 600s work + 120s cleanup + 30s exit margin.

# Only these literal classifications may be emitted, never arbitrary exception
# text, command arguments, environment values or captured command output.
SAFE_FAILURE_CATEGORIES = {
    label: label
    for label in (
        "github-job-required",
        "rerun-not-authorized",
        "external-command-failed",
        "external-command-unavailable",
        "archive-mismatch",
        "archive-config-mismatch",
        "archive-pair-incomplete",
        "unusable-image-archive",
        "loaded-config-mismatch",
        "tag-availability-unknown",
        "tag-exists-or-availability-unknown",
        "push-outcome-unknown",
        "pulled-config-mismatch",
    )
}


def failure_category(error):
    if isinstance(error, r.ReleaseError):
        if len(error.args) == 1 and type(error.args[0]) is str:
            return SAFE_FAILURE_CATEGORIES.get(
                error.args[0], "release-validation-failed"
            )
        return "release-validation-failed"
    if isinstance(error, original.ReleaseError):
        return "source-validation-failed"
    if isinstance(error, subprocess.SubprocessError):
        return "external-command-unavailable"
    if isinstance(error, OSError):
        return "io-failed"
    return "invalid-release-data"


def run(argv, *, timeout=120, env=None, stdout_path=None):
    try:
        with (
            Path(stdout_path).open("wb")
            if stdout_path
            else contextlib.nullcontext(subprocess.PIPE)
        ) as output:
            result = subprocess.run(
                [str(a) for a in argv],
                cwd=r.ROOT,
                capture_output=False,
                stdout=output,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env=env,
            )
        r.require(result.returncode == 0, "external-command-failed")
        return result.stdout or b""
    except (OSError, subprocess.SubprocessError):
        raise r.ReleaseError("external-command-unavailable") from None


def github_guard(phase):
    r.require(
        phase in ("validate", "build-test", "publish", "verify-published"),
        "unknown-phase",
    )
    e = os.environ
    r.require(
        e.get("GITHUB_ACTIONS") == "true"
        and e.get("GITHUB_REPOSITORY") == r.REPOSITORY,
        "github-job-required",
    )
    r.validate_invocation(
        e.get("GITHUB_EVENT_NAME"),
        e.get("GITHUB_REF"),
        e.get("SOURCE_SHA"),
        e.get("GITHUB_WORKFLOW_SHA"),
        e.get("GITHUB_SHA"),
    )
    r.schema_validate(e.get("GITHUB_RUN_ID"), r.IDENT)
    r.require(e.get("GITHUB_RUN_ATTEMPT") == "1", "rerun-not-authorized")


def archive_configs(archive, images):
    wanted = {image["configDigest"][7:]: role for role, image in images.items()}
    found = {}
    try:
        with tarfile.open(archive, "r|*") as tar:
            seen = set()
            for entry in tar:
                r.require(entry.name not in seen, "duplicate-archive-member")
                seen.add(entry.name)
                name = entry.name.removesuffix(".json").removeprefix("blobs/sha256/")
                if name not in wanted:
                    continue
                role = wanted[name]
                r.require(
                    entry.isfile() and entry.size <= 1024 * 1024 and role not in found,
                    "unsafe-config-member",
                )
                body = tar.extractfile(entry).read()
                r.require(
                    r.hash_bytes(body) == images[role]["configDigest"],
                    "archive-config-mismatch",
                )
                r.loads(body)
                found[role] = body
    except (OSError, tarfile.TarError):
        raise r.ReleaseError("unusable-image-archive") from None
    r.require(set(found) == set(r.ROLES), "archive-pair-incomplete")
    return found


def check_archive(archive, expected_hash, images):
    r.require(r.hash_file(archive) == expected_hash, "archive-mismatch")
    return archive_configs(archive, images)


def inspect(image):
    return r.loads(run(builder.DOCKER + ["image", "inspect", image]))[0]


def image_binding(image):
    r.require(
        image["Os"] == "linux"
        and image["Architecture"] == "amd64"
        and image["Config"]["User"] == "1000:1000",
        "unexpected-image-platform",
    )
    return {"configDigest": image["Id"], "diffIds": image["RootFS"]["Layers"]}


def validate_base_image(base):
    r.require(
        base["Id"] == r.BASE["configDigest"]
        and base["Os"] == "linux"
        and base["Architecture"] == "amd64"
        and base["Config"]["User"] == "app",
        "base-config-mismatch",
    )


def verification_argv(image, *, standard, base=False):
    workflow = ".github/workflows/docker-publish.yml" if base else r.WORKFLOW
    sha = r.BASE["publisherCommit"] if base else os.environ["GITHUB_WORKFLOW_SHA"]
    predicate = (
        r.STANDARD
        if standard
        else (
            "https://github.com/" + r.REPOSITORY + "/manual-container-release/v1"
            if base
            else r.PREDICATE
        )
    )
    return [
        "gh",
        "attestation",
        "verify",
        "oci://" + image,
        "--bundle-from-oci",
        "--repo",
        r.REPOSITORY,
        "--signer-workflow",
        r.REPOSITORY + "/" + workflow,
        "--source-ref",
        "refs/heads/main",
        "--source-digest",
        sha,
        "--signer-digest",
        sha,
        "--deny-self-hosted-runners",
        "--predicate-type",
        predicate,
        "--format",
        "json",
    ]


def base_preflight():
    image = r.IMAGE_NAME + "@" + r.BASE["manifestDigest"]
    statements = {}
    for kind in ("standard", "custom"):
        statements[kind] = r.loads(
            run(verification_argv(image, standard=kind == "standard", base=True))
        )
    subject = [
        {"name": r.IMAGE_NAME, "digest": {"sha256": r.BASE["manifestDigest"][7:]}}
    ]
    expected_invocation = f"https://github.com/{r.REPOSITORY}/actions/runs/{r.BASE['runId']}/attempts/{r.BASE['runAttempt']}"
    standard_ok = custom_ok = False
    for item in statements["standard"]:
        statement = item.get("verificationResult", {}).get("statement", {})
        standard_ok |= (
            statement.get("subject") == subject
            and statement.get("predicateType") == r.STANDARD
            and statement.get("predicate", {})
            .get("runDetails", {})
            .get("metadata", {})
            .get("invocationId")
            == expected_invocation
        )
    for item in statements["custom"]:
        statement = item.get("verificationResult", {}).get("statement", {})
        predicate = statement.get("predicate", {})
        if statement.get("subject") != subject:
            continue
        try:
            original._validate_build_receipt(predicate)
            custom_ok |= (
                predicate.get("source_repository") == r.REPOSITORY
                and predicate.get("source_sha") == r.BASE["applicationCommit"]
                and predicate.get("registry_digest") == r.BASE["manifestDigest"]
                and predicate.get("tested_image_id") == r.BASE["configDigest"]
                and predicate.get("image_name") == r.IMAGE_NAME
            )
        except original.ReleaseError:
            pass
    r.require(standard_ok and custom_ok, "base-provenance-mismatch")
    raw = run(builder.DOCKER + ["buildx", "imagetools", "inspect", image, "--raw"])
    r.require(
        r.hash_bytes(raw) == r.BASE["manifestDigest"]
        and r.loads(raw).get("config", {}).get("digest") == r.BASE["configDigest"],
        "base-manifest-mismatch",
    )
    run(builder.DOCKER + ["pull", "--platform", "linux/amd64", image], timeout=240)
    base = inspect(image)
    validate_base_image(base)
    return base


def expected_bindings(base):
    sha = os.environ["SOURCE_SHA"]
    tree = run(["git", "rev-parse", "HEAD^{tree}"]).decode().strip()
    r.require(
        run(["git", "rev-parse", "HEAD"]).decode().strip() == sha, "checkout-mismatch"
    )
    return {
        "repository": r.REPOSITORY,
        "runId": os.environ["GITHUB_RUN_ID"],
        "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "workflow": {"path": r.WORKFLOW, "commit": sha},
        "overlay": {"commit": sha, "tree": tree},
        "sourceFiles": r.source_hashes(),
        "baseDiffIds": base["RootFS"]["Layers"],
    }


def scan(kind, target, destination):
    argv = [
        "trivy",
        kind,
        "--scanners",
        "secret",
        "--skip-db-update",
        "--offline-scan",
        "--quiet",
        "--format",
        "json",
        "--output",
        destination,
    ]
    if kind == "image":
        argv += ["--input", target]
    else:
        argv += [
            "--skip-dirs",
            str(r.ROOT / ".venv"),
            "--skip-dirs",
            str(r.ROOT / ".git"),
            target,
        ]
    try:
        run(argv, timeout=240)
        original.validate_scan_report(SimpleNamespace(report=destination))
        return r.hash_file(destination)
    except Exception:
        # Findings must never be emitted or retained in a public artifact.
        Path(destination).unlink(missing_ok=True)
        raise r.ReleaseError("secret-scan-failed") from None


def export_rootfs(image, archive, base_source):
    name = "packaged-inventory-" + str(uuid.uuid4())
    try:
        run(
            builder.DOCKER
            + ["create", "--name", name, "--network", "none", "--pull", "never", image]
        )
        run(builder.DOCKER + ["export", "--output", archive, name], timeout=180)
        original.validate_image_inventory(SimpleNamespace(archive=archive))
        original.validate_image_source(
            SimpleNamespace(archive=archive, source_repository=base_source)
        )
    finally:
        # Registered before uncertain create; query absence independently.
        try:
            run(builder.DOCKER + ["rm", "--force", name])
        except r.ReleaseError:
            pass
        absent = run(
            builder.DOCKER
            + [
                "container",
                "ls",
                "--all",
                "--filter",
                "name=^/" + name + "$",
                "--format",
                "{{.Names}}",
            ]
        )
        r.require(not absent.strip(), "inventory-cleanup-incomplete")


def rehearsal_summary(path, images):
    d = r.load(path)
    r.require(
        not d.get("failed") and d["network"] == "none" and d["googleAccess"] is False,
        "rehearsal-failed",
    )
    r.require(
        d["runtimeLocalImageId"] == images["runtime"]["configDigest"]
        and d["migrationLocalImageId"] == images["migration"]["configDigest"],
        "rehearsal-image-mismatch",
    )
    r.require(
        "sha256:" + d["launcherSha256"] == r.FIXED_FILES["docker/runtime_launcher.py"]
        and "sha256:" + d["helperSha256"]
        == r.FIXED_FILES["docker/content_permission_migration.py"],
        "rehearsal-code-mismatch",
    )
    r.require(
        [s["label"] for s in d["stages"]] == list(r.STAGES), "rehearsal-stages-missing"
    )
    previous = None
    for index, stage in enumerate(d["stages"]):
        uid = 0 if stage["label"] in ("root-baseline", "root-fallback") else 1000
        storage, process = stage["storage"], stage["process"]
        r.require(
            stage["http"] == {"health": 200, "mcp": 401} and stage["signalExit"] == 0,
            "rehearsal-process-failed",
        )
        r.require(
            storage["readCount"] == index
            and storage["recordCount"] == index + 1
            and storage["encrypted"] is True
            and storage["metadataQualified"] is True
            and storage["freshProviderRead"] is True
            and storage["expectedIdentity"] == uid,
            "rehearsal-storage-failed",
        )
        r.require(
            process["Uid"].split() == [str(uid)] * 4
            and process["Gid"].split() == [str(uid)] * 4
            and process["NoNewPrivs"] == "1"
            and process["Umask"] == "0077"
            and process["home"] == "/home/app",
            "rehearsal-identity-failed",
        )
        if uid:
            r.require(
                process["Groups"].split() == ["1000"]
                and all(
                    int(process[k], 16) == 0
                    for k in ("CapInh", "CapPrm", "CapEff", "CapAmb")
                ),
                "rehearsal-capabilities-failed",
            )
        if previous:
            r.require(storage["beforeSha256"] == previous, "rehearsal-record-drift")
        previous = storage["afterSha256"]
    faults = d["faults"]
    interrupted = faults["interruptedFallback"]
    r.require(
        d["servingSurvivesMutationExpiry"] is True
        and d["wrongKeyRejected"] is True
        and faults["expiredFresh"] == "refused-without-store-or-journal-effect"
        and faults["boundaryEntries"] == 512
        and faults["sameDeviceNestedMount"] == "refused"
        and interrupted["signal"] == "SIGKILL"
        and all(
            interrupted[k] is True
            for k in (
                "mixedOwnershipObserved",
                "originalBytesPreserved",
                "pendingReplayRejected",
                "freshOperationBlocked",
                "pendingJournalUnchanged",
            )
        )
        and interrupted["http"] == {"health": 200, "mcp": 401},
        "rehearsal-faults-incomplete",
    )
    cleanup = {
        kind: {"owned": d["cleanup"][kind], **d["cleanup"][field]}
        for kind, field in [
            ("containers", "containerAbsence"),
            ("volumes", "volumeAbsence"),
        ]
    }
    r.require(
        d["cleanup"]["verifiedAbsent"] is True and d["elapsedMs"] <= 600000,
        "rehearsal-boundary-failed",
    )
    for kind in cleanup:
        ledger = d["cleanup"]["ledger"][kind]
        r.require(
            len(ledger) == len(set(ledger)) == cleanup[kind]["owned"],
            "cleanup-ledger-mismatch",
        )
    r.validate_cleanup(cleanup)
    return {
        "sha256": r.hash_file(path),
        "stages": list(r.STAGES),
        "faults": list(r.FAULTS),
        "cleanup": cleanup,
    }


def qualify(images, directory, base_source, context, *, full):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    scans, tests = {}, {}
    if full:
        scans["source"] = scan("fs", r.ROOT, directory / "source-scan.json")
        run(
            [
                r.ROOT / ".venv/bin/python",
                "-m",
                "pytest",
                "-q",
                "-m",
                "not integration",
                "--junitxml",
                directory / "nonIntegration.xml",
            ],
            timeout=600,
        )
        tests["nonIntegration"] = r.test_summary(
            directory / "nonIntegration.xml", "nonIntegration"
        )
        for role, kind in [
            ("runtime", "linuxRuntime"),
            ("migration", "linuxMigration"),
        ]:
            # The driver sends unittest output to stderr. Capture both channels,
            # retain only synthetic test diagnostics, and require real exit success.
            completed = subprocess.run(
                [
                    sys.executable,
                    str(r.ROOT / "tests/container/test_packaged_runtime.py"),
                    "--docker-context",
                    context,
                    "--image-id",
                    images[role]["configDigest"],
                    "--test-file",
                    role,
                ],
                cwd=r.ROOT,
                capture_output=True,
                timeout=240,
            )
            r.require(completed.returncode == 0, "linux-suite-failed")
            (directory / (kind + ".txt")).write_bytes(
                completed.stdout + completed.stderr
            )
            tests[kind] = r.test_summary(directory / (kind + ".txt"), kind)
    for role in r.ROLES:
        image = images[role]["configDigest"]
        archive = directory / (role + ".tar")
        run(builder.DOCKER + ["image", "save", "--output", archive, image], timeout=180)
        scans[role] = scan("image", archive, directory / (role + "-scan.json"))
        export_rootfs(image, directory / (role + "-rootfs.tar"), base_source)
        # Baseline image tests are preserved verbatim; their own finally blocks
        # remove started containers. Ensure the host container set is unchanged.
        before = set(
            run(builder.DOCKER + ["container", "ls", "--all", "--quiet"]).split()
        )
        env = {
            k: v
            for k, v in os.environ.items()
            if k
            not in (
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                "ACTIONS_ID_TOKEN_REQUEST_URL",
            )
        }
        env.update(
            WORKSPACE_MCP_TEST_IMAGE=image, WORKSPACE_MCP_TEST_DOCKER_CONTEXT=context
        )
        try:
            run(
                [
                    r.ROOT / ".venv/bin/python",
                    "-m",
                    "pytest",
                    "-q",
                    "tests/container/test_runtime_image.py",
                    "--junitxml",
                    directory / (role + "Image.xml"),
                ],
                timeout=600,
                env=env,
            )
        finally:
            after = set(
                run(builder.DOCKER + ["container", "ls", "--all", "--quiet"]).split()
            )
            r.require(after == before, "image-test-cleanup-incomplete")
        tests[role + "Image"] = r.test_summary(
            directory / (role + "Image.xml"), role + "Image"
        )
        archive.unlink()
        (directory / (role + "-rootfs.tar")).unlink()
    verified_layers = layers.verify(*(images[role]["configDigest"] for role in r.ROLES))
    r.write(directory / "layers.json", verified_layers)
    run(
        [
            "node",
            r.ROOT / "tests/container/rehearse_packaged_pair.mjs",
            "--docker-context",
            context,
            *(images[role]["configDigest"] for role in r.ROLES),
        ],
        timeout=REHEARSAL_TIMEOUT,
        stdout_path=directory / "rehearsal.json",
    )
    evidence = {
        "tests": tests,
        "scans": scans,
        "layers": r.hash_file(directory / "layers.json"),
        "rehearsal": rehearsal_summary(directory / "rehearsal.json", images),
    }
    r.schema_validate(
        evidence,
        r.build_schema()["properties"]["evidence"] if full else r.post_schema(),
    )
    r.validate_evidence(evidence)
    return evidence


def buildkit_version(output):
    versions = re.findall(
        r"^BuildKit version:\s*(v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][\w.-]+)?)\s*$",
        output,
        re.MULTILINE,
    )
    statuses = re.findall(r"^Status:\s*(\S+)\s*$", output, re.MULTILINE)
    r.require(
        len(versions) == 1 and statuses == ["running"], "buildkit-version-unknown"
    )
    return versions[0]


def tools_record():
    return {
        "docker": run(builder.DOCKER + ["version", "--format", "{{.Server.Version}}"])
        .decode()
        .strip(),
        "buildkit": buildkit_version(
            run(builder.DOCKER + ["buildx", "inspect", builder.DOCKER[-1]]).decode()
        ),
        "python": ".".join(map(str, sys.version_info[:3])),
        "node": run(["node", "--version"]).decode().strip(),
        "scanner": r.loads(run(["trivy", "version", "--format", "json"]))["Version"],
    }


def outputs(values):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as file:
        for name, value in values.items():
            r.require(
                re.fullmatch(r"[a-z_]+", name)
                and re.fullmatch(r"[a-zA-Z0-9:/_.-]+", str(value)),
                "unsafe-job-output",
            )
            file.write(f"{name}={value}\n")


def require_unused_tag(tag):
    try:
        result = subprocess.run(
            builder.DOCKER + ["manifest", "inspect", tag],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise r.ReleaseError("tag-availability-unknown") from None
    # A failed request is not evidence of absence. Docker can pass through the
    # registry's exact "manifest unknown" classification instead of its own
    # "no such manifest" message. Reject mixed output, signals and other errors.
    r.require(
        result.returncode == 1
        and result.stdout == ""
        and result.stderr.strip() in {"manifest unknown", "no such manifest: " + tag},
        "tag-exists-or-availability-unknown",
    )


def publish(work, receipt, configs):
    publication = Path(os.environ["RUNNER_TEMP"]) / "packaged-published"
    publication.mkdir(exist_ok=True)
    known = {}
    try:
        run(
            builder.DOCKER + ["image", "load", "--input", work / "pair.tar"],
            timeout=180,
        )
        for role in r.ROLES:
            image = receipt["images"][role]
            r.require(
                image_binding(inspect(image["configDigest"])) == image,
                "loaded-config-mismatch",
            )
        tags = {
            role: f"{r.IMAGE_NAME}:packaged-{letter}-run-{receipt['runId']}-{receipt['runAttempt']}-sha-{receipt['overlay']['commit']}"
            for role, letter in zip(r.ROLES, ("r", "m"))
        }
        for tag in tags.values():
            require_unused_tag(tag)
        for role in r.ROLES:
            run(
                builder.DOCKER
                + ["image", "tag", receipt["images"][role]["configDigest"], tags[role]]
            )
            raw_output = run(
                builder.DOCKER + ["image", "push", tags[role]], timeout=240
            )
            found = set(
                re.findall(rb"digest: (sha256:[0-9a-f]{64}) size: [0-9]+", raw_output)
            )
            r.require(len(found) == 1, "push-outcome-unknown")
            digest = found.pop().decode()
            known[role] = digest
            raw = run(
                builder.DOCKER
                + [
                    "buildx",
                    "imagetools",
                    "inspect",
                    r.IMAGE_NAME + "@" + digest,
                    "--raw",
                ]
            )
            r.validate_manifest(raw, configs[role], digest, receipt["images"][role])
            (publication / (role + "-manifest.json")).write_bytes(raw)
        pair = r.create_pair_record(
            receipt, r.hash_file(work / "build-receipt.json"), known
        )
        r.write(publication / "pair.json", pair)
        for role in r.ROLES:
            r.write(
                publication / (role + "-predicate.json"), {"role": role, "pair": pair}
            )
        outputs({role + "_digest": value for role, value in known.items()})
    finally:
        # Even successful pushes are incomplete until all attestations and the
        # separate verifier finish. This record never grants acceptance.
        r.write(
            publication / "publication-state.json",
            {
                "status": "incomplete-not-accepted",
                "runId": receipt["runId"],
                "runAttempt": receipt["runAttempt"],
                "knownDigests": known,
            },
        )


def verify_published(work, receipt, configs):
    publication = Path(os.environ["RUNNER_TEMP"]) / "packaged-published"
    pair = r.validate_pair_record(
        r.load(publication / "pair.json"),
        receipt,
        r.hash_file(work / "build-receipt.json"),
    )
    verifications = {}
    for role in r.ROLES:
        digest = pair["images"][role]["manifestDigest"]
        r.require(
            digest == os.environ[role.upper() + "_DIGEST"], "job-output-pair-mismatch"
        )
        image = r.IMAGE_NAME + "@" + digest
        verifications[role] = {}
        for kind in ("standard", "custom"):
            raw = run(
                verification_argv(image, standard=kind == "standard"), timeout=180
            )
            verified = r.loads(raw)
            r.validate_attestation(verified, pair, role, standard=kind == "standard")
            verifications[role][kind] = verified
            (publication / (role + "-" + kind + "-verification.json")).write_bytes(raw)
        manifest = run(
            builder.DOCKER + ["buildx", "imagetools", "inspect", image, "--raw"]
        )
        r.validate_manifest(manifest, configs[role], digest, receipt["images"][role])
    # Neither candidate is executed until both subjects and pair bindings pass.
    for role in r.ROLES:
        image = r.IMAGE_NAME + "@" + pair["images"][role]["manifestDigest"]
        run(builder.DOCKER + ["pull", "--platform", "linux/amd64", image], timeout=240)
        r.require(
            image_binding(inspect(image)) == receipt["images"][role],
            "pulled-config-mismatch",
        )
    run(builder.DOCKER + ["logout", "ghcr.io"])
    post = qualify(
        receipt["images"],
        work / "post-pull",
        r.ROOT.parent / "base-source",
        "default",
        full=False,
    )
    accepted = r.accept_pair(
        receipt, pair, r.hash_file(work / "build-receipt.json"), post, verifications
    )
    r.write(publication / "accepted-pair.json", accepted)
    print("Pair accepted; liveReady=false")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument(
        "phase", choices=["validate", "build-test", "publish", "verify-published"]
    )
    args = parser.parse_args(argv)
    try:
        github_guard(args.phase)
        builder.DOCKER[:] = select_context("default")
        original.validate_source(
            SimpleNamespace(
                repository=r.ROOT,
                source_sha=os.environ["SOURCE_SHA"],
                reviewed_ref="refs/remotes/origin/main",
                expected_repository=r.REPOSITORY,
            )
        )
        original.validate_context(
            SimpleNamespace(repository=r.ROOT, source_sha=os.environ["SOURCE_SHA"])
        )
        base = base_preflight()
        expected = expected_bindings(base)
        work = Path(os.environ["RUNNER_TEMP"]) / "packaged-pair"
        work.mkdir(parents=True, exist_ok=True)
        if args.phase == "validate":
            return 0
        if args.phase == "build-test":
            runtime = builder.build("runtime")["localImageId"]
            migration = builder.build("migration", runtime)["localImageId"]
            images = {
                role: image_binding(inspect(value))
                for role, value in zip(r.ROLES, (runtime, migration))
            }
            evidence = qualify(
                images,
                work / "evidence",
                r.ROOT.parent / "base-source",
                "default",
                full=True,
            )
            run(
                builder.DOCKER
                + ["image", "save", "--output", work / "pair.tar", runtime, migration],
                timeout=180,
            )
            receipt = {
                "schemaVersion": 1,
                **{k: v for k, v in expected.items() if k != "baseDiffIds"},
                "base": r.BASE,
                "images": images,
                "archiveSha256": r.hash_file(work / "pair.tar"),
                "tools": tools_record(),
                "evidence": evidence,
            }
            r.validate_build_receipt(receipt, receipt["archiveSha256"], expected)
            check_archive(work / "pair.tar", receipt["archiveSha256"], images)
            r.write(work / "build-receipt.json", receipt)
        else:
            receipt = r.validate_build_receipt(
                r.load(work / "build-receipt.json"),
                r.hash_file(work / "pair.tar"),
                expected,
            )
            configs = check_archive(
                work / "pair.tar", receipt["archiveSha256"], receipt["images"]
            )
            if args.phase == "publish":
                publish(work, receipt, configs)
            else:
                verify_published(work, receipt, configs)
        return 0
    except (
        r.ReleaseError,
        original.ReleaseError,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(
            "packaged-pipeline-failed:incomplete-not-accepted "
            f"phase={args.phase} category={failure_category(error)}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
