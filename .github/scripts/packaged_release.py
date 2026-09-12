#!/usr/bin/env python3
"""Strict, stdlib-only evidence controls for the separate R/M publisher.

These validators do not contact Docker, a registry or a provider. Successful gh
verification must precede statement validation; JSON alone is not a signature.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import importlib.util
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "jazzli/google_workspace_mcp"
IMAGE_NAME = "ghcr.io/" + REPOSITORY
WORKFLOW = ".github/workflows/packaged-container-publish.yml"
PREDICATE = "https://github.com/" + REPOSITORY + "/packaged-container-release/v1"
STANDARD = "https://slsa.dev/provenance/v1"
ROLES = ("runtime", "migration")
BASE = {
    "manifestDigest": "sha256:8af597d77f12ec7bf1319354065af3843c09426f4469374f698ee7e675d32f43",
    "configDigest": "sha256:933b5d014a64ec9ff4a6499f3b039659f29d59976b53e9689b09f9c99940f0b0",
    "applicationCommit": "7d7f2a7d714fe0e1e450b8a5267db357d18c4da6",
    "publisherCommit": "e8b8faa42ea91403279393ee0eae8ac5af9424de",
    "runId": "34531455287",
    "runAttempt": "1",
}
FIXED_FILES = {
    "docker/runtime_launcher.py": "sha256:408f73ec5770cda6916ac0a94378017cb7a7e254fae381280c36d6b11c782e58",
    "docker/content_permission_migration.py": "sha256:6809742aa6eb4ff3f8eb25f595a4d08a9bc2bd52436ec2fd429889ee90cf2bcd",
    "docker/Dockerfile.runtime": "sha256:e72d77420290699884f6cf8dc6f4c12422b9eb777177f08a5996310c69812a54",
    "docker/Dockerfile.content-migration": "sha256:21641864b1ec079d1d5a3432fa94560f73dd0e7b0334ca39a3fbd432848ae2ce",
}
SOURCE_FILES = tuple(
    sorted(
        (
            *FIXED_FILES,
            WORKFLOW,
            ".github/scripts/packaged_release.py",
            ".github/scripts/packaged-release.schema.json",
            ".github/scripts/packaged_pipeline.py",
            ".github/scripts/packaged_workflow.py",
            ".github/scripts/container_release.py",
            "tests/container/packaged_docker.py",
            "tests/container/build_packaged_images.py",
            "tests/container/verify_packaged_layers.py",
            "tests/container/test_packaged_runtime.py",
            "tests/container/test_packaged_migration.py",
            "tests/container/test_runtime_image.py",
            "tests/container/rehearse_packaged_pair.mjs",
            "tests/container/packaged_storage_probe.py",
            "pyproject.toml",
            "uv.lock",
        )
    )
)
STAGES = (
    "root-baseline",
    "migration",
    "completed-restart",
    "nonroot-final",
    "final-replacement",
    "root-fallback",
    "fresh-migration",
    "final-return",
)
FAULTS = (
    "serving-after-expiry",
    "wrong-key",
    "expired-fresh",
    "boundary-512",
    "same-device-nested-mount",
    "mixed-ownership-sigkill",
    "pending-replay",
    "fresh-operation-blocked",
    "root-fallback-current-store",
)


class ReleaseError(ValueError):
    """Only value-free classifications may cross the CLI boundary."""


def require(condition, label="invalid-release-evidence"):
    if not condition:
        raise ReleaseError(label)


def hash_bytes(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def hash_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def loads(raw, limit=1024 * 1024):
    require(len(raw) <= limit, "oversized-json")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result

    def check_depth(obj, depth=0):
        require(depth <= 32, "json-depth-exceeded")
        if isinstance(obj, (dict, list)):
            for item in obj.values() if isinstance(obj, dict) else obj:
                check_depth(item, depth + 1)

    try:
        result = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: require(False, "nonfinite-json"),
        )
        check_depth(result)
        return result
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ReleaseError("invalid-json") from None


def load(path):
    with Path(path).open("rb") as stream:
        return loads(stream.read(1024 * 1024 + 1))


def write(path, value):
    Path(path).write_bytes(canonical(value) + b"\n")


def object_schema(properties):
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


DIGEST = {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$", "maxLength": 71}
SHA = {"type": "string", "pattern": r"^[0-9a-f]{40}$", "maxLength": 40}
IDENT = {"type": "string", "pattern": r"^[1-9][0-9]{0,19}$", "maxLength": 20}
COUNT = {"type": "integer", "minimum": 0, "maximum": 100000}
CASE = {"type": "string", "minLength": 1, "maxLength": 512}


def array_schema(items, maximum=100000, minimum=1):
    return {
        "type": "array",
        "items": items,
        "uniqueItems": True,
        "minItems": minimum,
        "maxItems": maximum,
    }


def build_schema():
    test = object_schema(
        {
            "sha256": DIGEST,
            "cases": array_schema(CASE),
            "passed": COUNT,
            "skipped": COUNT,
            "failed": COUNT,
        }
    )
    cleanup = object_schema(
        {
            kind: object_schema(
                {name: COUNT for name in ("owned", "absent", "present", "unknown")}
            )
            for kind in ("containers", "volumes")
        }
    )
    return object_schema(
        {
            "schemaVersion": {"const": 1},
            "repository": {"const": REPOSITORY},
            "runId": IDENT,
            "runAttempt": IDENT,
            "workflow": object_schema({"path": {"const": WORKFLOW}, "commit": SHA}),
            "overlay": object_schema({"commit": SHA, "tree": SHA}),
            "base": object_schema(
                {key: {"const": value} for key, value in BASE.items()}
            ),
            "images": object_schema(
                {
                    role: object_schema(
                        {"configDigest": DIGEST, "diffIds": array_schema(DIGEST, 128)}
                    )
                    for role in ROLES
                }
            ),
            "archiveSha256": DIGEST,
            "sourceFiles": object_schema({name: DIGEST for name in SOURCE_FILES}),
            "tools": object_schema(
                {
                    name: {
                        "type": "string",
                        "pattern": r"^[a-zA-Z0-9.+_ /,:()=-]{1,180}$",
                        "maxLength": 180,
                    }
                    for name in ("docker", "buildkit", "python", "node", "scanner")
                }
            ),
            "evidence": object_schema(
                {
                    "tests": object_schema(
                        {
                            name: test
                            for name in (
                                "nonIntegration",
                                "linuxRuntime",
                                "linuxMigration",
                                "runtimeImage",
                                "migrationImage",
                            )
                        }
                    ),
                    "scans": object_schema(
                        {name: DIGEST for name in ("source", *ROLES)}
                    ),
                    "layers": DIGEST,
                    "rehearsal": object_schema(
                        {
                            "sha256": DIGEST,
                            "stages": array_schema(CASE, 8),
                            "faults": array_schema(CASE, 9),
                            "cleanup": cleanup,
                        }
                    ),
                }
            ),
        }
    )


def schema_validate(value, schema):
    # Implement exactly the JSON Schema vocabulary used in the companion schema.
    if "const" in schema:
        require(type(value) is type(schema["const"]) and value == schema["const"])
    kind = schema.get("type")
    if kind == "object":
        require(type(value) is dict and set(value) == set(schema["required"]))
        for key in value:
            schema_validate(value[key], schema["properties"][key])
    elif kind == "array":
        require(
            type(value) is list
            and schema["minItems"] <= len(value) <= schema["maxItems"]
        )
        require(len({canonical(item) for item in value}) == len(value))
        for item in value:
            schema_validate(item, schema["items"])
    elif kind == "string":
        require(
            type(value) is str
            and schema.get("minLength", 0) <= len(value) <= schema["maxLength"]
        )
        if "pattern" in schema:
            require(re.fullmatch(schema["pattern"], value) is not None)
    elif kind == "integer":
        require(type(value) is int and schema["minimum"] <= value <= schema["maximum"])


def source_cases(filename, class_name=None):
    tree = ast.parse((ROOT / "tests/container" / filename).read_text())
    nodes = (
        tree.body
        if class_name is None
        else next(
            n.body
            for n in tree.body
            if isinstance(n, ast.ClassDef) and n.name == class_name
        )
    )
    names = []
    for node in nodes:
        if not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) or not node.name.startswith("test_"):
            continue
        parameters = [
            d
            for d in node.decorator_list
            if isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and d.func.attr == "parametrize"
        ]
        if parameters:
            # The preserved six-case image contract has one simple selection list.
            require(
                len(parameters) == 1 and len(parameters[0].args) == 2,
                "unsupported-test-parameterization",
            )
            parameter, values = map(ast.literal_eval, parameters[0].args)
            require(
                parameter == "selection" and isinstance(values, list),
                "unsupported-test-parameterization",
            )
            names.extend(f"{node.name}[{parameter}{i}]" for i in range(len(values)))
        else:
            names.append(node.name)
    return sorted(names)


REQUIRED_CASES = {
    "linuxRuntime": source_cases("test_packaged_runtime.py", "RuntimeTests"),
    "linuxMigration": source_cases("test_packaged_migration.py", "EngineTests"),
    "runtimeImage": source_cases("test_runtime_image.py"),
    "migrationImage": source_cases("test_runtime_image.py"),
}


def source_hashes(root=ROOT):
    result = {}
    for name in SOURCE_FILES:
        path = Path(root) / name
        require(path.is_file() and not path.is_symlink(), "unsafe-source-file")
        result[name] = hash_file(path)
    require(
        all(result[name] == value for name, value in FIXED_FILES.items()),
        "qualified-input-changed",
    )
    return result


def validate_invocation(event, ref, source_sha, workflow_sha, event_sha):
    require(
        event == "workflow_dispatch" and ref == "refs/heads/main", "invalid-invocation"
    )
    for sha in (source_sha, workflow_sha, event_sha):
        schema_validate(sha, SHA)
    require(source_sha == workflow_sha == event_sha, "overlay-workflow-mismatch")
    return {"workflowCommit": workflow_sha}


def real_digest(value):
    schema_validate(value, DIGEST)
    require(len(set(value[7:])) > 1, "synthetic-artifact-digest")


def validate_cleanup(cleanup):
    total = 0
    for row in cleanup.values():
        require(
            0 < row["owned"] <= 128
            and row["absent"] == row["owned"]
            and row["present"] == row["unknown"] == 0,
            "cleanup-incomplete",
        )
        total += row["owned"]
    require(total <= 128, "resource-bound-exceeded")


def validate_evidence(evidence):
    for name, row in evidence["tests"].items():
        require(
            row["failed"] == 0
            and row["passed"] > 0
            and row["passed"] + row["skipped"] == len(row["cases"]),
            "test-evidence-incomplete",
        )
        if name in REQUIRED_CASES:
            require(
                row["skipped"] == 0 and sorted(row["cases"]) == REQUIRED_CASES[name],
                "required-cases-missing",
            )
    rehearsal = evidence["rehearsal"]
    require(
        rehearsal["stages"] == list(STAGES) and rehearsal["faults"] == list(FAULTS),
        "rehearsal-incomplete",
    )
    validate_cleanup(rehearsal["cleanup"])


def validate_build_receipt(receipt, archive_sha256, expected):
    schema_validate(receipt, build_schema())
    require(
        set(expected)
        == {
            "repository",
            "runId",
            "runAttempt",
            "workflow",
            "overlay",
            "sourceFiles",
            "baseDiffIds",
        },
        "missing-independent-expectations",
    )
    for name, value in expected.items():
        if name != "baseDiffIds":
            require(receipt[name] == value, "build-binding-mismatch")
    require(
        receipt["workflow"]["commit"] == receipt["overlay"]["commit"],
        "overlay-workflow-mismatch",
    )
    require(receipt["archiveSha256"] == archive_sha256, "archive-mismatch")
    for name, digest in FIXED_FILES.items():
        require(receipt["sourceFiles"][name] == digest, "qualified-input-changed")
    runtime, migration = (receipt["images"][role] for role in ROLES)
    for image in (runtime, migration):
        real_digest(image["configDigest"])
        for digest in image["diffIds"]:
            real_digest(digest)
    require(runtime["configDigest"] != migration["configDigest"], "duplicate-image")
    require(
        len(runtime["diffIds"]) == len(expected["baseDiffIds"]) + 1
        and runtime["diffIds"][:-1] == expected["baseDiffIds"],
        "base-ancestry-mismatch",
    )
    require(
        len(migration["diffIds"]) == len(runtime["diffIds"]) + 1
        and migration["diffIds"][:-1] == runtime["diffIds"],
        "pair-ancestry-mismatch",
    )
    require(
        receipt["tools"]["node"] == "v22.23.2"
        and receipt["tools"]["scanner"] == "0.74.0"
        and receipt["tools"]["python"].startswith("3.11."),
        "unqualified-tool-version",
    )
    validate_evidence(receipt["evidence"])
    return receipt


def pair_schema():
    return object_schema(
        {
            "schemaVersion": {"const": 1},
            "buildReceiptSha256": DIGEST,
            "repository": {"const": REPOSITORY},
            "runId": IDENT,
            "runAttempt": IDENT,
            "workflowCommit": SHA,
            "overlayCommit": SHA,
            "images": object_schema(
                {
                    role: object_schema(
                        {"manifestDigest": DIGEST, "configDigest": DIGEST}
                    )
                    for role in ROLES
                }
            ),
        }
    )


def create_pair_record(receipt, receipt_hash, digests):
    require(set(digests) == set(ROLES), "incomplete-pair")
    result = {
        "schemaVersion": 1,
        "buildReceiptSha256": receipt_hash,
        **{k: receipt[k] for k in ("repository", "runId", "runAttempt")},
        "workflowCommit": receipt["workflow"]["commit"],
        "overlayCommit": receipt["overlay"]["commit"],
        "images": {
            role: {
                "manifestDigest": digests[role],
                "configDigest": receipt["images"][role]["configDigest"],
            }
            for role in ROLES
        },
    }
    validate_pair_record(result, receipt, receipt_hash)
    return result


def validate_pair_record(pair, receipt, receipt_hash):
    schema_validate(pair, pair_schema())
    require(pair["buildReceiptSha256"] == receipt_hash, "receipt-hash-mismatch")
    require(
        all(pair[k] == receipt[k] for k in ("repository", "runId", "runAttempt")),
        "pair-run-mismatch",
    )
    require(
        pair["workflowCommit"]
        == pair["overlayCommit"]
        == receipt["workflow"]["commit"]
        == receipt["overlay"]["commit"],
        "pair-source-mismatch",
    )
    for role in ROLES:
        real_digest(pair["images"][role]["manifestDigest"])
        require(
            pair["images"][role]["configDigest"]
            == receipt["images"][role]["configDigest"],
            "pair-config-mismatch",
        )
    require(
        pair["images"]["runtime"]["manifestDigest"]
        != pair["images"]["migration"]["manifestDigest"],
        "duplicate-manifest",
    )
    return pair


def validate_manifest(raw, config_raw, manifest_digest, image):
    real_digest(manifest_digest)
    require(hash_bytes(raw) == manifest_digest, "manifest-hash-mismatch")
    require(hash_bytes(config_raw) == image["configDigest"], "config-hash-mismatch")
    manifest, config = loads(raw), loads(config_raw)
    try:
        require(
            manifest["schemaVersion"] == 2
            and manifest["mediaType"]
            in {
                "application/vnd.docker.distribution.manifest.v2+json",
                "application/vnd.oci.image.manifest.v1+json",
            },
            "single-platform-manifest-required",
        )
        require(
            manifest["config"]["digest"] == image["configDigest"]
            and manifest["config"]["size"] == len(config_raw),
            "registry-config-mismatch",
        )
        require(
            config["os"] == "linux"
            and config["architecture"] == "amd64"
            and config["rootfs"]["type"] == "layers"
            and config["rootfs"]["diff_ids"] == image["diffIds"],
            "registry-ancestry-mismatch",
        )
        require(
            len(manifest["layers"]) == len(image["diffIds"]),
            "registry-layer-count-mismatch",
        )
        require(
            config["config"]["User"] == "1000:1000"
            and config["config"]["Entrypoint"]
            == [
                "/usr/local/bin/python3.11",
                "-I",
                "-S",
                "/opt/mcp-runtime/runtime_launcher.py",
            ]
            and config["config"]["Cmd"] == ["run"],
            "registry-runtime-config-mismatch",
        )
    except (KeyError, TypeError):
        raise ReleaseError("invalid-registry-document") from None
    return manifest_digest


def validate_attestation(verification, pair, role, *, standard=False):
    require(
        role in ROLES and type(verification) is list and 0 < len(verification) <= 16,
        "invalid-verification-output",
    )
    predicate_type = STANDARD if standard else PREDICATE
    subject = [
        {
            "name": IMAGE_NAME,
            "digest": {"sha256": pair["images"][role]["manifestDigest"][7:]},
        }
    ]
    for item in verification:
        try:
            statement = item["verificationResult"]["statement"]
            if (
                statement["_type"] != "https://in-toto.io/Statement/v1"
                or statement["subject"] != subject
                or statement["predicateType"] != predicate_type
            ):
                continue
            if standard:
                invocation = f"https://github.com/{REPOSITORY}/actions/runs/{pair['runId']}/attempts/{pair['runAttempt']}"
                if (
                    statement["predicate"]["runDetails"]["metadata"]["invocationId"]
                    != invocation
                ):
                    continue
            elif statement["predicate"] != {"role": role, "pair": pair}:
                continue
            return {"role": role, "predicateType": predicate_type, "verified": True}
        except (KeyError, TypeError):
            continue
    raise ReleaseError("attestation-pair-mismatch")


def test_summary(path, kind):
    raw = Path(path).read_bytes()
    require(len(raw) <= 16 * 1024 * 1024, "test-report-oversized")
    if kind.startswith("linux"):
        text = raw.decode("utf-8")
        cases = re.findall(
            r"^(test_[a-zA-Z0-9_]+) \([^\n]+\) \.\.\. ok$", text, re.MULTILINE
        )
        ran = re.findall(r"^Ran ([0-9]+) tests? in [0-9.]+s$", text, re.MULTILINE)
        require(
            ran == [str(len(cases))] and re.search(r"^OK$", text, re.MULTILINE),
            "linux-tests-incomplete",
        )
        cleanup = [loads(line) for line in text.splitlines() if line.startswith("{")]
        require(
            len(cleanup) == 1
            and set(cleanup[0]) == {"unitContainer", "cleanup"}
            and cleanup[0]["cleanup"] == "verified-absent"
            and re.fullmatch(
                r"packaged-unit-[0-9a-f-]{36}", cleanup[0]["unitContainer"]
            ),
            "linux-cleanup-incomplete",
        )
        skipped = failed = 0
    else:
        require(b"<!DOCTYPE" not in raw and b"<!ENTITY" not in raw, "unsafe-xml")
        try:
            tests = list(ET.fromstring(raw).iter("testcase"))
        except ET.ParseError:
            raise ReleaseError("invalid-test-report") from None
        cases = [
            case.get("name")
            if kind in REQUIRED_CASES
            else case.get("classname", "") + "::" + case.get("name", "")
            for case in tests
        ]
        if kind == "nonIntegration":
            # Pytest may embed complete binary fixtures in parameter IDs. Keep
            # every original identity uniquely bound without copying that data
            # into the bounded receipt. The raw JUnit report is also hashed.
            cases = ["node-" + hash_bytes(name.encode("utf-8")) for name in cases]
        skipped = sum(case.find("skipped") is not None for case in tests)
        failed = sum(
            case.find("failure") is not None or case.find("error") is not None
            for case in tests
        )
    result = {
        "sha256": hash_bytes(raw),
        "cases": sorted(cases),
        "passed": len(cases) - skipped - failed,
        "skipped": skipped,
        "failed": failed,
    }
    require(
        cases and len(set(cases)) == len(cases) and not failed, "invalid-test-results"
    )
    if kind in REQUIRED_CASES:
        require(
            not skipped and sorted(cases) == REQUIRED_CASES[kind],
            "required-cases-missing",
        )
    return result


def post_schema():
    evidence = build_schema()["properties"]["evidence"]
    evidence["properties"]["tests"] = object_schema(
        {
            name: evidence["properties"]["tests"]["properties"][name]
            for name in ("runtimeImage", "migrationImage")
        }
    )
    evidence["properties"]["scans"] = object_schema({role: DIGEST for role in ROLES})
    return evidence


def accept_pair(receipt, pair, receipt_hash, post, verifications):
    validate_pair_record(pair, receipt, receipt_hash)
    schema_validate(post, post_schema())
    validate_evidence(post)
    require(
        type(verifications) is dict and set(verifications) == set(ROLES),
        "missing-verification-role",
    )
    hashes = {}
    for role in ROLES:
        require(
            set(verifications[role]) == {"standard", "custom"}, "missing-attestation"
        )
        hashes[role] = {}
        for kind, verification in verifications[role].items():
            validate_attestation(verification, pair, role, standard=kind == "standard")
            hashes[role][kind] = hash_bytes(canonical(verification))
    return {
        "schemaVersion": 1,
        "status": "accepted",
        "liveReady": False,
        "pair": pair,
        "postPullEvidence": post,
        "verificationSha256": hashes,
    }


def validate_workflow(document):
    spec = importlib.util.spec_from_file_location(
        "packaged_workflow", ROOT / ".github/scripts/packaged_workflow.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    require(document == module.workflow(), "workflow-contract-mismatch")
    return {"workflow": "valid"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    workflow = sub.add_parser("validate-workflow", allow_abbrev=False)
    workflow.add_argument("--workflow", required=True)
    invocation = sub.add_parser("validate-invocation", allow_abbrev=False)
    for flag in ("event", "ref", "source-sha", "workflow-sha", "event-sha"):
        invocation.add_argument("--" + flag, required=True)
    for command in (
        "create-build-receipt",
        "validate-build-receipt",
        "create-pair-record",
        "validate-pair-record",
        "validate-attestation",
        "accept-pair",
    ):
        p = sub.add_parser(command, allow_abbrev=False)
        p.add_argument("--receipt", required=True)
        p.add_argument("--expected", required=True)
        p.add_argument("--archive", required=True)
        if command in ("validate-pair-record", "validate-attestation", "accept-pair"):
            p.add_argument("--pair", required=True)
        if command == "create-pair-record":
            p.add_argument("--digests", required=True)
        if command == "validate-attestation":
            p.add_argument("--verification", required=True)
            p.add_argument("--role", choices=ROLES, required=True)
            p.add_argument("--standard", action="store_true")
        if command == "accept-pair":
            p.add_argument("--post", required=True)
            p.add_argument("--verifications", required=True)
        p.add_argument("--output")
    options = parser.parse_args(argv)
    try:
        if options.command == "validate-workflow":
            result = validate_workflow(load(options.workflow))
        elif options.command == "validate-invocation":
            result = validate_invocation(
                options.event,
                options.ref,
                options.source_sha,
                options.workflow_sha,
                options.event_sha,
            )
        else:
            receipt = validate_build_receipt(
                load(options.receipt),
                hash_file(options.archive),
                load(options.expected),
            )
            receipt_hash = hash_file(options.receipt)
            result = receipt
            if hasattr(options, "pair"):
                pair = validate_pair_record(load(options.pair), receipt, receipt_hash)
                result = pair
            if options.command == "create-pair-record":
                result = create_pair_record(
                    receipt, receipt_hash, load(options.digests)
                )
            elif options.command == "validate-attestation":
                result = validate_attestation(
                    load(options.verification),
                    pair,
                    options.role,
                    standard=options.standard,
                )
            elif options.command == "accept-pair":
                result = accept_pair(
                    receipt,
                    pair,
                    receipt_hash,
                    load(options.post),
                    load(options.verifications),
                )
            if options.output:
                write(options.output, result)
        print(json.dumps({"validated": options.command}))
        return 0
    except (ReleaseError, OSError, KeyError, TypeError, UnicodeError):
        print(
            "packaged-release-refused:invalid-or-unavailable-evidence", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
