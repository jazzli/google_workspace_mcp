"""Local-only minimal tar contexts; no repository tree is sent to Docker."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import uuid
from packaged_docker import select_context

ROOT = Path(__file__).resolve().parents[2]
BASE = "ghcr.io/jazzli/google_workspace_mcp@sha256:8af597d77f12ec7bf1319354065af3843c09426f4469374f698ee7e675d32f43"
BASE_ID = "sha256:933b5d014a64ec9ff4a6499f3b039659f29d59976b53e9689b09f9c99940f0b0"
DOCKER = ["docker", "--context", "desktop-linux"]


def context(stage):
    names = {
        "runtime": ("Dockerfile.runtime", "runtime_launcher.py"),
        "migration": (
            "Dockerfile.content-migration",
            "content_permission_migration.py",
        ),
    }[stage]
    output = io.BytesIO()
    hashes = {}
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name in names:
            source = ROOT / "docker" / name
            if not source.is_file() or source.is_symlink():
                raise ValueError("unsafe-build-source")
            content = source.read_bytes()
            if re.search(
                rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                content,
            ):
                raise ValueError("private-identifier-in-build-source")
            hashes[name] = hashlib.sha256(content).hexdigest()
            entry = tarfile.TarInfo(
                "Dockerfile" if name.startswith("Dockerfile") else name
            )
            entry.mode, entry.size = 0o644, len(content)
            archive.addfile(entry, io.BytesIO(content))
    return output.getvalue(), hashes


def docker(*args, data=None):
    result = subprocess.run(
        DOCKER + list(args), input=data, capture_output=True, timeout=180
    )
    if result.returncode:
        # Build input is strictly public source, but don't dump arbitrary daemon responses.
        raise RuntimeError("local-build-failed:" + result.stderr.decode()[-2500:])
    return result.stdout.decode()


def inspect(image):
    return json.loads(docker("image", "inspect", image))[0]


def build(stage, runtime=None):
    base = inspect(BASE)
    if base["Id"] != BASE_ID:
        raise ValueError("wrong-cached-base")
    tar, hashes = context(stage)
    args = [
        "build",
        "--pull=false",
        "--network=none",
        "--platform=linux/amd64",
        "--provenance=false",
        "--load",
        "--quiet",
    ]
    if stage == "migration":
        if not runtime or not re.fullmatch(r"sha256:[0-9a-f]{64}", runtime):
            raise ValueError("exact-local-runtime-reference-required")
        parent = inspect(runtime)
        # Docker's local builder resolves FROM by name. Bind a unique local
        # alias to the requested config ID; assert identity before/after and
        # full layer ancestry. This alias is never a release identity.
        alias = "content-packaged-parent-local:" + str(uuid.uuid4())
        args += ["--build-arg", "RUNTIME_IMAGE=" + alias]
    else:
        parent = base
    tag = "content-packaged-" + stage + "-local:" + str(uuid.uuid4())
    print(json.dumps({"buildingLocalTag": tag}), flush=True)
    try:
        if stage == "migration":
            docker("image", "tag", runtime, alias)
            if inspect(alias)["Id"] != runtime:
                raise ValueError("local-parent-alias-drift")
        docker(*args, "--tag", tag, "-", data=tar)
        if stage == "migration" and inspect(alias)["Id"] != runtime:
            raise ValueError("local-parent-alias-drift")
    finally:
        if stage == "migration":
            # Only our exact unique alias, not its underlying image.
            docker("image", "rm", alias)
    child = inspect(tag)
    layers, previous = child["RootFS"]["Layers"], parent["RootFS"]["Layers"]
    if layers[:-1] != previous or len(layers) != len(previous) + 1:
        raise ValueError("unexpected-layer-ancestry")
    if child["Config"]["User"] != "1000:1000" or child["Architecture"] != "amd64":
        raise ValueError("unexpected-image-config")
    return {
        "stage": stage,
        "localTag": tag,
        "localImageId": child["Id"],
        "localRepoDigests": child.get("RepoDigests", []),
        "descriptor": child.get("Descriptor"),
        "sourceSha256": hashes,
        "parentLocalImageId": parent["Id"],
        "published": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=["runtime", "migration"])
    parser.add_argument("--runtime")
    parser.add_argument(
        "--docker-context",
        choices=["default", "desktop-linux"],
        default="desktop-linux",
    )
    options = parser.parse_args()
    DOCKER[:] = select_context(options.docker_context)
    print(json.dumps(build(options.stage, options.runtime), indent=2))
