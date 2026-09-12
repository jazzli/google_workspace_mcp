"""Verify exact local image ancestry and every member of both added layers."""

import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
import threading
from build_packaged_images import BASE_ID, DOCKER, ROOT, inspect
from packaged_docker import select_context


def verify(runtime, migration):
    assert all(
        re.fullmatch(r"sha256:[0-9a-f]{64}", image) for image in (runtime, migration)
    )
    images = [inspect(image) for image in (BASE_ID, runtime, migration)]
    expected = {}
    for index, source in (
        (1, "runtime_launcher.py"),
        (2, "content_permission_migration.py"),
    ):
        layers, parent = (
            images[index]["RootFS"]["Layers"],
            images[index - 1]["RootFS"]["Layers"],
        )
        assert layers[:-1] == parent and len(layers) == len(parent) + 1
        assert images[index]["Config"]["User"] == "1000:1000"
        expected[layers[-1]] = source
    # Stream a local Docker save. Only one bounded layer is held at a time;
    # nothing is extracted onto the host and no registry is contacted.
    process = subprocess.Popen(
        DOCKER + ["image", "save", runtime, migration],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    timer = threading.Timer(120, process.kill)
    timer.daemon = True
    timer.start()
    found = {}
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                candidates = {
                    "blobs/sha256/" + digest.split(":")[1] for digest in expected
                }
                if not member.isfile() or not (
                    member.name.endswith("/layer.tar") or member.name in candidates
                ):
                    continue
                assert member.size <= 256 * 1024 * 1024, "unexpected-large-layer"
                data = archive.extractfile(member).read()
                digest = "sha256:" + hashlib.sha256(data).hexdigest()
                if digest not in expected:
                    continue
                source = expected[digest]
                allowed = {"opt", "opt/mcp-runtime", "opt/mcp-runtime/" + source}
                with tarfile.open(fileobj=io.BytesIO(data)) as layer:
                    names = []
                    for entry in layer:
                        name = entry.name.rstrip("/")
                        assert (
                            name in allowed and not entry.issym() and not entry.islnk()
                        ), "unexpected-layer-member"
                        assert entry.uid == entry.gid == 0 and not entry.mode & 0o022, (
                            "unprotected-layer-member"
                        )
                        if entry.isdir():
                            assert entry.mode & 0o555 == 0o555, (
                                "untraversable-layer-directory"
                            )
                        else:
                            assert entry.isfile() and name.endswith("/" + source), (
                                "unexpected-layer-type"
                            )
                            assert (
                                hashlib.sha256(layer.extractfile(entry).read()).digest()
                                == hashlib.sha256(
                                    (ROOT / "docker" / source).read_bytes()
                                ).digest()
                            )
                        names.append(name)
                    assert "opt/mcp-runtime/" + source in names
                    assert len(names) == len(set(names)), "duplicate-layer-member"
                    found[source] = {
                        "diffId": digest,
                        "members": names,
                        "matchesSource": True,
                    }
        assert process.wait(timeout=30) == 0
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    assert set(found) == {"runtime_launcher.py", "content_permission_migration.py"}, (
        "added-layers-not-verified"
    )
    return {
        "localOnly": True,
        "acceptedBaseLayersUnchanged": True,
        "runtimeLayersPreservedInMigration": True,
        "addedLayers": found,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--migration", required=True)
    parser.add_argument(
        "--docker-context",
        choices=["default", "desktop-linux"],
        default="desktop-linux",
    )
    args = parser.parse_args()
    DOCKER[:] = select_context(args.docker_context)
    print(json.dumps(verify(args.runtime, args.migration), indent=2))
