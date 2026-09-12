"""Synthetic-only probe injected into the cached image by the local rehearsal.

Uses the unmodified application's runtime provider factory and client methods.
This is a separate process, NOT a running PID 1 OAuth request or Google check.
Never run against a live container, real environment, or existing host volume.
"""

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
import socket
import stat
import sys
import traceback
from importlib.metadata import version

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
ROOT = Path("/data/oauth-proxy")
CALLBACK = "http://127.0.0.1:8000/oauth2callback"


def guard():
    assert Path("/.dockerenv").is_file(), "synthetic-container-required"
    assert (
        os.getuid()
        == os.getgid()
        == int(os.environ["CONTENT_PACKAGED_EXPECTED_UID"])
        in (0, 1000)
    ), "synthetic-app-identity-required"
    assert os.environ.get("CONTENT_STORAGE_SYNTHETIC_REHEARSAL") == "1"
    for name, expected in {
        "GOOGLE_OAUTH_CLIENT_ID": "123456789-rehearsal.apps.googleusercontent.com",
        "GOOGLE_OAUTH_CLIENT_SECRET": "synthetic-rehearsal-client-secret",
        "FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY": "synthetic-rehearsal-signing-key-0123456789abcdef",
        "WORKSPACE_MCP_OAUTH_PROXY_DISK_DIRECTORY": str(ROOT),
        "WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND": "disk",
        "WORKSPACE_EXTERNAL_URL": "http://127.0.0.1:8000",
    }.items():
        assert os.environ.get(name) == expected, "synthetic-configuration-required"
    assert version("fastmcp") == "3.2.4", "unqualified-fastmcp-version"
    assert version("py-key-value-aio") == "0.4.4", "unqualified-storage-version"
    os.umask(0o077)  # docker exec does not inherit PID 1's umask.
    logging.disable(logging.CRITICAL)

    def deny(*args, **kwargs):
        raise AssertionError("synthetic-storage-probe-must-not-connect")

    # Defense in depth to --network none; do not mock any storage code.
    socket.socket.connect = deny
    socket.socket.connect_ex = deny
    socket.create_connection = deny


def provider():
    from core import server
    from key_value.aio.stores.filetree import FileTreeStore
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    server.set_transport_mode("streamable-http")
    server.configure_server_for_http()
    result = server.get_auth_provider()
    assert result is server.server.auth, "runtime-provider-mismatch"
    assert isinstance(result._client_storage, FernetEncryptionWrapper)
    assert isinstance(result._client_storage.key_value, FileTreeStore)
    assert Path(result._client_storage.key_value._data_directory) == ROOT
    return result


def client_id(stage):
    return "synthetic-migration-" + stage


async def check_clients(auth, stages):
    for stage in stages:
        record = await auth.get_client(client_id(stage))
        assert record is not None, "synthetic-client-missing"
        assert record.client_id == client_id(stage)
        assert record.client_name == "synthetic-only-payload-" + stage
        assert [str(uri) for uri in record.redirect_uris] == [CALLBACK]
        assert record.scope == "openid"
        assert record.token_endpoint_auth_method == "none"
        assert record.client_secret is None


def snapshot(expected_count):
    """Only controlled synthetic records; emit hashes and counts, never bytes."""
    digest = hashlib.sha256()
    paths = sorted(ROOT.rglob("synthetic-migration-*.json"))
    assert len(paths) == expected_count, "synthetic-record-count-mismatch"
    for path in [ROOT, *ROOT.rglob("*")]:
        metadata = path.lstat()
        assert metadata.st_uid == metadata.st_gid and metadata.st_uid in (
            (0, 1000) if os.getuid() == 0 else (1000,)
        ), "nonprivate-owner"
        expected_mode = 0o700 if stat.S_ISDIR(metadata.st_mode) else 0o600
        assert stat.S_IMODE(metadata.st_mode) in (
            (expected_mode, 0o755 if stat.S_ISDIR(metadata.st_mode) else 0o644)
            if os.getuid() == 0
            else (expected_mode,)
        ), "nonprivate-mode"
        assert stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
    for path in paths:
        data = path.read_bytes()
        assert b"__encrypted_data__" in data, "unencrypted-record"
        assert b"synthetic-only-payload-" not in data, "plaintext-payload"
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + data)
    return digest.hexdigest()


async def run(mode):
    guard()
    if mode == "wrong-key":
        from key_value.aio.errors import DecryptionError

        before = snapshot(len(STAGES))
        os.environ["FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY"] = (
            "synthetic-intentionally-wrong-signing-key-0123456789abcdef"
        )
        auth = provider()
        try:
            await auth.get_client(client_id(STAGES[0]))
        except DecryptionError:
            assert snapshot(len(STAGES)) == before, "negative-control-mutated-records"
            return {"wrongKeyRejected": True}
        raise AssertionError("wrong-key-was-not-rejected")
    auth = provider()
    if mode == "legacy-denied":
        record = await auth.get_client(client_id(STAGES[0]))
        assert record is not None, "legacy-fixture-missing"
        try:
            await auth.register_client(record)
        except PermissionError:
            return {"legacyWriteRejected": True}
        raise AssertionError("legacy-write-was-not-rejected")

    from mcp.shared.auth import OAuthClientInformationFull
    from pydantic import AnyUrl

    index = STAGES.index(mode)
    before = snapshot(index)
    await check_clients(auth, STAGES[:index])
    await auth.register_client(
        OAuthClientInformationFull(
            client_id=client_id(mode),
            client_name="synthetic-only-payload-" + mode,
            redirect_uris=[AnyUrl(CALLBACK)],
            scope="openid",
            token_endpoint_auth_method="none",
        )
    )
    await check_clients(auth, STAGES[: index + 1])
    after = snapshot(index + 1)
    # Reconstruct the real factory, rather than trusting one instance's memory.
    await check_clients(provider(), STAGES[: index + 1])
    assert snapshot(index + 1) == after, "lookup-rewrote-records"
    return {
        "readCount": index,
        "recordCount": index + 1,
        "beforeSha256": before,
        "afterSha256": after,
        "encrypted": True,
        "privateMetadata": os.getuid() == 1000,
        "expectedIdentity": os.getuid(),
        "metadataQualified": True,
        "freshProviderRead": True,
    }


if __name__ == "__main__":
    try:
        assert len(sys.argv) == 2 and sys.argv[1] in (
            *STAGES,
            "wrong-key",
            "legacy-denied",
        )
        print(json.dumps(asyncio.run(run(sys.argv[1]))))
    except Exception as error:
        # No exception payloads, record values, application logs or traceback.
        line = traceback.extract_tb(error.__traceback__)[-1].lineno
        print(
            f"synthetic-storage-probe-failed:{type(error).__name__}:line-{line}",
            file=sys.stderr,
        )
        sys.exit(1)
