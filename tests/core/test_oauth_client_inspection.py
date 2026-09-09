"""Synthetic-only tests: no runtime environment, account, or credential reads."""

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient
from key_value.aio.adapters.pydantic import PydanticAdapter
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from core.oauth_client_inspection import ExpectedClient, inspect_client
from core.storage import make_sanitized_file_store

COLLECTION = "mcp-oauth-proxy-clients"
CLIENT = "11111111-1111-4111-8111-111111111111"
EXPECTED = ExpectedClient(
    CLIENT,
    "Synthetic Canary",
    "http://127.0.0.1:58508/oauth/callback",
    ("openid", "email"),
)


@pytest_asyncio.fixture
async def store(tmp_path):
    root = tmp_path.resolve() / "store"
    cipher = Fernet(Fernet.generate_key())
    adapter = PydanticAdapter(
        key_value=FernetEncryptionWrapper(
            key_value=make_sanitized_file_store(str(root)), fernet=cipher
        ),
        pydantic_model=ProxyDCRClient,
        default_collection=COLLECTION,
    )
    await adapter.put(
        CLIENT,
        ProxyDCRClient(
            client_id=CLIENT,
            client_name="Synthetic Canary",
            client_secret=None,
            redirect_uris=["http://127.0.0.1:58508/oauth/callback"],
            token_endpoint_auth_method="none",
            scope="email openid",
            grant_types=["authorization_code", "refresh_token"],
        ),
    )
    record = root / COLLECTION / f"{CLIENT}.json"
    record.chmod(0o600)
    return root, cipher, record


async def run(store, expected=EXPECTED, **kwargs):
    root, cipher, _ = store
    return await inspect_client(
        root=root, owner_uid=os.getuid(), expected=expected, fernet=cipher, **kwargs
    )


@pytest.mark.asyncio
@pytest.mark.filterwarnings("error")
async def test_matching_encrypted_client_is_not_cleanup_permission(
    store, capsys, caplog
):
    root, _, _ = store
    before = {
        p.relative_to(root): (p.read_bytes(), p.stat().st_mtime_ns)
        for p in root.rglob("*.json")
    }
    assert await run(store) == {
        "registration": "matched",
        "related_state": "unknown",
        "cleanup_ready": False,
    }
    after = {
        p.relative_to(root): (p.read_bytes(), p.stat().st_mtime_ns)
        for p in root.rglob("*.json")
    }
    assert before == after
    assert capsys.readouterr() == ("", "")
    assert not caplog.records


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"client_name": "Wrong"},
        {"callback": "http://127.0.0.1:58509/oauth/callback"},
        {"scopes": ("openid",)},
        {"scopes": ("openid", "email", "profile")},
    ],
)
async def test_exact_metadata_mismatch_is_not_a_match(store, change):
    assert (await run(store, replace(EXPECTED, **change)))["registration"] == "mismatch"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client_id",
    [
        "../escape",
        "https://example.test/client",
        "",
        "../../secret",
        CLIENT.upper().replace("1", "A", 1),
    ],
)
async def test_unsafe_client_id_rejected_before_io(store, client_id):
    assert (await run(store, replace(EXPECTED, client_id=client_id)))[
        "registration"
    ] == "invalid_input"


@pytest.mark.asyncio
async def test_missing_record_does_not_claim_token_or_registration_absence(store):
    store[2].unlink()
    assert await run(store) == {
        "registration": "candidate_missing",
        "related_state": "unknown",
        "cleanup_ready": False,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "symlink",
        "hardlink",
        "world_readable",
        "oversized",
        "wrong_owner",
        "parent_symlink",
        "missing_mapping",
        "redirected_mapping",
    ],
)
async def test_unsafe_or_unproven_file_mapping_is_refused(store, fault):
    root, _, record = store
    if fault == "symlink":
        target = root / "other"
        record.rename(target)
        record.symlink_to(target)
    elif fault == "hardlink":
        os.link(record, root / "other")
    elif fault == "world_readable":
        record.chmod(0o644)
    elif fault == "oversized":
        record.write_bytes(b"X" * 70000)
    elif fault == "wrong_owner":
        assert (
            await inspect_client(
                root=root, owner_uid=os.getuid() + 1, expected=EXPECTED, fernet=store[1]
            )
        )["registration"] == "unreadable_or_unsafe"
        return
    elif fault == "parent_symlink":
        parent = root / COLLECTION
        parent.rename(root / "moved")
        parent.symlink_to(root / "moved")
    elif fault == "missing_mapping":
        (root / f"{COLLECTION}-info.json").unlink()
    else:
        info = root / f"{COLLECTION}-info.json"
        body = json.loads(info.read_text())
        body["directory"] = str(root / "other")
        info.write_text(json.dumps(body))
    assert (await run(store))["registration"] == "unreadable_or_unsafe"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "wrong_key",
        "malformed",
        "plaintext",
        "encryption_version",
        "expired",
        "invalid_model",
    ],
)
async def test_decryption_or_schema_failure_is_never_absence(
    store, fault, capsys, caplog
):
    root, cipher, record = store
    if fault == "wrong_key":
        result = await inspect_client(
            root=root,
            owner_uid=os.getuid(),
            expected=EXPECTED,
            fernet=Fernet(Fernet.generate_key()),
        )
    else:
        body = json.loads(record.read_text())
        if fault == "malformed":
            record.write_text("SYNTHETIC_SECRET_MUST_NOT_APPEAR")
        elif fault == "plaintext":
            body["value"] = {"client_id": CLIENT}
        elif fault == "encryption_version":
            body["value"]["__encryption_version__"] = 2
        elif fault == "expired":
            body["expires_at"] = "2000-01-01T00:00:00+00:00"
        else:
            wrapper = FernetEncryptionWrapper(
                key_value=make_sanitized_file_store(str(root)), fernet=cipher
            )
            await wrapper.put(
                CLIENT,
                {"redirect_uris": ["SYNTHETIC_SECRET_MUST_NOT_APPEAR"]},
                collection=COLLECTION,
            )
            record.chmod(0o600)
        if fault not in ("malformed", "invalid_model"):
            record.write_text(json.dumps(body))
        result = await run(store)
    assert result == {
        "registration": "invalid_record",
        "related_state": "unknown",
        "cleanup_ready": False,
    }
    assert capsys.readouterr() == ("", "")
    assert not caplog.records


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value", [("expires_at", 42), ("created_at", 42), ("unexpected", "ignored")]
)
async def test_envelope_fields_cannot_silently_bypass_provider_parsing(
    store, field, value
):
    record = store[2]
    body = json.loads(record.read_text())
    body[field] = value
    record.write_text(json.dumps(body))
    assert (await run(store))["registration"] == "invalid_record"


@pytest.mark.asyncio
async def test_noninteger_mapping_version_is_not_supported(store):
    info = store[0] / f"{COLLECTION}-info.json"
    body = json.loads(info.read_text())
    body["version"] = True
    info.write_text(json.dumps(body))
    assert (await run(store))["registration"] == "unreadable_or_unsafe"


@pytest.mark.asyncio
@pytest.mark.parametrize("created_at", [None, "not-a-date", 42])
async def test_mapping_must_be_reloadable_by_provider(store, created_at):
    info = store[0] / f"{COLLECTION}-info.json"
    body = json.loads(info.read_text())
    if created_at is None:
        body.pop("created_at")
    else:
        body["created_at"] = created_at
    info.write_text(json.dumps(body))
    assert (await run(store))["registration"] == "unreadable_or_unsafe"


@pytest.mark.asyncio
async def test_runtime_mismatch_refuses_before_any_file_access(store, monkeypatch):
    import core.oauth_client_inspection as inspector

    monkeypatch.setattr(inspector, "version", lambda name: "9.9.9")

    def forbidden(*args, **kwargs):
        raise AssertionError("file open must not run")

    monkeypatch.setattr(os, "open", forbidden)
    assert (await run(store))["registration"] == "unsupported_runtime"


@pytest.mark.asyncio
async def test_only_two_exact_files_are_read_and_no_listing_or_writes(
    store, monkeypatch
):
    real_open = os.open
    opened = []

    def bounded_open(path, flags, *args, **kwargs):
        assert not flags & (
            os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        )
        if not flags & os.O_DIRECTORY:
            opened.append(path)
        return real_open(path, flags, *args, **kwargs)

    def forbidden(*args, **kwargs):
        raise AssertionError("enumeration must not run")

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", bounded_open)
        patch.setattr(os, "listdir", forbidden)
        patch.setattr(os, "scandir", forbidden)
        assert (await run(store))["registration"] == "matched"
    assert opened == [f"{COLLECTION}-info.json", f"{CLIENT}.json"]


@pytest.mark.asyncio
async def test_record_replacement_during_validation_is_not_a_match(store, monkeypatch):
    from core.oauth_client_inspection import _OneValue

    original_get = _OneValue.get

    async def replace_record(self, key, **kwargs):
        record = store[2]
        replacement = record.with_suffix(".replacement")
        replacement.write_bytes(record.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(record)
        return await original_get(self, key, **kwargs)

    monkeypatch.setattr(_OneValue, "get", replace_record)
    assert (await run(store))["registration"] == "unreadable_or_unsafe"


def test_fresh_import_does_not_load_provider_or_dotenv(tmp_path):
    sentinel = tmp_path / "synthetic.env"
    sentinel.write_text("FASTMCP_LOG_LEVEL=DEBUG\n")
    code = """
import asyncio, os, sys
from pathlib import Path
def guard(event, args):
    if event == "open" and args[0] == os.environ["FASTMCP_ENV_FILE"]:
        raise AssertionError("forbidden dotenv read")
sys.addaudithook(guard)
from core.oauth_client_inspection import ExpectedClient, inspect_client
from cryptography.fernet import Fernet
assert "fastmcp" not in sys.modules
result = asyncio.run(inspect_client(
    root=Path("/synthetic-nonexistent-root"), owner_uid=os.getuid(),
    expected=ExpectedClient("11111111-1111-4111-8111-111111111111", "Synthetic", "http://127.0.0.1:58508/oauth/callback", ("openid",)),
    fernet=Fernet(Fernet.generate_key())))
assert result == {"registration": "unsupported_runtime", "related_state": "unknown", "cleanup_ready": False}
assert "fastmcp" not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-B", "-c", code],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        timeout=15,
        env={
            "FASTMCP_ENV_FILE": str(sentinel),
            "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
        },
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == completed.stderr == ""


@pytest.mark.asyncio
async def test_directory_mode_race_cannot_become_the_accepted_snapshot(
    store, monkeypatch
):
    from core.oauth_client_inspection import _ExactReader

    original_directory = _ExactReader._directory
    calls = 0

    def change_mode(self, fd):
        nonlocal calls
        info = original_directory(self, fd)
        calls += 1
        if calls == 2:
            os.fchmod(fd, 0o777)
        return info

    monkeypatch.setattr(_ExactReader, "_directory", change_mode)
    assert (await run(store))["registration"] == "unreadable_or_unsafe"
