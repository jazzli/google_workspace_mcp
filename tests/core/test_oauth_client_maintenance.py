"""Synthetic fixtures only; never inherit credentials or contact a service."""

import importlib.util
import base64
import json
import os
import stat
import subprocess
import sys
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fastmcp.server.auth.jwt_issuer import derive_jwt_key
from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient
from key_value.aio.adapters.pydantic import PydanticAdapter
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from core.storage import make_sanitized_file_store

MODULE = Path(__file__).parents[2] / "core/oauth_client_maintenance.py"
NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
SIGNING = "SYNTHETIC_SIGNING_SENTINEL_123456789"
TARGET = {
    "project_id": "83b53f62-d3db-496a-8570-f9f28b603dde",
    "environment_id": "c0830349-42cb-450a-adb5-04fef95a0c21",
    "service_id": "a6316699-fec1-4c9d-acd7-3ae6a8e9eab0",
    "deployment_id": "27b82461-74cc-48d1-9f05-37755b203c18",
    "source_commit": "d12cc5978396240e6a48a7147e7e8b110b967d86",
    "volume_id": "29fe3f25-062c-43b2-8dac-9533f656f429",
    "root": "/data/oauth-proxy",
    "collection": "mcp-oauth-proxy-clients",
    "client_id": "59df8c3a-ceb7-4bff-9967-b82d45670444",
    "client_name": "Jazz Li Personal MCP Canary - Content",
    "callback": "http://127.0.0.1:58508/oauth/callback",
    "auth_method": "none",
    "attempt_id": "dae0dcd9-baef-46dc-afba-424030cb35fb",
    "generation_before": 0,
    "operation": "bootstrap",
    "stage": "code-exchange-pending",
    "attempt_started_at": "2026-09-09T10:21:14.584Z",
}


def maintenance():
    assert MODULE.exists(), "missing exact-client maintenance executor"
    spec = importlib.util.spec_from_file_location("maintenance_test_module", MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def identity(path, file=False):
    s = path.stat()
    values = [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink]
    if file:
        values += [s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    return [str(value) for value in values]


@pytest_asyncio.fixture
async def sample(tmp_path):
    root = tmp_path.resolve() / "store"
    jwt = derive_jwt_key(low_entropy_material=SIGNING, salt="fastmcp-jwt-signing-key")
    key = derive_jwt_key(
        high_entropy_material=jwt.decode(), salt="fastmcp-storage-encryption-key"
    )
    adapter = PydanticAdapter(
        key_value=FernetEncryptionWrapper(
            key_value=make_sanitized_file_store(str(root)), fernet=Fernet(key)
        ),
        pydantic_model=ProxyDCRClient,
        default_collection=TARGET["collection"],
    )
    await adapter.put(
        TARGET["client_id"],
        ProxyDCRClient(
            client_id=TARGET["client_id"],
            client_name=TARGET["client_name"],
            redirect_uris=[TARGET["callback"]],
            token_endpoint_auth_method="none",
            scope="email openid",
            grant_types=["authorization_code", "refresh_token"],
        ),
    )
    collection = root / TARGET["collection"]
    record = collection / (TARGET["client_id"] + ".json")
    record.chmod(0o600)
    request = {
        "schema": 1,
        "request_id": "22222222-2222-4222-8222-222222222222",
        "mode": "inspect",
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=3)).isoformat(),
        "approval_sha256": "a" * 64,
        "artifact_sha256": "b" * 64,
        "target": deepcopy(TARGET),
        "scopes": ["email", "openid"],
        "filesystem": {
            "root": identity(root),
            "collection": identity(collection),
            "info": identity(root / (TARGET["collection"] + "-info.json"), True),
            "candidate": identity(record, True),
        },
    }
    return root, record, request


async def execute(module, sample, **kwargs):
    root, _, request = sample
    return await module.execute_request(
        request,
        root=root,
        owner_uid=os.getuid(),
        runtime_target=deepcopy(TARGET),
        approved_sha256="a" * 64,
        artifact_sha256="b" * 64,
        approved_scopes=["email", "openid"],
        signing_override=SIGNING,
        now=NOW,
        **kwargs,
    )


@pytest.mark.asyncio
async def test_inspection_is_read_only_and_retirement_deletes_only_exact_record(sample):
    module = maintenance()
    root, record, request = sample
    adjacent = record.with_name("adjacent.json")
    adjacent.write_text("SYNTHETIC_NEIGHBOUR")
    request["filesystem"]["collection"] = identity(record.parent)
    original = record.read_bytes()
    result = await execute(module, sample)
    assert result == {
        "request_id": request["request_id"],
        "target": TARGET,
        "mode": "inspect",
        "result": "matched",
        "related_state": "unknown",
    }
    assert record.read_bytes() == original
    request["mode"] = "retire"
    request["request_id"] = "33333333-3333-4333-8333-333333333333"
    assert (await execute(module, sample))["result"] == "retired_verified"
    assert not record.exists()
    assert adjacent.read_text() == "SYNTHETIC_NEIGHBOUR"
    assert (root / (TARGET["collection"] + "-info.json")).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "mode",
        "missing_mode",
        "approval",
        "artifact",
        "expired",
        "future",
        "uuid",
        "scopes",
        "callback",
        "deployment",
        "extra",
        "identity_number",
        "timestamp",
    ],
)
async def test_invalid_binding_never_mutates(sample, fault):
    module = maintenance()
    _, record, request = sample
    request["mode"] = "retire"
    before = record.read_bytes()
    if fault == "mode":
        request["mode"] = "delete-all"
    elif fault == "missing_mode":
        del request["mode"]
    elif fault == "approval":
        request["approval_sha256"] = "c" * 64
    elif fault == "artifact":
        request["artifact_sha256"] = "c" * 64
    elif fault == "expired":
        request["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
    elif fault == "future":
        request["issued_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif fault == "uuid":
        request["request_id"] = "not-a-uuid"
    elif fault == "scopes":
        request["scopes"] = ["email", "email"]
    elif fault == "callback":
        request["target"]["callback"] = "http://127.0.0.1:99/oauth/callback"
    elif fault == "deployment":
        request["target"]["deployment_id"] = "wrong"
    elif fault == "extra":
        request["command"] = "SYNTHETIC_SECRET"
    elif fault == "identity_number":
        request["filesystem"]["candidate"][0] = 1
    else:
        request["issued_at"] = "2026-09-09 12:00:00+00:00"
    assert (await execute(module, sample))["result"] == "invalid_request"
    assert record.read_bytes() == before


@pytest.mark.asyncio
async def test_missing_candidate_never_counts_as_verified_retirement(sample):
    module = maintenance()
    _, record, request = sample
    request["mode"] = "retire"
    record.unlink()
    assert (await execute(module, sample))["result"] == "filesystem_changed"
    request["filesystem"]["candidate"] = None
    request["filesystem"]["collection"] = identity(record.parent)
    request["request_id"] = "33333333-3333-4333-8333-333333333333"
    assert (await execute(module, sample))["result"] == "candidate_missing"


@pytest.mark.asyncio
async def test_replaced_candidate_retained_even_when_contents_match(sample):
    module = maintenance()
    _, record, request = sample
    request["mode"] = "retire"
    old = record.with_name("old.json")
    record.rename(old)
    record.write_bytes(old.read_bytes())
    record.chmod(0o600)
    assert (await execute(module, sample))["result"] == "filesystem_changed"
    assert record.exists() and old.exists()


@pytest.mark.asyncio
async def test_same_process_request_replay_refused(sample):
    module = maintenance()
    assert (await execute(module, sample))["result"] == "matched"
    assert (await execute(module, sample))["result"] == "invalid_request"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["malformed", "plaintext", "ciphertext", "scopes", "callback"]
)
async def test_record_failures_preserve_candidate_without_secret_output(
    sample, fault, capsys
):
    module = maintenance()
    _, record, request = sample
    request["mode"] = "retire"
    body = json.loads(record.read_text())
    if fault == "malformed":
        record.write_text("SYNTHETIC_SECRET_SENTINEL")
    elif fault == "plaintext":
        body["value"] = {"client_id": TARGET["client_id"]}
        record.write_text(json.dumps(body))
    elif fault == "ciphertext":
        body["value"]["__encrypted_data__"] = "SYNTHETIC_SECRET_SENTINEL"
        record.write_text(json.dumps(body))
    else:
        jwt = derive_jwt_key(
            low_entropy_material=SIGNING, salt="fastmcp-jwt-signing-key"
        )
        key = derive_jwt_key(
            high_entropy_material=jwt.decode(), salt="fastmcp-storage-encryption-key"
        )
        cipher = Fernet(key)
        # Re-encrypt authentic payload with incorrect client metadata.
        payload = json.loads(
            cipher.decrypt(base64.b64decode(body["value"]["__encrypted_data__"]))
        )
        if fault == "scopes":
            payload["scope"] = "openid"
        else:
            payload["redirect_uris"] = ["http://127.0.0.1:99/oauth/callback"]
        body["value"]["__encrypted_data__"] = base64.b64encode(
            cipher.encrypt(json.dumps(payload).encode())
        ).decode()
        record.write_text(json.dumps(body))
    request["filesystem"]["candidate"] = identity(record, True)
    before = record.read_bytes()
    assert (await execute(module, sample))["result"] == (
        "mismatch" if fault in ("scopes", "callback") else "invalid_record"
    )
    assert record.read_bytes() == before
    assert capsys.readouterr() == ("", "")


@pytest.mark.asyncio
async def test_directory_sync_failure_after_unlink_is_uncertain(sample, monkeypatch):
    module = maintenance()
    _, record, request = sample
    request["mode"] = "retire"

    def fail(fd):
        raise OSError("SYNTHETIC_SECRET_SENTINEL")

    monkeypatch.setattr(os, "fsync", fail)
    assert (await execute(module, sample))["result"] == "uncertain"
    assert not record.exists()


def test_fresh_process_controls_precede_genuine_fastmcp_import(tmp_path):
    module = maintenance()
    assert hasattr(module, "controlled_runtime"), "missing fresh-process controls"
    # Would fail Settings parsing if either dotenv route were consumed.
    poisoned = tmp_path / "poison.env"
    poisoned.write_text("FASTMCP_LOG_LEVEL=SYNTHETIC_SECRET_SENTINEL\n")
    (tmp_path / ".env").write_text(poisoned.read_text())
    script = f"""
import importlib.util, json, os, resource, sys
spec = importlib.util.spec_from_file_location('maintenance', {str(MODULE)!r})
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
out = m.controlled_runtime()
import fastmcp
from fastmcp.server.auth.oauth_proxy.models import ProxyDCRClient
import logging
print('SYNTHETIC_SECRET_SENTINEL', flush=True)
os.write(2, b'SYNTHETIC_SECRET_SENTINEL')
logging.critical('SYNTHETIC_SECRET_SENTINEL')
result = [fastmcp.settings.log_level, fastmcp.settings.test_mode, sys.dont_write_bytecode,
          resource.getrlimit(resource.RLIMIT_CORE)[0], 'core.server' in sys.modules]
os.write(out, json.dumps(result).encode())
"""
    proc = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script],
        cwd=tmp_path,
        env={
            "PATH": "/usr/bin:/bin",
            "FASTMCP_ENV_FILE": str(poisoned),
            "FASTMCP_TEST_MODE": "true",
        },
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert proc.stderr == b""
    assert json.loads(proc.stdout) == ["INFO", False, True, 0, False]
    assert not list(tmp_path.rglob("*.pyc"))


@pytest.mark.parametrize(
    "raw", [b'{"mode":"inspect","mode":"retire"}', b'{"x":NaN}', b"[]", b"{}" * 9000]
)
def test_json_parser_rejects_ambiguous_or_oversized_documents(raw):
    with pytest.raises(ValueError):
        maintenance().strict_json(raw)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["key", "runtime", "version", "bool_target", "python"]
)
async def test_runtime_binding_and_missing_key_fail_closed(sample, monkeypatch, fault):
    module = maintenance()
    root, record, request = sample
    request["mode"] = "retire"
    values = dict(
        root=root,
        owner_uid=os.getuid(),
        runtime_target=deepcopy(TARGET),
        approved_sha256="a" * 64,
        artifact_sha256="b" * 64,
        approved_scopes=["email", "openid"],
        signing_override=SIGNING,
        now=NOW,
    )
    if fault == "key":
        values["signing_override"] = " "
    elif fault == "runtime":
        values["runtime_target"]["deployment_id"] = "wrong"
    elif fault == "version":
        monkeypatch.setattr("importlib.metadata.version", lambda _: "0.0.0")
    elif fault == "python":
        monkeypatch.setattr(sys, "version_info", (3, 12, 0))
    else:
        request["target"]["generation_before"] = False
    expected = {
        "key": "runtime_key_unavailable",
        "runtime": "target_mismatch",
        "version": "unsupported_runtime",
        "bool_target": "invalid_request",
        "python": "unsupported_runtime",
    }
    assert (await module.execute_request(request, **values))["result"] == expected[
        fault
    ]
    assert record.exists()


@pytest.mark.asyncio
async def test_fake_remote_process_derives_runtime_key_without_fallback(
    sample, tmp_path
):
    module = maintenance()
    assert hasattr(module, "process_request"), (
        "missing fixed fresh-process request adapter"
    )
    root, record, request = sample
    request["issued_at"] = datetime.now(timezone.utc).isoformat()
    request["expires_at"] = (
        datetime.now(timezone.utc) + timedelta(minutes=3)
    ).isoformat()
    context = {
        "approval_sha256": "a" * 64,
        "artifact_sha256": "b" * 64,
        "scopes": ["email", "openid"],
        "runtime_target": deepcopy(TARGET),
    }
    # An unrelated canonical-package path must never supersede the reviewed
    # staged inspector or trigger application package initialization.
    decoy = tmp_path / "core"
    decoy.mkdir()
    (decoy / "__init__.py").write_text(
        "raise RuntimeError('SYNTHETIC_IMPORT_SENTINEL')\n"
    )
    script = f"""
import importlib.util, os, sys, json
spec = importlib.util.spec_from_file_location('maintenance', {str(MODULE)!r})
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
out = m.controlled_runtime()
sys.path.insert(0, {str(tmp_path)!r})
sys.path.insert(0, {str(MODULE.parent)!r})
import asyncio
from pathlib import Path
from datetime import datetime, timezone
data = m.strict_json(sys.stdin.buffer.read(16385))
answer = asyncio.run(m.process_request(data['request'], data['context'], root=Path({str(root)!r}), owner_uid={os.getuid()}, now=datetime.now(timezone.utc)))
os.write(out, json.dumps(answer).encode())
"""
    env = {
        "PATH": "/usr/bin:/bin",
        "WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND": "disk",
        "WORKSPACE_MCP_OAUTH_PROXY_DISK_DIRECTORY": TARGET["root"],
        "GOOGLE_OAUTH_CLIENT_SECRET": "SYNTHETIC_FALLBACK_MUST_NOT_BE_USED",
    }
    for field in ("project_id", "environment_id", "service_id", "deployment_id"):
        env["RAILWAY_" + field.upper()] = TARGET[field]
    env["RAILWAY_GIT_COMMIT_SHA"] = TARGET["source_commit"]
    raw = json.dumps({"request": request, "context": context}).encode()
    for key, expected in ((None, "runtime_key_unavailable"), (SIGNING, "matched")):
        if key:
            env["FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY"] = key
        proc = subprocess.run(
            [sys.executable, "-I", "-B", "-c", script],
            input=raw,
            env=env,
            cwd=tmp_path,
            capture_output=True,
            timeout=30,
        )
        assert proc.returncode == 0 and proc.stderr == b""
        result = module.parse_result(proc.stdout, request)
        assert result["result"] == expected
        assert b"SYNTHETIC" not in proc.stdout
    assert record.exists()


@pytest.mark.asyncio
async def test_staged_main_refuses_untrusted_nonroot_launch_without_output_leak(sample):
    module = maintenance()
    assert hasattr(module, "main"), "missing fixed staged process entry"
    sample[2]["artifact_sha256"] = module.source_digest()
    stage = module.stage_bundle(module.build_bundle(sample[2]), owner_uid=os.getuid())
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(stage.path / "oauth_client_maintenance.py"),
            ],
            input=b'{"secret":"SYNTHETIC_SECRET_SENTINEL"}',
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            timeout=30,
        )
        assert proc.returncode == 0
        assert proc.stderr == b""
        assert json.loads(proc.stdout)["result"] == "invalid_request"
        assert b"SYNTHETIC" not in proc.stdout
    finally:
        stage.cleanup()


@pytest.mark.asyncio
async def test_bundle_staging_has_only_bound_private_files_and_exact_cleanup(sample):
    module = maintenance()
    assert hasattr(module, "build_bundle"), "missing reviewed source bundle"
    sample[2]["artifact_sha256"] = module.source_digest()
    bundle = module.build_bundle(sample[2])
    assert set(bundle) == {
        "oauth_client_maintenance.py",
        "oauth_client_inspection.py",
        "request.json",
    }
    stage = module.stage_bundle(bundle, owner_uid=os.getuid())
    path = stage.path
    try:
        assert path.stat().st_mode & 0o777 == 0o700
        assert {p.name for p in path.iterdir()} == set(bundle)
        assert all(p.stat().st_mode & 0o777 == 0o600 for p in path.iterdir())
        stage.verify()
        assert stage.argv == [
            "/app/.venv/bin/python",
            "-I",
            "-B",
            "-S",
            str(path / "oauth_client_maintenance.py"),
        ]
    finally:
        stage.cleanup()
    assert not path.exists()


@pytest.mark.asyncio
async def test_staging_replacement_and_adjacent_files_are_never_deleted(sample):
    module = maintenance()
    assert hasattr(module, "build_bundle"), "missing reviewed source bundle"
    sample[2]["artifact_sha256"] = module.source_digest()
    stage = module.stage_bundle(module.build_bundle(sample[2]), owner_uid=os.getuid())
    extra = stage.path / "unapproved"
    extra.write_text("SYNTHETIC_NEIGHBOUR")
    with pytest.raises(ValueError):
        stage.cleanup()
    assert extra.read_text() == "SYNTHETIC_NEIGHBOUR"
    # The synthetic fixture owns these files; remove only its exact added file.
    extra.unlink()
    original = stage.path / "request.json"
    original.unlink()
    original.write_text("SYNTHETIC_REPLACEMENT")
    original.chmod(0o600)
    with pytest.raises(ValueError):
        stage.cleanup()
    assert original.read_text() == "SYNTHETIC_REPLACEMENT"
    for name in (
        "request.json",
        "oauth_client_maintenance.py",
        "oauth_client_inspection.py",
    ):
        (stage.path / name).unlink()
    stage.path.rmdir()


@pytest.mark.asyncio
async def test_staging_midread_change_rejected(sample, monkeypatch):
    module = maintenance()
    sample[2]["artifact_sha256"] = module.source_digest()
    stage = module.stage_bundle(module.build_bundle(sample[2]), owner_uid=os.getuid())
    read = os.read
    original = stage.path / "oauth_client_maintenance.py"

    def changed(fd, amount):
        raw = read(fd, amount)
        if os.fstat(fd).st_ino == original.stat().st_ino:
            original.write_bytes(raw + b"\n# synthetic mutation\n")
        return raw

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "read", changed)
        with pytest.raises(ValueError):
            stage.verify()
    # Exact synthetic fixture teardown after intentionally violating binding.
    os.close(stage.fd)
    for name in (
        "request.json",
        "oauth_client_maintenance.py",
        "oauth_client_inspection.py",
    ):
        (stage.path / name).unlink()
    stage.path.rmdir()


@pytest.mark.asyncio
async def test_staging_directory_replacement_during_read_rejected(sample, monkeypatch):
    module = maintenance()
    sample[2]["artifact_sha256"] = module.source_digest()
    stage = module.stage_bundle(module.build_bundle(sample[2]), owner_uid=os.getuid())
    moved = stage.path.with_name(stage.path.name + "-moved")
    read = os.read

    def changed(fd, amount):
        raw = read(fd, amount)
        if not moved.exists():
            stage.path.rename(moved)
            stage.path.mkdir(mode=0o700)
        return raw

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "read", changed)
        with pytest.raises(ValueError):
            stage.verify()
    os.close(stage.fd)
    for name in (
        "request.json",
        "oauth_client_maintenance.py",
        "oauth_client_inspection.py",
    ):
        (moved / name).unlink()
    moved.rmdir()
    stage.path.rmdir()


@pytest.mark.asyncio
async def test_expiry_rechecked_after_record_authentication_before_retirement(
    sample, monkeypatch
):
    module = maintenance()
    assert hasattr(module, "time"), "missing elapsed-time expiry guard"
    from types import SimpleNamespace
    from core import oauth_client_inspection

    elapsed = [0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: elapsed[0]))
    inspect = oauth_client_inspection.inspect_client

    async def delayed(**kwargs):
        result = await inspect(**kwargs)
        elapsed[0] = 301
        return result

    monkeypatch.setattr(oauth_client_inspection, "inspect_client", delayed)
    sample[2]["mode"] = "retire"
    assert (await execute(module, sample))["result"] == "invalid_request"
    assert sample[1].exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["timeout", "bad_output", "wrong_request", "success"]
)
async def test_fixed_transport_invocation_cleanup_and_uncertain_outcome(
    sample, failure
):
    module = maintenance()
    assert hasattr(module.StagedBundle, "invoke"), "missing fixed transport adapter"
    request = sample[2]
    request["artifact_sha256"] = module.source_digest()
    request["issued_at"] = datetime.now(timezone.utc).isoformat()
    request["expires_at"] = (
        datetime.now(timezone.utc) + timedelta(minutes=3)
    ).isoformat()
    request["mode"] = "retire"
    stage = module.stage_bundle(module.build_bundle(request), owner_uid=os.getuid())
    context = {
        "approval_sha256": "a" * 64,
        "artifact_sha256": request["artifact_sha256"],
        "scopes": ["email", "openid"],
        "runtime_target": deepcopy(TARGET),
    }
    calls = []

    def fake_remote(argv, *, input, timeout, output_limit):
        calls.append(argv)
        assert argv == [
            "/app/.venv/bin/python",
            "-I",
            "-B",
            "-S",
            str(stage.path / "oauth_client_maintenance.py"),
        ]
        wire = json.loads(input)
        assert wire["approval_sha256"] == "a" * 64
        assert wire["stage_identity"] == list(stage.identity)
        assert set(wire["stage_files"]) == {
            "oauth_client_maintenance.py",
            "oauth_client_inspection.py",
            "request.json",
        }
        assert timeout <= 30 and output_limit == 4096
        if failure == "timeout":
            raise TimeoutError("SYNTHETIC_SECRET_SENTINEL")
        if failure == "bad_output":
            return b"SYNTHETIC_SECRET_SENTINEL"
        return json.dumps(
            {
                "request_id": request["request_id"]
                if failure == "success"
                else "wrong",
                "mode": "retire",
                "target": TARGET,
                "result": "retired_verified",
                "related_state": "unknown",
            }
        ).encode()

    result = stage.invoke(fake_remote, request, context)
    assert len(calls) == 1
    assert result["result"] == (
        "retired_verified" if failure == "success" else "uncertain"
    )
    assert not stage.path.exists()


@pytest.mark.asyncio
async def test_partial_stage_creation_closes_descriptors(sample, monkeypatch):
    module = maintenance()
    request = sample[2]
    request["artifact_sha256"] = module.source_digest()
    opened = []
    made = []
    import tempfile

    real_open, real_mkdir = os.open, tempfile.mkdtemp

    def track_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def track_mkdir(*args, **kwargs):
        path = real_mkdir(*args, **kwargs)
        made.append(Path(path))
        return path

    with monkeypatch.context() as scoped:
        scoped.setattr(os, "open", track_open)
        scoped.setattr(tempfile, "mkdtemp", track_mkdir)
        scoped.setattr(os, "fsync", lambda _: (_ for _ in ()).throw(OSError()))
        with pytest.raises(OSError):
            module.stage_bundle(module.build_bundle(request), owner_uid=os.getuid())
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert len(made) == 1
    (made[0] / "oauth_client_maintenance.py").unlink()
    made[0].rmdir()


@pytest.mark.asyncio
async def test_invalid_staged_request_never_echoes_input_or_invokes_transport(sample):
    module = maintenance()
    request = sample[2]
    request["artifact_sha256"] = module.source_digest()
    request["request_id"] = "SYNTHETIC_SECRET_SENTINEL"
    stage = module.stage_bundle(module.build_bundle(request), owner_uid=os.getuid())

    def forbidden(*args, **kwargs):
        pytest.fail("invalid request must not dispatch")

    result = stage.invoke(
        forbidden,
        request,
        {
            "approval_sha256": "a" * 64,
            "artifact_sha256": request["artifact_sha256"],
            "scopes": ["email", "openid"],
            "runtime_target": TARGET,
        },
    )
    assert result["result"] == "invalid_request"
    assert result["request_id"] is None and result["mode"] is None
    assert "SYNTHETIC" not in json.dumps(result)
    assert not stage.path.exists()


@pytest.mark.asyncio
async def test_staged_python_flags_disable_site_hooks_before_controls(sample, tmp_path):
    import venv

    module = maintenance()
    sample[2]["artifact_sha256"] = module.source_digest()
    stage = module.stage_bundle(module.build_bundle(sample[2]), owner_uid=os.getuid())
    runtime = tmp_path / "synthetic-venv"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(runtime)
    hook = runtime / "lib/python3.11/site-packages/synthetic-startup.pth"
    hook.write_text("import os; os.write(1, b'SYNTHETIC_STARTUP_SECRET_SENTINEL')\n")
    script = f"""
import importlib.util, os, json, sys
spec = importlib.util.spec_from_file_location('maintenance', {str(MODULE)!r})
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
out = m.controlled_runtime()
sys.path.append({str(Path(sys.executable).parent.parent / "lib/python3.11/site-packages")!r})
import fastmcp
os.write(out, json.dumps([sys.flags.no_site, fastmcp.settings.test_mode]).encode())
"""
    try:
        proc = subprocess.run(
            [str(runtime / "bin/python"), *stage.argv[1:-1], "-c", script],
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            timeout=30,
        )
        assert proc.returncode == 0 and proc.stderr == b""
        assert proc.stdout == b"[1, false]"
    finally:
        stage.cleanup()


@pytest.mark.asyncio
async def test_missing_initial_candidate_cannot_retire_a_later_matching_record(
    sample, monkeypatch
):
    from core import oauth_client_inspection as inspection

    module = maintenance()
    _, record, request = sample
    encrypted_record = record.read_bytes()
    record.unlink()
    request["mode"] = "retire"
    request["filesystem"]["candidate"] = None
    request["filesystem"]["collection"] = identity(record.parent)
    # Linux directory nlink does not change when a regular file appears.
    # Normalize only that platform difference; all reads, crypto and file
    # creation/deletion remain real synthetic filesystem operations.
    original_identity = inspection._identity

    def linux_identity(info):
        values = original_identity(info)
        return (*values[:-1], 2) if stat.S_ISDIR(info.st_mode) else values

    monkeypatch.setattr(inspection, "_identity", linux_identity)
    for name in ("root", "collection"):
        request["filesystem"][name][-1] = "2"
    inspect = inspection.inspect_client

    async def insert_before_inspection(**kwargs):
        record.write_bytes(encrypted_record)
        record.chmod(0o600)
        return await inspect(**kwargs)

    monkeypatch.setattr(inspection, "inspect_client", insert_before_inspection)
    result = await execute(module, sample)
    assert result["result"] == "filesystem_changed"
    assert record.read_bytes() == encrypted_record


@pytest.mark.asyncio
async def test_main_unsupported_python_does_not_echo_unvalidated_request(sample):
    module = maintenance()
    request = sample[2]
    request["artifact_sha256"] = module.source_digest()
    request["request_id"] = "SYNTHETIC_UNVALIDATED_ID_SENTINEL"
    request["mode"] = "SYNTHETIC_UNVALIDATED_MODE_SENTINEL"
    stage = module.stage_bundle(module.build_bundle(request), owner_uid=os.getuid())
    context = {
        "approval_sha256": "a" * 64,
        "artifact_sha256": request["artifact_sha256"],
        "scopes": ["email", "openid"],
        "runtime_target": TARGET,
        "stage_identity": stage.identity,
        "stage_files": stage.files,
    }
    entry = str(Path("/tmp") / stage.path.name / "oauth_client_maintenance.py")
    # Reach the unsupported-version branch with actual staged sources/JSON and
    # fresh-process controls. Emulate only UID ownership gates on this nonroot
    # macOS host; this does not claim production root/Linux validation.
    script = f"""
import asyncio, importlib.util, os, sys
spec = importlib.util.spec_from_file_location('maintenance', {entry!r})
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
verify = m.StagedBundle.verify
def synthetic_owner_verify(stage):
    stage.owner_uid = os.getuid()
    return verify(stage)
m.StagedBundle.verify = synthetic_owner_verify
os.geteuid = lambda: 0
sys.version_info = (3, 12, 0)
sys.argv = [{entry!r}]
m.main()
"""
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-B", "-S", "-c", script],
            input=json.dumps(context).encode(),
            env={"PATH": "/usr/bin:/bin"},
            capture_output=True,
            timeout=30,
        )
        assert proc.returncode == 0 and proc.stderr == b""
        result = json.loads(proc.stdout)
        assert result["result"] == "invalid_request"
        assert result["request_id"] is None and result["mode"] is None
        assert b"SYNTHETIC" not in proc.stdout
    finally:
        stage.cleanup()
