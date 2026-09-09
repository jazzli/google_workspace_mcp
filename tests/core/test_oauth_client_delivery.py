"""Synthetic delivery tests. No production connection or owner-state access."""

import base64
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE = Path(__file__).parents[2] / "core/oauth_client_delivery.py"


def delivery():
    assert MODULE.exists(), "missing application-owned delivery runner"
    spec = importlib.util.spec_from_file_location("delivery_under_test", MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def packet():
    from core import oauth_client_maintenance as maintenance

    now = datetime.now(timezone.utc)
    request = {
        "schema": 1,
        "request_id": "22222222-2222-4222-8222-222222222222",
        "mode": "inspect",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=30)).isoformat(),
        "approval_sha256": "a" * 64,
        "artifact_sha256": maintenance.source_digest(),
        "target": dict(maintenance.TARGET),
        "scopes": ["email", "openid"],
        "filesystem": {
            "root": ["0"] * 6,
            "collection": ["0"] * 6,
            "info": ["0"] * 9,
            "candidate": ["0"] * 9,
        },
    }
    context = {
        "approval_sha256": "a" * 64,
        "artifact_sha256": maintenance.source_digest(),
        "scopes": ["email", "openid"],
        "runtime_target": dict(maintenance.TARGET),
    }
    return {
        "schema": 1,
        "request": request,
        "context": context,
        "sources": {
            name: base64.b64encode((MODULE.parent / name).read_bytes()).decode()
            for name in maintenance.SOURCE_NAMES
        },
    }


@pytest.mark.parametrize("fault", ["source", "context", "target", "extra", "expiry"])
def test_invalid_wire_stops_before_runtime_or_key_access(monkeypatch, fault):
    m = delivery()
    wire = packet()
    if fault == "source":
        wire["sources"]["oauth_client_inspection.py"] = base64.b64encode(
            b"raise SystemExit"
        ).decode()
    if fault == "context":
        wire["context"]["approval_sha256"] = "b" * 64
    if fault == "target":
        wire["context"]["runtime_target"]["service_id"] = "other"
    if fault == "extra":
        wire["command"] = "bad"
    if fault == "expiry":
        wire["request"]["expires_at"] = "2000-01-01T00:00:00Z"
    monkeypatch.setattr(
        m,
        "runtime_preflight",
        lambda *_: pytest.fail("runtime accessed before validation"),
    )
    result = m.deliver(json.dumps(wire).encode())
    assert result["delivery"] == "invalid_delivery"
    assert result["cleanup"] == "not_staged"


@pytest.mark.parametrize(
    "code,reason",
    [
        (
            "import sys;sys.stderr.write('SYNTHETIC_SECRET');sys.exit(7)",
            "process_failed",
        ),
        ("import os;os.write(1,b'x'*8192)", "output_overflow"),
        ("import time;time.sleep(10)", "process_timeout"),
    ],
)
def test_real_child_failure_is_bounded_and_sanitized(code, reason):
    m = delivery()
    with pytest.raises(m.DeliveryFailure) as caught:
        m.bounded_child(
            [sys.executable, "-I", "-B", "-S", "-c", code],
            input=b"{}",
            timeout=0.2,
            output_limit=4096,
            environment={},
        )
    assert str(caught.value) == reason


@pytest.mark.parametrize(
    "kind", ["success", "nonzero", "malformed", "timeout", "adjacent"]
)
def test_real_stage_and_child_cleanup_preserve_adjacent(monkeypatch, tmp_path, kind):
    m = delivery()
    wire = packet()
    stages = []
    original = m.load_maintenance

    def load(sources):
        maintenance = original(sources)
        base = maintenance.StagedBundle

        class Stage(base):
            def __init__(self, bundle, owner_uid):
                super().__init__(bundle, os.geteuid())
                stages.append(self.path)

            @property
            def argv(self):
                result = {
                    "request_id": wire["request"]["request_id"],
                    "target": wire["request"]["target"],
                    "mode": "inspect",
                    "result": "matched",
                    "related_state": "unknown",
                }
                code = "import sys;sys.stdout.write(" + repr(json.dumps(result)) + ")"
                if kind == "nonzero":
                    code = "import sys;sys.exit(2)"
                if kind == "malformed":
                    code = "print('{}')"
                if kind == "timeout":
                    code = "import time;time.sleep(10)"
                if kind == "adjacent":
                    (self.path / "adjacent").write_text("preserve")
                return [sys.executable, "-I", "-B", "-S", "-c", code]

        maintenance.StagedBundle = Stage
        return maintenance

    monkeypatch.setattr(m, "load_maintenance", load)
    monkeypatch.setattr(m, "runtime_preflight", lambda *_: {})
    monkeypatch.setattr(m, "CHILD_TIMEOUT", 0.2)
    result = m.deliver(json.dumps(wire).encode())
    assert len(stages) == 1
    if kind == "adjacent":
        assert result["cleanup"] == "retained"
        assert result["delivery"] == "cleanup_failed"
        assert (stages[0] / "adjacent").read_text() == "preserve"
        for name in (
            "oauth_client_maintenance.py",
            "oauth_client_inspection.py",
            "request.json",
            "adjacent",
        ):
            (stages[0] / name).unlink()
        stages[0].rmdir()
    else:
        assert result["cleanup"] == "removed"
        assert not stages[0].exists()
        assert (
            result["delivery"]
            == {
                "success": "completed",
                "nonzero": "process_failed",
                "malformed": "invalid_result",
                "timeout": "process_timeout",
            }[kind]
        )


def test_production_entry_has_no_test_path_override():
    delivery()
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-S", str(MODULE), "--root", "/tmp"],
        input=b"{}",
        capture_output=True,
        timeout=5,
        env={},
    )
    result = json.loads(completed.stdout)
    assert result["delivery"] == "invalid_delivery"
    assert result["cleanup"] == "not_staged"
    assert completed.stderr == b""


@pytest.mark.parametrize(
    "fault",
    [
        "uid",
        "python",
        "flags",
        "dependencies",
        "ids",
        "storage",
        "valkey",
        "filesystem",
        "missing-key",
        "success",
    ],
)
def test_runtime_checks_precede_any_signing_key_access(monkeypatch, fault):
    from importlib import metadata

    m = delivery()
    wire = packet()
    target = wire["request"]["target"]
    visited = []
    environment = {
        "RAILWAY_" + name.upper(): target[name]
        for name in ("project_id", "environment_id", "service_id", "deployment_id")
    }
    environment.update(
        RAILWAY_GIT_COMMIT_SHA=target["source_commit"],
        WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND="disk",
        WORKSPACE_MCP_OAUTH_PROXY_DISK_DIRECTORY="/data/oauth-proxy",
    )
    if fault == "ids":
        environment["RAILWAY_DEPLOYMENT_ID"] = "other"
    if fault == "storage":
        environment["WORKSPACE_MCP_OAUTH_PROXY_DISK_DIRECTORY"] = "/other"
    if fault == "valkey":
        environment["WORKSPACE_MCP_OAUTH_PROXY_VALKEY_HOST"] = "other"

    class Environment(dict):
        def get(self, name, default=None):
            if name == "FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY":
                assert visited == ["filesystem"]
                assert fault in ("success", "missing-key"), (
                    "key used before preflight passed"
                )
                visited.append("key")
                return "" if fault == "missing-key" else "SYNTHETIC_ONLY"
            return super().get(name, default)

    monkeypatch.setattr(m.os, "environ", Environment(environment))
    monkeypatch.setattr(m.os, "geteuid", lambda: 1 if fault == "uid" else 0)
    monkeypatch.setattr(
        m.sys, "version_info", (3, 12) if fault == "python" else (3, 11)
    )
    monkeypatch.setattr(
        m.sys,
        "flags",
        SimpleNamespace(
            isolated=fault != "flags", dont_write_bytecode=True, no_site=True
        ),
    )
    executable = Path(sys.executable).resolve()
    monkeypatch.setattr(
        m,
        "safe_runtime_path",
        lambda p, **_: executable if p == m.PYTHON else m.PACKAGES,
    )
    pins = [
        SimpleNamespace(metadata={"Name": name}, version=version)
        for name, version in [
            ("fastmcp", "3.2.4"),
            ("mcp", "1.27.0"),
            ("py-key-value-aio", "0.4.4"),
        ]
    ]
    if fault == "dependencies":
        pins[0].version = "0.0.0"
    monkeypatch.setattr(metadata, "distributions", lambda **_: pins)

    def filesystem(*_):
        visited.append("filesystem")
        m.require(fault != "filesystem")

    monkeypatch.setattr(m, "filesystem_preflight", filesystem)
    if fault == "success":
        result = m.runtime_preflight(wire["request"], target)
        assert result["FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY"] == "SYNTHETIC_ONLY"
        assert set(result) == set(environment) | {
            "FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY",
            "FASTMCP_ENV_FILE",
            "FASTMCP_LOG_ENABLED",
            "FASTMCP_TEST_MODE",
        }
    else:
        with pytest.raises(m.DeliveryFailure):
            m.runtime_preflight(wire["request"], target)
    assert ("key" in visited) == (fault in ("missing-key", "success"))


@pytest.mark.parametrize(
    "fault",
    ["none", "candidate-replaced", "candidate-symlink", "collection-mode", "missing"],
)
def test_metadata_preflight_lstats_only_four_exact_nodes(monkeypatch, tmp_path, fault):
    m = delivery()
    root = tmp_path / "store"
    collection = root / "mcp-oauth-proxy-clients"
    collection.mkdir(parents=True, mode=0o700)
    info = root / "mcp-oauth-proxy-clients-info.json"
    candidate = collection / "59df8c3a-ceb7-4bff-9967-b82d45670444.json"
    info.write_text("SYNTHETIC_METADATA")
    candidate.write_text("SYNTHETIC_RECORD")
    candidate.chmod(0o600)
    paths = {
        "root": root,
        "collection": collection,
        "info": info,
        "candidate": candidate,
    }
    original = Path.lstat
    reads = []

    def lstat(path):
        assert path in paths.values(), "unrelated metadata access"
        reads.append(path)
        observed = original(path)
        values = {
            name: getattr(observed, name)
            for name in [
                "st_dev",
                "st_ino",
                "st_gid",
                "st_mode",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            ]
        }
        return SimpleNamespace(st_uid=0, **values)

    monkeypatch.setattr(Path, "lstat", lstat)
    filesystem = {}
    for name, path in paths.items():
        s = lstat(path)
        values = [s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink]
        if name in ("info", "candidate"):
            values += [s.st_size, s.st_mtime_ns, s.st_ctime_ns]
        filesystem[name] = [str(v) for v in values]
    if fault == "candidate-replaced":
        candidate.unlink()
        candidate.write_text("REPLACED")
    if fault == "candidate-symlink":
        candidate.unlink()
        candidate.symlink_to(info)
    if fault == "collection-mode":
        collection.chmod(0o777)
    if fault == "missing":
        candidate.unlink()
    reads.clear()
    target = {
        "root": str(root),
        "collection": collection.name,
        "client_id": candidate.stem,
    }
    if fault == "none":
        m.filesystem_preflight({"filesystem": filesystem}, target)
        assert reads == list(paths.values())
    else:
        with pytest.raises(m.DeliveryFailure):
            m.filesystem_preflight({"filesystem": filesystem}, target)
