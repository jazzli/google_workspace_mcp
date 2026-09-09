"""Exact-source SSH delivery entry, stdlib only and no application endpoint.

The controller authenticates SSH and constructs context from a separately
approved envelope under protected owner coordination. This wire is not itself
authentication. Never install this as a service or expose it as a public API.
"""

import base64
import hashlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
import types
from datetime import datetime, timezone
from pathlib import Path

ARTIFACT = "f2fd33074dc9266811594de09541bab9928351ab313e79743873c47beae5bb3d"
SOURCES = ("oauth_client_maintenance.py", "oauth_client_inspection.py")
PYTHON = Path("/app/.venv/bin/python")
PACKAGES = Path("/app/.venv/lib/python3.11/site-packages")
CHILD_TIMEOUT = 20


class DeliveryFailure(Exception):
    """Only fixed non-secret classifications cross this boundary."""


def require(condition):
    if not condition:
        raise DeliveryFailure("invalid_delivery")


def strict_json(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 750000)

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def invalid(_):
        raise DeliveryFailure("invalid_delivery")

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    require(type(value) is dict)
    return value


def load_maintenance(sources):
    require(type(sources) is dict and set(sources) == set(SOURCES))
    decoded = {}
    digest = hashlib.sha256()
    for name in SOURCES:
        require(type(sources[name]) is str)
        data = base64.b64decode(sources[name], validate=True)
        require(0 < len(data) <= 262144)
        decoded[name] = data
        digest.update(name.encode() + b"\0" + str(len(data)).encode() + b"\0" + data)
    require(digest.hexdigest() == ARTIFACT)
    module = types.ModuleType("reviewed_maintenance")
    # Source bytes have been authenticated against the reviewed artifact before
    # execution. This module uses only stdlib until the isolated child starts.
    module.__file__ = "/tmp/reviewed-source-not-installed/oauth_client_maintenance.py"
    exec(compile(decoded[SOURCES[0]], SOURCES[0], "exec"), module.__dict__)
    module.delivery_sources = decoded
    return module


def safe_runtime_path(path, *, directory):
    resolved = path.resolve(strict=True)
    for parent in (resolved, *resolved.parents):
        info = parent.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022)
        require(
            stat.S_ISDIR(info.st_mode)
            if parent != resolved or directory
            else stat.S_ISREG(info.st_mode)
        )
    # Ancestors of the original path must not redirect through writable paths.
    for parent in path.parents:
        info = parent.lstat()
        require(
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
        )
    return resolved


def filesystem_preflight(request, target):
    root = Path(target["root"])
    paths = {
        "root": root,
        "collection": root / target["collection"],
        "info": root / (target["collection"] + "-info.json"),
        "candidate": root / target["collection"] / (target["client_id"] + ".json"),
    }
    for name, path in paths.items():
        try:
            info = path.lstat()
        except FileNotFoundError:
            require(name == "candidate" and request["filesystem"][name] is None)
            continue
        directory = name in ("root", "collection")
        require(info.st_uid == 0 and not info.st_mode & 0o022)
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        if not directory:
            require(info.st_nlink == 1 and 0 < info.st_size <= 262144)
            require(
                stat.S_IMODE(info.st_mode)
                in ((0o600,) if name == "candidate" else (0o600, 0o644))
            )
        values = [
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_nlink,
        ]
        if not directory:
            values += [info.st_size, info.st_mtime_ns, info.st_ctime_ns]
        require([str(v) for v in values] == request["filesystem"][name])


def runtime_preflight(request, target):
    require(os.geteuid() == 0 and sys.version_info[:2] == (3, 11))
    require(sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site)
    require(
        Path(sys.executable).resolve(strict=True)
        == safe_runtime_path(PYTHON, directory=False)
    )
    require(safe_runtime_path(PACKAGES, directory=True) == PACKAGES)
    from importlib.metadata import distributions

    pins = {"fastmcp": "3.2.4", "mcp": "1.27.0", "py-key-value-aio": "0.4.4"}
    found = {}
    for distribution in distributions(path=[str(PACKAGES)]):
        name = distribution.metadata["Name"].lower().replace("_", "-")
        if name in pins:
            require(name not in found)
            found[name] = distribution.version
    require(found == pins)
    environment = {}
    for field in ("project_id", "environment_id", "service_id", "deployment_id"):
        name = "RAILWAY_" + field.upper()
        require(os.environ.get(name) == target[field])
        environment[name] = target[field]
    require(os.environ.get("RAILWAY_GIT_COMMIT_SHA") == target["source_commit"])
    environment["RAILWAY_GIT_COMMIT_SHA"] = target["source_commit"]
    disk = os.environ.get("WORKSPACE_MCP_OAUTH_PROXY_DISK_DIRECTORY", "").strip()
    if not disk:
        home = os.environ.get("FASTMCP_HOME", "").strip()
        disk = home + "/oauth-proxy" if home else None
    require(disk == target["root"])
    require(
        os.environ.get("WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND", "").strip().lower()
        == "disk"
    )
    require(not os.environ.get("WORKSPACE_MCP_OAUTH_PROXY_VALKEY_HOST", "").strip())
    filesystem_preflight(request, target)
    # No key access until all runtime, dependency, selection and metadata checks
    # above succeed. No /proc, dotenv, provider exports or credential-file fallback.
    signing = os.environ.get("FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY", "")
    if not signing.strip():
        raise DeliveryFailure("runtime_key_unavailable")
    environment.update(
        {
            "FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY": signing,
            "WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND": "disk",
            "WORKSPACE_MCP_OAUTH_PROXY_DISK_DIRECTORY": target["root"],
            "FASTMCP_ENV_FILE": "/dev/null",
            "FASTMCP_LOG_ENABLED": "false",
            "FASTMCP_TEST_MODE": "false",
        }
    )
    return environment


def bounded_child(argv, *, input, timeout, output_limit, environment):
    """Single owned process group; bounded pipe reads, writes and lifetime."""
    child = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
        start_new_session=True,
        close_fds=True,
    )
    deadline = time.monotonic() + timeout
    output = bytearray()
    pending = memoryview(input)
    try:
        with selectors.DefaultSelector() as selector:
            for stream, event in (
                (child.stdin, selectors.EVENT_WRITE),
                (child.stdout, selectors.EVENT_READ),
            ):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise DeliveryFailure("process_timeout")
                for key, _ in selector.select(remaining):
                    if key.fileobj is child.stdin:
                        if pending:
                            pending = pending[os.write(child.stdin.fileno(), pending) :]
                        if not pending:
                            selector.unregister(child.stdin)
                            child.stdin.close()
                    else:
                        data = os.read(child.stdout.fileno(), output_limit + 1)
                        if not data:
                            selector.unregister(child.stdout)
                        output.extend(data)
                        if len(output) > output_limit:
                            raise DeliveryFailure("output_overflow")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeliveryFailure("process_timeout")
            if child.wait(timeout=remaining) != 0:
                raise DeliveryFailure("process_failed")
        return bytes(output)
    except subprocess.TimeoutExpired:
        raise DeliveryFailure("process_timeout") from None
    except (BrokenPipeError, OSError):
        raise DeliveryFailure("process_failed") from None
    finally:
        # Kill the owned group even when its leader exited, so a grandchild cannot
        # retain pipes or the inherited environment past the bounded operation.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        child.stdin.close()
        child.stdout.close()


def deliver(raw):
    response = {
        "schema": 1,
        "delivery": "invalid_delivery",
        "cleanup": "not_staged",
        "stage": None,
        "outcome": None,
    }
    stage = None
    try:
        wire = strict_json(raw)
        require(
            set(wire) == {"schema", "request", "context", "sources"}
            and type(wire["schema"]) is int
            and wire["schema"] == 1
        )
        maintenance = load_maintenance(wire["sources"])
        request, context = wire["request"], wire["context"]
        require(
            type(context) is dict
            and set(context)
            == {"approval_sha256", "artifact_sha256", "scopes", "runtime_target"}
        )
        require(
            context["artifact_sha256"] == ARTIFACT
            and maintenance._same_target(context["runtime_target"])
        )
        maintenance._validate(
            request,
            context["approval_sha256"],
            ARTIFACT,
            context["scopes"],
            datetime.now(timezone.utc),
        )
        environment = runtime_preflight(request, maintenance.TARGET)
        bundle = {
            **maintenance.delivery_sources,
            "request.json": json.dumps(request, allow_nan=False).encode(),
        }
        stage = maintenance.StagedBundle.__new__(maintenance.StagedBundle)
        stage.__init__(bundle, 0)
        response.update(cleanup="retained", stage=stage.path.name)
        stage.verify()
        context = {
            **context,
            "stage_identity": stage.identity,
            "stage_files": stage.files,
        }
        raw_result = bounded_child(
            stage.argv,
            input=json.dumps(context, allow_nan=False).encode(),
            timeout=min(
                CHILD_TIMEOUT,
                (
                    datetime.fromisoformat(request["expires_at"].replace("Z", "+00:00"))
                    - datetime.now(timezone.utc)
                ).total_seconds(),
            ),
            output_limit=4096,
            environment=environment,
        )
        response["delivery"] = "invalid_result"
        response["outcome"] = maintenance.parse_result(raw_result, request)
        response["delivery"] = "completed"
    except DeliveryFailure as error:
        response["delivery"] = str(error)
    except BaseException:
        if stage is not None and response["delivery"] != "invalid_result":
            response["delivery"] = "process_failed"
    finally:
        if stage is not None and hasattr(stage, "path"):
            response.update(cleanup="retained", stage=stage.path.name)
            try:
                stage.cleanup()
                response["cleanup"] = "removed"
            except BaseException:
                response.update(delivery="cleanup_failed", outcome=None)
                if hasattr(stage, "fd"):
                    try:
                        os.close(stage.fd)
                    except OSError:
                        pass
    return response


def main():
    import resource

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = os.dup(1)
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 1)
    os.dup2(null, 2)
    os.close(null)
    result = {
        "schema": 1,
        "delivery": "invalid_delivery",
        "cleanup": "not_staged",
        "stage": None,
        "outcome": None,
    }
    try:
        require(len(sys.argv) == 1)
        result = deliver(sys.stdin.buffer.read(750001))
    except BaseException:
        pass
    os.write(output, json.dumps(result, separators=(",", ":")).encode() + b"\n")
    os.close(output)


if __name__ == "__main__":
    main()
