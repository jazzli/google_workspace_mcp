"""One exact historical registration; no app route or credential-file loader.

Only stdlib imports at module load. The authenticated operator supplies trusted
context separately from the request. This module cannot authenticate that caller
or prevent cross-process replay. Deleting a registration does not revoke tokens.
"""

import hashlib
import json
import os
import re
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

SOURCE_NAMES = ("oauth_client_maintenance.py", "oauth_client_inspection.py")
STAGE_NAMES = (*SOURCE_NAMES, "request.json")

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
RESULTS = frozenset(
    {
        "matched",
        "retired_verified",
        "candidate_missing",
        "invalid_request",
        "unsupported_runtime",
        "target_mismatch",
        "runtime_key_unavailable",
        "invalid_record",
        "mismatch",
        "filesystem_changed",
        "uncertain",
    }
)
FIELDS = frozenset(
    {
        "schema",
        "request_id",
        "mode",
        "issued_at",
        "expires_at",
        "approval_sha256",
        "artifact_sha256",
        "target",
        "scopes",
        "filesystem",
    }
)
_USED = set()


def strict_json(raw):
    """Bounded JSON object, without duplicate keys or nonfinite numbers."""
    _require(type(raw) is bytes and 0 < len(raw) <= 16384)

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError()

    value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    _require(type(value) is dict)
    return value


def controlled_runtime():
    """One-shot process controls. Caller writes only bounded result to saved fd.

    No restoration: this is for an isolated maintenance process, not the server.
    Stdout/stderr descriptors and Python logging are silenced before imports.
    """
    import logging
    import resource
    import sys
    import warnings

    output = os.dup(1)
    os.set_inheritable(output, False)
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 1)
    os.dup2(null, 2)
    os.close(null)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    sys.dont_write_bytecode = True
    sys.excepthook = lambda *_: None
    logging.disable(2**31 - 1)
    warnings.filterwarnings("ignore")
    os.environ["FASTMCP_ENV_FILE"] = os.devnull
    os.environ["FASTMCP_LOG_ENABLED"] = "false"
    os.environ["FASTMCP_TEST_MODE"] = "false"
    return output


def _source_digest(sources):
    digest = hashlib.sha256()
    for name in SOURCE_NAMES:
        data = sources[name]
        _require(type(data) is bytes and 0 < len(data) <= 262144)
        digest.update(name.encode() + b"\0" + str(len(data)).encode() + b"\0" + data)
    return digest.hexdigest()


def source_digest():
    """Digest the two local reviewed sources, never application credential data."""
    return _source_digest(
        {name: Path(__file__).with_name(name).read_bytes() for name in SOURCE_NAMES}
    )


def build_bundle(request):
    sources = {
        name: Path(__file__).with_name(name).read_bytes() for name in SOURCE_NAMES
    }
    _require(request["artifact_sha256"] == _source_digest(sources))
    raw = json.dumps(request, allow_nan=False, separators=(",", ":")).encode()
    strict_json(raw)
    return {**sources, "request.json": raw}


def _stat_identity(info):
    return tuple(
        str(v)
        for v in (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_nlink,
        )
    )


class StagedBundle:
    """Owns only its freshly created directory and three exact private files.

    The authenticated transport is responsible for invoking this on the target
    as root. A trusted local caller may select its own UID for synthetic tests.
    No path or executable is accepted from request data.
    """

    def __init__(self, bundle, owner_uid):
        import tempfile

        _require(type(owner_uid) is int and owner_uid == os.geteuid())
        _require(set(bundle) == set(STAGE_NAMES))
        request = strict_json(bundle["request.json"])
        _require(request["artifact_sha256"] == _source_digest(bundle))
        self.request = request
        self.path = Path(
            tempfile.mkdtemp(prefix="oauth-client-maintenance-", dir="/tmp")
        ).resolve()
        self.owner_uid = owner_uid
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.files = {}
        try:
            self._populate(bundle)
        except BaseException:
            os.close(self.fd)
            raise

    def _populate(self, bundle):
        # On a failure, retain the exact staging path for manual reconciliation;
        # never broaden cleanup to an unvalidated partial directory.
        for name in STAGE_NAMES:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.fd,
            )
            try:
                raw = bundle[name]
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(fd)
                info = os.fstat(fd)
                self.files[name] = (
                    _stat_identity(info),
                    str(info.st_size),
                    str(info.st_mtime_ns),
                    str(info.st_ctime_ns),
                    hashlib.sha256(raw).hexdigest(),
                )
            finally:
                os.close(fd)
        os.fsync(self.fd)
        self.identity = _stat_identity(os.fstat(self.fd))

    @property
    def argv(self):
        return [
            "/app/.venv/bin/python",
            "-I",
            "-B",
            "-S",
            str(self.path / SOURCE_NAMES[0]),
        ]

    def verify(self):
        import stat

        _require(_stat_identity(os.fstat(self.fd)) == self.identity)
        _require(_stat_identity(self.path.lstat()) == self.identity)
        _require(
            os.fstat(self.fd).st_uid == self.owner_uid
            and stat.S_IMODE(os.fstat(self.fd).st_mode) == 0o700
        )
        _require(set(os.listdir(self.fd)) == set(STAGE_NAMES))
        snapshot = {}
        for name in STAGE_NAMES:
            fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd
            )
            try:
                info = os.fstat(fd)
                _require(
                    stat.S_ISREG(info.st_mode)
                    and info.st_nlink == 1
                    and info.st_uid == self.owner_uid
                    and stat.S_IMODE(info.st_mode) == 0o600
                )
                _require(0 < info.st_size <= 262144)
                data = os.read(fd, 262145)
                current = (
                    _stat_identity(info),
                    str(info.st_size),
                    str(info.st_mtime_ns),
                    str(info.st_ctime_ns),
                    hashlib.sha256(data).hexdigest(),
                )
                _require(current == self.files[name])
                after = os.fstat(fd)
                _require(
                    (
                        _stat_identity(after),
                        str(after.st_size),
                        str(after.st_mtime_ns),
                        str(after.st_ctime_ns),
                    )
                    == current[:4]
                )
                _require(
                    _stat_identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
                    == current[0]
                )
                snapshot[name] = data
            finally:
                os.close(fd)
        _require(_stat_identity(os.fstat(self.fd)) == self.identity)
        _require(_stat_identity(self.path.lstat()) == self.identity)
        return snapshot

    def cleanup(self):
        self.verify()
        for name in STAGE_NAMES:
            os.unlink(name, dir_fd=self.fd)
        os.fsync(self.fd)
        # Revalidate containing directory identity except nlink (APFS changes
        # directory link counts as files are removed), then remove empty only.
        _require(_stat_identity(self.path.lstat())[:5] == self.identity[:5])
        os.rmdir(self.path)
        os.close(self.fd)

    def invoke(self, transport, request, context):
        """Invoke once through a trusted authenticated process capability.

        ``transport`` must enforce timeout, a 4096-byte stdout limit, discard
        stderr, raise for nonzero exit, and never retry. It is not implemented
        here: no SSH registration, endpoint or account selection is provided.
        A successful cleanup cannot resolve uncertain registration mutation.
        """
        result = _result(None, "invalid_request")
        safe_request = None
        try:
            _require(
                type(context) is dict
                and set(context)
                == {"approval_sha256", "artifact_sha256", "scopes", "runtime_target"}
            )
            _validate(
                request,
                context["approval_sha256"],
                context["artifact_sha256"],
                context["scopes"],
                datetime.now(timezone.utc),
            )
            _require(
                request == self.request and _same_target(context["runtime_target"])
            )
            safe_request = request
            result = _result(request, "uncertain")
            self.verify()
            wire = {
                **context,
                "stage_identity": self.identity,
                "stage_files": self.files,
            }
            raw = transport(
                self.argv,
                input=json.dumps(wire, allow_nan=False).encode(),
                timeout=30,
                output_limit=4096,
            )
            result = parse_result(raw, request)
        except Exception:
            pass
        finally:
            try:
                self.cleanup()
            except Exception:
                result = _result(
                    safe_request, "uncertain" if safe_request else "invalid_request"
                )
                os.close(self.fd)
        return result


def stage_bundle(bundle, *, owner_uid=0):
    return StagedBundle(bundle, owner_uid)


def _require(condition):
    if not condition:
        raise ValueError()


def _result(request, classification):
    return {
        "request_id": request["request_id"] if request else None,
        "target": dict(TARGET),
        "mode": request["mode"] if request else None,
        "result": classification,
        "related_state": "unknown",
    }


def _validate(request, approved_sha256, artifact_sha256, approved_scopes, now):
    _require(type(request) is dict and set(request) == FIELDS)
    _require(len(json.dumps(request)) <= 16384)
    _require(type(request["schema"]) is int and request["schema"] == 1)
    _require(request["mode"] in ("inspect", "retire"))
    nonce = UUID(request["request_id"])
    _require(nonce.version == 4 and str(nonce) == request["request_id"])
    _require(request["request_id"] not in _USED)
    for field, trusted in (
        ("approval_sha256", approved_sha256),
        ("artifact_sha256", artifact_sha256),
    ):
        _require(
            type(request[field]) is str
            and re.fullmatch(r"[0-9a-f]{64}", request[field])
        )
        _require(request[field] == trusted)
    _require(_same_target(request["target"]))
    scopes = request["scopes"]
    _require(type(scopes) is list and 0 < len(scopes) <= 100)
    _require(
        all(
            type(s) is str and re.fullmatch(r"[\x21\x23-\x5b\x5d-\x7e]{1,256}", s)
            for s in scopes
        )
    )
    _require(scopes == sorted(set(scopes)) and scopes == approved_scopes)
    for field in ("issued_at", "expires_at"):
        _require(
            type(request[field]) is str
            and re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)",
                request[field],
            )
        )
    issued, expires = (
        datetime.fromisoformat(request[k].replace("Z", "+00:00"))
        for k in ("issued_at", "expires_at")
    )
    _require(
        issued.utcoffset() == expires.utcoffset() == timezone.utc.utcoffset(issued)
    )
    _require(issued <= now < expires and 0 < (expires - issued).total_seconds() <= 300)
    fs = request["filesystem"]
    _require(
        type(fs) is dict and set(fs) == {"root", "collection", "info", "candidate"}
    )
    for name, count in (("root", 6), ("collection", 6), ("info", 9), ("candidate", 9)):
        values = fs[name]
        if name == "candidate" and values is None:
            continue
        _require(type(values) is list and len(values) == count)
        _require(
            all(
                type(v) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", v)
                for v in values
            )
        )


async def execute_request(
    request,
    *,
    root,
    owner_uid,
    runtime_target,
    approved_sha256,
    artifact_sha256,
    approved_scopes,
    signing_override,
    now,
):
    """Trusted, in-process capability boundary; request alone authorizes nothing.

    The fresh-process entry owns environment controls and authenticates runtime
    identifiers. ``root`` is supplied by reviewed code, never a wire path.
    Protected policy/approval and transport attestation are the caller's duties.
    """
    started = time.monotonic()
    try:
        _validate(request, approved_sha256, artifact_sha256, approved_scopes, now)
    except Exception:
        return _result(None, "invalid_request")
    _USED.add(request["request_id"])
    if not _same_target(runtime_target):
        return _result(request, "target_mismatch")
    if type(signing_override) is not str or not signing_override.strip():
        return _result(request, "runtime_key_unavailable")
    try:
        from importlib.metadata import version
        import sys

        if sys.version_info[:2] != (3, 11):
            return _result(request, "unsupported_runtime")

        if any(
            version(p) != v
            for p, v in {
                "fastmcp": "3.2.4",
                "mcp": "1.27.0",
                "py-key-value-aio": "0.4.4",
            }.items()
        ):
            return _result(request, "unsupported_runtime")
        # Genuine imports: standalone callers must install process controls first.
        from cryptography.fernet import Fernet
        from fastmcp.server.auth.jwt_issuer import derive_jwt_key
        from fastmcp.server.auth.oauth_proxy import models  # noqa: F401

        try:
            import oauth_client_inspection as inspection
        except ModuleNotFoundError:
            from core import oauth_client_inspection as inspection

        _require(
            Path(inspection.__file__).resolve()
            == Path(__file__).with_name(SOURCE_NAMES[1]).resolve()
        )

        jwt_key = derive_jwt_key(
            low_entropy_material=signing_override.strip(),
            salt="fastmcp-jwt-signing-key",
        )
        storage_key = derive_jwt_key(
            high_entropy_material=jwt_key.decode(),
            salt="fastmcp-storage-encryption-key",
        )
        cipher = Fernet(storage_key)
        expected = inspection.ExpectedClient(
            TARGET["client_id"],
            TARGET["client_name"],
            TARGET["callback"],
            tuple(approved_scopes),
        )
        with ExitStack() as stack:
            reader = inspection._ExactReader(stack, root, owner_uid)
            info_name = TARGET["collection"] + "-info.json"
            reader.read(reader.root_fd, info_name, False)
            collection = reader.collection()
            candidate = TARGET["client_id"] + ".json"
            fs = request["filesystem"]
            _require(
                [str(v) for v in inspection._identity(os.fstat(reader.root_fd))]
                == fs["root"]
            )
            _require(
                [str(v) for v in inspection._identity(os.fstat(collection))]
                == fs["collection"]
            )
            _require(
                [
                    str(v)
                    for v in inspection._file_identity(
                        os.stat(info_name, dir_fd=reader.root_fd, follow_symlinks=False)
                    )
                ]
                == fs["info"]
            )
            present = True
            try:
                reader.read(collection, candidate, True)
            except FileNotFoundError:
                present = False
            if present:
                _require([str(v) for v in reader.bindings[-1][3]] == fs["candidate"])
            else:
                _require(fs["candidate"] is None)
            observation = await inspection.inspect_client(
                root=root, owner_uid=owner_uid, expected=expected, fernet=cipher
            )
            reader.verify()
            registration = observation["registration"]
            if registration != "matched" or request["mode"] == "inspect":
                classification = (
                    registration if registration in RESULTS else "filesystem_changed"
                )
                return _result(request, classification)
            # A record observed only by the independent inspector is not the
            # initial descriptor-bound candidate approved for this retirement.
            _require(present and fs["candidate"] is not None)
            # This validates the same authenticated snapshot immediately before
            # unlink. POSIX has no atomic compare-inode-and-unlink: coordinated
            # writers are required. An advisory lock cannot stop other writers.
            expires = datetime.fromisoformat(
                request["expires_at"].replace("Z", "+00:00")
            )
            if time.monotonic() - started >= (expires - now).total_seconds():
                return _result(None, "invalid_request")
            reader.verify()
            try:
                os.unlink(candidate, dir_fd=collection)
                os.fsync(collection)
                reader.bindings.pop()  # removed candidate; validate other mappings
                # APFS directory nlink counts files too. Permit exactly the
                # decrement caused by this unlink, retaining all other fields.
                parent, name, fd, original = reader.bindings[-1]
                current = inspection._identity(os.fstat(fd))
                if current == (*original[:-1], original[-1] - 1):
                    reader.bindings[-1] = (parent, name, fd, current)
                reader.verify()
                try:
                    os.stat(candidate, dir_fd=collection, follow_symlinks=False)
                except FileNotFoundError:
                    return _result(request, "retired_verified")
                return _result(request, "uncertain")
            except Exception:
                return _result(request, "uncertain")
    except Exception:
        return _result(request, "filesystem_changed")


def _same_target(target):
    return (
        type(target) is dict
        and set(target) == set(TARGET)
        and all(
            type(target[k]) is type(v) and target[k] == v for k, v in TARGET.items()
        )
    )


def parse_result(raw, request):
    """Validate bounded transport output; authentication remains transport-owned."""
    _require(type(raw) is bytes and len(raw) <= 4096)
    result = strict_json(raw)
    _require(set(result) == {"request_id", "target", "mode", "result", "related_state"})
    _require(_same_target(result["target"]) and result["related_state"] == "unknown")
    _require(result["result"] in RESULTS)
    if result["result"] == "invalid_request":
        _require(result["request_id"] is None and result["mode"] is None)
    else:
        _require(
            result["request_id"] == request["request_id"]
            and result["mode"] == request["mode"]
        )
    _require(
        not (result["result"] == "retired_verified" and result["mode"] != "retire")
    )
    return result


async def process_request(request, context, *, root, owner_uid, now):
    """Fresh controlled process: read only necessary runtime environment fields.

    Context must arrive via the authenticated operator channel. Environment IDs
    are a consistency check, not cryptographic attestation. Volume identity and
    protected approval remain outer controller responsibilities.
    """
    try:
        _require(
            type(context) is dict
            and set(context)
            == {"approval_sha256", "artifact_sha256", "scopes", "runtime_target"}
        )
        _validate(
            request,
            context["approval_sha256"],
            context["artifact_sha256"],
            context["scopes"],
            now,
        )
    except Exception:
        return _result(None, "invalid_request")
    runtime = dict(context["runtime_target"])
    for field in ("project_id", "environment_id", "service_id", "deployment_id"):
        runtime[field] = os.environ.get("RAILWAY_" + field.upper())
    runtime["source_commit"] = os.environ.get("RAILWAY_GIT_COMMIT_SHA")
    disk = os.environ.get("WORKSPACE_MCP_OAUTH_PROXY_DISK_DIRECTORY", "").strip()
    if not disk:
        home = os.environ.get("FASTMCP_HOME", "").strip()
        disk = home + "/oauth-proxy" if home else None
    if (
        not _same_target(context["runtime_target"])
        or not _same_target(runtime)
        or os.environ.get("WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND", "")
        .strip()
        .lower()
        != "disk"
        or os.environ.get("WORKSPACE_MCP_OAUTH_PROXY_VALKEY_HOST", "").strip()
        or disk != TARGET["root"]
    ):
        return _result(request, "target_mismatch")
    # Never fall back to upstream client secret, dotenv or a credential file.
    signing = os.environ.get("FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY", "")
    return await execute_request(
        request,
        root=root,
        owner_uid=owner_uid,
        runtime_target=runtime,
        approved_sha256=context["approval_sha256"],
        artifact_sha256=context["artifact_sha256"],
        approved_scopes=context["scopes"],
        signing_override=signing,
        now=now,
    )


def main():
    """Fixed staged entry. No arbitrary arguments, commands, paths or credentials."""
    output = controlled_runtime()
    result = _result(None, "invalid_request")
    stage = None
    try:
        import asyncio
        import sys

        _require(len(sys.argv) == 1 and os.geteuid() == 0)
        _require(
            sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site
        )
        context = strict_json(sys.stdin.buffer.read(16385))
        _require(
            set(context)
            == {
                "approval_sha256",
                "artifact_sha256",
                "scopes",
                "runtime_target",
                "stage_identity",
                "stage_files",
            }
        )
        stage = StagedBundle.__new__(StagedBundle)
        stage.path = Path(__file__).absolute().parent
        _require(
            stage.path.parent == Path("/tmp")
            and re.fullmatch(r"oauth-client-maintenance-[a-z0-9_]{8}", stage.path.name)
        )
        stage.owner_uid = 0
        stage.fd = os.open(stage.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stage.identity = tuple(context.pop("stage_identity"))
        files = context.pop("stage_files")
        _require(type(files) is dict and set(files) == set(STAGE_NAMES))
        stage.files = {
            name: (tuple(values[0]), *values[1:]) for name, values in files.items()
        }
        snapshot = stage.verify()
        _require(_source_digest(snapshot) == context["artifact_sha256"])
        request = strict_json(snapshot["request.json"])
        stage.verify()
        _validate(
            request,
            context["approval_sha256"],
            context["artifact_sha256"],
            context["scopes"],
            datetime.now(timezone.utc),
        )
        if sys.version_info[:2] != (3, 11):
            result = _result(request, "unsupported_runtime")
            return
        # -S suppresses site/.pth startup before controls. Only this canonical
        # Python 3.11 dependency directory is added; do not call site.addsitedir.
        sys.path.append("/app/.venv/lib/python3.11/site-packages")
        # Isolated Python omits the script directory. Add only the already
        # validated, root-owned stage to import the reviewed inspector sibling.
        sys.path.insert(0, str(stage.path))
        result = asyncio.run(
            process_request(
                request,
                context,
                root=Path(TARGET["root"]),
                owner_uid=0,
                now=datetime.now(timezone.utc),
            )
        )
    except BaseException:
        pass
    finally:
        if stage is not None and hasattr(stage, "fd"):
            os.close(stage.fd)
        os.write(output, json.dumps(result, separators=(",", ":")).encode() + b"\n")
        os.close(output)


if __name__ == "__main__":
    main()
