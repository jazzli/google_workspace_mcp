"""Exact-client, read-only adapter for the application's pinned encrypted disk store.

No CLI, environment lookup, server startup, listing, deletion or credential
loader is provided. A separately reviewed caller must supply verified runtime
identity, protected expectations and an in-process storage Fernet instance.
Results are observations, never absence/revocation proofs or cleanup authority.
"""

import json
import os
import re
import stat
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime
from importlib.metadata import version
from pathlib import Path
from uuid import UUID

from cryptography.fernet import Fernet
from key_value.aio._utils.serialization import BasicSerializationAdapter
from key_value.aio.adapters.pydantic import PydanticAdapter
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

COLLECTION = "mcp-oauth-proxy-clients"
MAX_BYTES = 65536
PINNED = {"fastmcp": "3.2.4", "mcp": "1.27.0", "py-key-value-aio": "0.4.4"}


@dataclass(frozen=True)
class ExpectedClient:
    client_id: str
    client_name: str
    callback: str
    scopes: tuple[str, ...]


class _Unsafe(Exception):
    pass


class _Invalid(Exception):
    pass


def _require(condition, error=_Unsafe):
    if not condition:
        raise error()


def _result(registration):
    # There is no client-ID index over related state in FastMCP 3.2.4.
    return {
        "registration": registration,
        "related_state": "unknown",
        "cleanup_ready": False,
    }


def _identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
    )


def _file_identity(info):
    return (*_identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _require(key not in value, _Invalid)
            value[key] = item
        return value

    value = json.loads(raw, object_pairs_hook=unique)
    _require(type(value) is dict, _Invalid)
    return value


class _ExactReader:
    """Descriptor-relative reads, no-follow on every component, no mutators."""

    def __init__(self, stack, root, uid):
        self.stack, self.uid = stack, uid
        self.bindings = []
        parent = self._open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in root.parts[1:]:
            child = self._open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, parent
            )
            self.bindings.append((parent, part, child, _identity(os.fstat(child))))
            parent = child
        self.root_fd = parent
        self._directory(parent)

    def _open(self, name, flags, parent=None):
        fd = os.open(name, flags, dir_fd=parent)
        self.stack.callback(os.close, fd)
        return fd

    def _directory(self, fd):
        info = os.fstat(fd)
        _require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == self.uid
            and not info.st_mode & 0o022
        )
        return info

    def collection(self):
        fd = self._open(
            COLLECTION, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, self.root_fd
        )
        info = self._directory(fd)
        self.bindings.append((self.root_fd, COLLECTION, fd, _identity(info)))
        return fd

    def read(self, parent, name, private):
        # NONBLOCK avoids hanging if an unexpected FIFO is substituted.
        fd = self._open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, parent)
        before = os.fstat(fd)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_uid == self.uid
        )
        mode = stat.S_IMODE(before.st_mode)
        _require(mode == 0o600 if private else mode in (0o600, 0o644))
        _require(0 < before.st_size <= MAX_BYTES)
        data = bytearray()
        while len(data) <= MAX_BYTES:
            chunk = os.read(fd, min(8192, MAX_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        _require(
            len(data) == before.st_size
            and _file_identity(before) == _file_identity(os.fstat(fd))
        )
        self.bindings.append((parent, name, fd, _file_identity(before)))
        return bytes(data)

    def verify(self):
        for parent, name, fd, original in self.bindings:
            identify = _identity if len(original) == 6 else _file_identity
            _require(identify(os.fstat(fd)) == original)
            _require(
                identify(os.stat(name, dir_fd=parent, follow_symlinks=False))
                == original
            )


class _OneValue:
    """Protocol-compatible single-key snapshot; all other operations refuse."""

    def __init__(self, client_id, value):
        self.client_id, self.value = client_id, value

    async def get(self, key, *, collection=None):
        _require(key == self.client_id and collection == COLLECTION)
        return self.value

    async def _deny(self, *args, **kwargs):
        raise _Unsafe()

    put = delete = get_many = put_many = delete_many = ttl = ttl_many = _deny


def _valid_input(root, uid, expected):
    _require(isinstance(root, Path))
    _require(root.is_absolute() and len(root.parts) > 1 and ".." not in root.parts)
    _require(type(uid) is int and uid >= 0 and isinstance(expected, ExpectedClient))
    _require(
        str(UUID(expected.client_id)) == expected.client_id
        and UUID(expected.client_id).version == 4
    )
    _require(type(expected.client_name) is str and 0 < len(expected.client_name) <= 200)
    _require(
        re.fullmatch(
            r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/oauth/callback", expected.callback
        )
        is not None
    )
    _require(int(expected.callback.split(":")[2].split("/")[0]) <= 65535)
    _require(type(expected.scopes) is tuple and 0 < len(expected.scopes) <= 100)
    _require(
        all(
            type(s) is str and re.fullmatch(r"[\x21\x23-\x5b\x5d-\x7e]{1,256}", s)
            for s in expected.scopes
        )
    )
    _require(len(set(expected.scopes)) == len(expected.scopes))


async def inspect_client(
    *, root: Path, owner_uid: int, expected: ExpectedClient, fernet: Fernet
):
    """Return fixed enums/boolean only; never return/log records or exceptions.

    Reads at most the exact collection info and one client file. Even a missing
    candidate is not proof of registration absence: the key cannot be validated
    against a nonexistent record. Reads may update filesystem access times.
    """
    try:
        _valid_input(root, owner_uid, expected)
        _require(isinstance(fernet, Fernet))
    except Exception:
        return _result("invalid_input")
    try:
        if any(version(package) != pinned for package, pinned in PINNED.items()):
            return _result("unsupported_runtime")
        # Importing FastMCP constructs Settings and may read .env. Never do so
        # here. This adapter is only usable inside an already-initialized,
        # separately authorized provider runtime (or a synthetic test runtime).
        models = sys.modules.get("fastmcp.server.auth.oauth_proxy.models")
        model = getattr(models, "ProxyDCRClient", None)
        if model is None:
            return _result("unsupported_runtime")
        with ExitStack() as stack:
            reader = _ExactReader(stack, root, owner_uid)
            try:
                info = _json(
                    reader.read(reader.root_fd, f"{COLLECTION}-info.json", False)
                )
                _require(
                    set(info) == {"version", "collection", "directory", "created_at"}
                )
                _require(type(info.get("version")) is int and info["version"] == 1)
                _require(info.get("collection") == COLLECTION)
                _require(info.get("directory") == str(root / COLLECTION))
                # Same pure parser as DiskCollectionInfo.from_dict, without the
                # create_or_get_info path that can write metadata.
                _require(type(info["created_at"]) is str)
                datetime.fromisoformat(info["created_at"])
            except Exception:
                return _result("unreadable_or_unsafe")
            collection = reader.collection()
            try:
                raw = reader.read(collection, f"{expected.client_id}.json", True)
            except FileNotFoundError:
                reader.verify()
                return _result("candidate_missing")
            try:
                body = _json(raw)
                _require(
                    set(body) <= {"version", "value", "created_at", "expires_at"},
                    _Invalid,
                )
                _require(
                    type(body.get("version")) is int and body["version"] == 1, _Invalid
                )
                entry = BasicSerializationAdapter().load_dict(body)
                # DCR put has no TTL; do not filter or garbage-collect expired data.
                _require(entry.expires_at is None, _Invalid)
                payload = entry.value_as_dict
                _require(
                    set(payload) == {"__encrypted_data__", "__encryption_version__"},
                    _Invalid,
                )
                _require(
                    type(payload["__encryption_version__"]) is int
                    and payload["__encryption_version__"] == 1,
                    _Invalid,
                )
                adapter = PydanticAdapter(
                    key_value=FernetEncryptionWrapper(
                        key_value=_OneValue(expected.client_id, payload),
                        fernet=fernet,
                        raise_on_decryption_error=True,
                    ),
                    pydantic_model=model,
                    default_collection=COLLECTION,
                    raise_on_validation_error=True,
                )
                client = await adapter.get(expected.client_id)
                _require(client is not None, _Invalid)
                scopes = (client.scope or "").split()
                matches = (
                    client.client_id == expected.client_id
                    and client.client_name == expected.client_name
                    and [str(uri) for uri in client.redirect_uris or []]
                    == [expected.callback]
                    and client.token_endpoint_auth_method == "none"
                    and client.client_secret is None
                    and client.cimd_document is None
                    and len(scopes) == len(set(scopes))
                    and set(scopes) == set(expected.scopes)
                    and sorted(client.grant_types)
                    == ["authorization_code", "refresh_token"]
                )
            except Exception:
                return _result("invalid_record")
            reader.verify()
            return _result("matched" if matches else "mismatch")
    except Exception:
        return _result("unreadable_or_unsafe")
