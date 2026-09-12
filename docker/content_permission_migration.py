"""Content-only Linux metadata bootstrap. No record-data reads or live test mode.

The packaged protected entrypoint accepts only strict non-secret data under -I -S.
Provider exclusivity and exact command acceptance are external release gates.
All failure messages are fixed classifications; never emit underlying exceptions.
"""

import argparse
import hashlib
import ctypes
import errno
import fcntl
import json
import os
import pwd
import re
import signal
import stat
import sys
import time

IMAGE_RE = r"ghcr\.io/jazzli/google_workspace_mcp@sha256:[0-9a-f]{64}"
UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
FIELDS = (
    "operation_id",
    "mutate_until",
    "project_id",
    "environment_id",
    "service_id",
    "volume_id",
    "runtime_image",
    "migration_image",
    "helper_sha256",
    "manifest_sha256",
)
LAUNCHER = "/opt/mcp-runtime/runtime_launcher.py"
AT_EMPTY_PATH = 0x1000
MAX_JOURNAL = 1024 * 1024
MAX_ENTRIES = 512
_LIBC = ctypes.CDLL(None, use_errno=True)


class BootstrapError(Exception):
    """A fixed, non-sensitive failure classification."""


def _require(condition, code):
    if not condition:
        raise BootstrapError(code)


class Deadline:
    def __init__(self, seconds):
        self.end = time.monotonic() + seconds

    def check(self):
        _require(time.monotonic() < self.end, "deadline-exceeded")


def _install_signals(deadline):
    def stop(signum, frame):
        raise BootstrapError("bootstrap-interrupted")

    for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, deadline.end - time.monotonic()))


def _config(config):
    _require(type(config) is dict and set(config) == set(FIELDS), "invalid-config")
    for key in (
        "operation_id",
        "project_id",
        "environment_id",
        "service_id",
        "volume_id",
    ):
        _require(
            type(config[key]) is str and re.fullmatch(UUID_RE, config[key]),
            "invalid-identifier",
        )
    for key in ("runtime_image", "migration_image"):
        _require(
            type(config[key]) is str and re.fullmatch(IMAGE_RE, config[key]),
            "invalid-image",
        )
    _require(config["runtime_image"] != config["migration_image"], "invalid-image-pair")
    for key in ("helper_sha256", "manifest_sha256"):
        _require(
            type(config[key]) is str and re.fullmatch(r"[0-9a-f]{64}", config[key]),
            "invalid-hash",
        )
    # Expiry is syntactic here: completed operations may restart after expiry.
    _require(
        type(config["mutate_until"]) is int
        and 0 < config["mutate_until"] < 100000000000,
        "invalid-expiry",
    )
    manifest = {k: v for k, v in config.items() if k != "manifest_sha256"}
    digest = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    _require(digest == config["manifest_sha256"], "manifest-mismatch")
    return dict(config)


def _fresh(config):
    _require(0 < config["mutate_until"] - time.time() <= 1800, "mutation-window-closed")


def _target(config):
    return {
        "RAILWAY_" + key.upper(): config[key]
        for key in ("project_id", "environment_id", "service_id", "volume_id")
    } | {"RAILWAY_VOLUME_MOUNT_PATH": "/data"}


def _validate_binding(config, environment):
    _require(
        all(environment.get(k) == v for k, v in _target(config).items()), "wrong-target"
    )
    _protected(__file__)
    _require(
        hashlib.sha256(_read_bounded(__file__, 131072)).hexdigest()
        == config["helper_sha256"],
        "helper-hash-mismatch",
    )


def parse_config(argv):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise BootstrapError("invalid-arguments")

    # Only --flag value syntax; duplicate, abbreviated or alternate forms fail.
    _require(type(argv) is list and len(argv) == len(FIELDS) * 2, "invalid-arguments")
    expected = {"--" + field.replace("_", "-") for field in FIELDS}
    flags = argv[::2]
    _require(
        set(flags) == expected
        and len(flags) == len(set(flags))
        and all(type(v) is str and len(v) <= 256 for v in argv),
        "invalid-arguments",
    )
    parser = Parser(add_help=False, allow_abbrev=False)
    for field in FIELDS:
        parser.add_argument("--" + field.replace("_", "-"), required=True)
    config = vars(parser.parse_args(argv))
    _require(
        re.fullmatch(r"[1-9][0-9]{0,10}", config["mutate_until"]), "invalid-expiry"
    )
    config["mutate_until"] = int(config["mutate_until"])
    return _config(config)


def _read_bounded(path, maximum):
    # Only trusted procfs metadata and root-only journal bytes use readable FDs.
    with open(path, "rb") as handle:
        value = handle.read(maximum + 1)
    _require(len(value) <= maximum, "inspection-limit")
    return value


def _mount_id(fd):
    data = _read_bounded("/proc/self/fdinfo/" + str(fd), 4096)
    values = re.findall(rb"^mnt_id:\s*(\d+)$", data, re.M)
    _require(len(values) == 1, "mount-unqualified")
    return int(values[0])


def _meta(info):
    return [info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]


def _identity(info):
    return [info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)]


def _xattrs(fd):
    # procfs magic-link resolves the held O_PATH descriptor, not a record name.
    # listxattr performs metadata inspection and never opens the file for data.
    _require(not os.listxattr(_proc_descriptor(fd)), "unsupported-xattrs")


def _proc_descriptor(fd):
    buffer = ctypes.create_string_buffer(256)
    _require(
        _LIBC.statfs(ctypes.c_char_p(b"/proc/self/fd"), ctypes.byref(buffer)) == 0
        and ctypes.cast(buffer, ctypes.POINTER(ctypes.c_long))[0] == 0x9FA0,
        "procfs-unqualified",
    )
    info = os.fstat(fd)
    _require(not stat.S_ISLNK(info.st_mode), "unsafe-entry")
    path = "/proc/self/fd/" + str(fd)
    _require(_identity(os.stat(path)) == _identity(info), "descriptor-drift")
    return path


class Inventory:
    def __init__(self):
        self.entries = []
        self.fds = []

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()

    def validate(self, entry, expected=None):
        # Check the full held parent chain, then the direct name and descriptor.
        parent = entry["parent_entry"]
        if parent is not None:
            self.validate(parent)
        else:
            anchor = os.open(
                self.anchor_path,
                os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                _require(
                    _identity(os.fstat(anchor)) == self.anchor_identity
                    and _mount_id(anchor) == entry["mount"]
                    and _meta(os.fstat(anchor)) == [0, 0, 0o755],
                    "data-root-drift",
                )
            finally:
                os.close(anchor)
        fd = entry["fd"]
        current = os.fstat(fd)
        named = os.open(
            entry["name"],
            os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=entry["parent_fd"],
        )
        try:
            _require(
                _identity(current) == entry["identity"] == _identity(os.fstat(named)),
                "entry-drift",
            )
            _require(_mount_id(named) == entry["mount"], "mount-drift")
        finally:
            os.close(named)
        _require(_mount_id(fd) == entry["mount"], "mount-drift")
        _require(
            stat.S_ISDIR(current.st_mode)
            or (stat.S_ISREG(current.st_mode) and current.st_nlink == 1),
            "unsafe-entry",
        )
        _xattrs(fd)
        if expected is not None:
            _require(_meta(current) == expected, "metadata-drift")


def _inventory(root, deadline):
    result = Inventory()
    try:
        parent_path, root_name = os.path.split(root)
        parent_fd = os.open(
            parent_path, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        result.fds.append(parent_fd)
        result.anchor_path = parent_path
        result.anchor_identity = _identity(os.fstat(parent_fd))
        root_mount = _mount_id(parent_fd)

        def visit(parent, name, relative, depth, parent_entry):
            deadline.check()
            _require(
                depth <= 8 and len(result.entries) < MAX_ENTRIES, "inventory-limit"
            )
            _require(len(os.fsencode(relative)) <= 4096, "inventory-limit")
            fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            result.fds.append(fd)
            info = os.fstat(fd)
            is_dir = stat.S_ISDIR(info.st_mode)
            _require(is_dir or stat.S_ISREG(info.st_mode), "unsafe-entry")
            _require(is_dir or info.st_nlink == 1, "hardlink-rejected")
            _require(
                (info.st_uid, info.st_gid) in ((0, 0), (1000, 1000)), "unexpected-owner"
            )
            mode = stat.S_IMODE(info.st_mode)
            _require(not mode & 0o7000 and (is_dir or not mode & 0o111), "unsafe-mode")
            mount = _mount_id(fd)
            _require(mount == root_mount, "nested-mount")
            _xattrs(fd)
            entry = {
                "fd": fd,
                "parent_fd": parent,
                "parent_entry": parent_entry,
                "name": name,
                "relative": relative,
                "identity": _identity(info),
                "old": _meta(info),
                "target": [1000, 1000, 0o700 if is_dir else 0o600],
                "mount": mount,
            }
            result.entries.append(entry)
            result.validate(entry, entry["old"])
            if is_dir:
                directory = os.open(
                    ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd
                )
                try:
                    with os.scandir(directory) as children:
                        for child in children:
                            visit(
                                fd,
                                child.name,
                                child.name
                                if relative == "."
                                else relative + "/" + child.name,
                                depth + 1,
                                entry,
                            )
                finally:
                    os.close(directory)
            deadline.check()

        visit(parent_fd, root_name, ".", 0, None)
        return result
    except BaseException:
        result.__exit__()
        raise


def _chown(fd, uid, gid):
    _require(
        _LIBC.fchownat(fd, ctypes.c_char_p(b""), uid, gid, AT_EMPTY_PATH) == 0,
        "metadata-operation-failed",
    )


def _chmod(fd, mode):
    # fchmodat2 is ENOSYS under the cached amd64 image's local emulation. This
    # explicit metadata-only primitive dereferences a genuine procfs magic-link
    # to our still-held O_PATH descriptor; it never resolves a store pathname.
    before = _identity(os.fstat(fd))
    path = _proc_descriptor(fd)
    _require(
        _LIBC.fchmodat(-100, ctypes.c_char_p(path.encode("ascii")), mode, 0) == 0,
        "metadata-primitive-unsupported",
    )
    _require(
        _identity(os.fstat(fd)) == before and _identity(os.stat(path)) == before,
        "descriptor-drift",
    )


def _qualify_primitives(journal, deadline):
    deadline.check()
    _fresh(journal.config)
    # Empty disposable journal file, never a record. Exclusive creation ensures
    # a stale/uncertain probe blocks recovery instead of being overwritten.
    fd = os.open(
        "primitive-check",
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=journal.fd,
    )
    os.close(fd)
    pinned = os.open(
        "primitive-check", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=journal.fd
    )
    try:
        _chown(pinned, 1000, 1000)
        _chmod(pinned, 0o600)
        _require(
            _meta(os.fstat(pinned)) == [1000, 1000, 0o600],
            "metadata-primitive-unsupported",
        )
        _xattrs(pinned)
        _chown(pinned, 0, 0)
        _require(
            _meta(os.fstat(pinned)) == [0, 0, 0o600], "metadata-primitive-unsupported"
        )
        deadline.check()
    finally:
        os.close(pinned)
    os.unlink("primitive-check", dir_fd=journal.fd)
    os.fsync(journal.fd)


def _safe_directory(parent, name, create):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        else:
            os.fsync(parent)
    fd = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
    )
    info = os.fstat(fd)
    try:
        _require(
            _meta(info) == [0, 0, 0o700] and _mount_id(fd) == _mount_id(parent),
            "unsafe-journal",
        )
        _xattrs(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


class Journal:
    """Root-only journal. Pending history blocks; completed history is retained."""

    def __init__(self, base, config, inventory):
        self.fds, self.inventory = [], inventory
        self.document, self.completed = None, False
        self.config = _config(config)
        try:
            parent = os.open(
                base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            self.fds.append(parent)
            _require(_meta(os.fstat(parent)) == [0, 0, 0o755], "unsafe-data-root")
            try:
                journal_root = _safe_directory(
                    parent, ".content-permission-migration", False
                )
            except FileNotFoundError:
                _fresh(config)
                journal_root = _safe_directory(
                    parent, ".content-permission-migration", True
                )
            self.fds.append(journal_root)
            fcntl.flock(journal_root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            names = os.listdir(journal_root)
            _require(
                len(names) <= 16 and all(re.fullmatch(UUID_RE, n) for n in names),
                "journal-history-unqualified",
            )
            self.binding = {
                "config": config,
                "target": _target(config),
                "data": _identity(os.fstat(parent)),
            }
            # Read bounded history before even creating a new operation.
            # Pending/uncertain work cannot be bypassed with another UUID.
            for name in names:
                directory = _safe_directory(journal_root, name, False)
                try:
                    document = self._read(directory)
                    self.document = document
                    self._schema()
                    binding = document["binding"]
                    _require(
                        binding["target"] == self.binding["target"]
                        and binding["data"] == self.binding["data"]
                        and binding["config"]["operation_id"] == name,
                        "journal-binding-mismatch",
                    )
                    _require(document["status"] == "serving", "incomplete-journal")
                    if name == config["operation_id"]:
                        _require(binding == self.binding, "journal-binding-mismatch")
                finally:
                    os.close(directory)
            if config["operation_id"] in names:
                directory = _safe_directory(journal_root, config["operation_id"], False)
                self.fds.append(directory)
                self.fd = directory
                self.document = self._read(directory)
                self._schema()
                _require(
                    self.document["binding"] == self.binding
                    and self.document["status"] == "serving",
                    "journal-binding-mismatch",
                )
                self.completed = True
            else:
                _fresh(config)
                _require(len(names) < 16, "journal-history-limit")
                directory = _safe_directory(journal_root, config["operation_id"], True)
                self.fds.append(directory)
                self.fd = directory
                _require(not os.listdir(directory), "incomplete-journal")
                self.document = {
                    "version": 1,
                    "binding": self.binding,
                    "status": "pending",
                    "entries": [
                        {
                            "path": entry["relative"],
                            "identity": entry["identity"],
                            "old": entry["old"],
                            "target": entry["target"],
                            "state": "original",
                        }
                        for entry in inventory.entries
                    ],
                }
                self.save()
        except BaseException:
            self.__exit__()
            raise

    def _read(self, directory):
        _require(os.listdir(directory) == ["journal.json"], "incomplete-journal")
        fd = os.open(
            "journal.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
        )
        try:
            info = os.fstat(fd)
            _require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and _meta(info) == [0, 0, 0o600]
                and info.st_size <= MAX_JOURNAL
                and _mount_id(fd) == _mount_id(directory),
                "unsafe-journal",
            )
            _xattrs(fd)
            data = os.read(fd, MAX_JOURNAL + 1)
        finally:
            os.close(fd)

        def unique(pairs):
            result = {}
            for key, value in pairs:
                _require(key not in result, "invalid-journal")
                result[key] = value
            return result

        try:
            return json.loads(data, object_pairs_hook=unique)
        except (ValueError, UnicodeError):
            raise BootstrapError("invalid-journal") from None

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()

    def _schema(self):
        d = self.document
        _require(
            type(d) is dict
            and set(d) == {"version", "binding", "status", "entries"}
            and d["version"] == 1,
            "invalid-journal",
        )
        _require(
            d["status"] in ("pending", "serving", "undone")
            and type(d["entries"]) is list
            and 1 <= len(d["entries"]) <= MAX_ENTRIES,
            "invalid-journal",
        )
        binding = d["binding"]
        _require(
            type(binding) is dict and set(binding) == {"config", "target", "data"},
            "invalid-journal",
        )
        cfg = _config(binding["config"])
        _require(
            binding["target"] == _target(cfg)
            and type(binding["data"]) is list
            and len(binding["data"]) == 3
            and all(type(v) is int and v >= 0 for v in binding["data"]),
            "invalid-journal",
        )
        seen = set()
        for e in d["entries"]:
            _require(
                type(e) is dict
                and set(e) == {"path", "identity", "old", "target", "state"},
                "invalid-journal",
            )
            p = e["path"]
            _require(
                type(p) is str
                and len(os.fsencode(p)) <= 4096
                and p not in seen
                and (
                    p == "."
                    or (
                        not p.startswith("/")
                        and all(part not in ("", ".", "..") for part in p.split("/"))
                    )
                ),
                "invalid-journal",
            )
            seen.add(p)
            for field in ("identity", "old", "target"):
                _require(
                    type(e[field]) is list
                    and len(e[field]) == 3
                    and all(type(v) is int and v >= 0 for v in e[field]),
                    "invalid-journal",
                )
            _require(
                e["old"][:2] in ([0, 0], [1000, 1000])
                and e["old"][2] <= 0o777
                and e["target"] in ([1000, 1000, 0o700], [1000, 1000, 0o600])
                and e["identity"][2] in (stat.S_IFDIR, stat.S_IFREG)
                and e["state"]
                in (
                    "original",
                    "owner-intent",
                    "owner-done",
                    "mode-intent",
                    "done",
                    "undo-intent",
                    "undone",
                ),
                "invalid-journal",
            )
        _require(
            d["status"] != "serving" or all(e["state"] == "done" for e in d["entries"]),
            "invalid-journal",
        )

    def save(self):
        _require(not self.completed, "completed-read-only")
        _fresh(self.config)
        self._schema()
        payload = json.dumps(
            self.document, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")
        _require(len(payload) <= MAX_JOURNAL, "journal-limit")
        fd = os.open(
            "pending.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self.fd,
        )
        try:
            position = 0
            while position < len(payload):
                amount = os.write(fd, payload[position:])
                _require(amount > 0, "journal-write-failed")
                position += amount
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(
            "pending.json", "journal.json", src_dir_fd=self.fd, dst_dir_fd=self.fd
        )
        os.fsync(self.fd)

    def state(self, index, state):
        self.document["entries"][index]["state"] = state
        self.save()

    def serving(self):
        if not self.completed:
            _require(
                all(e["state"] == "done" for e in self.document["entries"]),
                "incomplete-journal",
            )
            self.document["status"] = "serving"
            self.save()


def _migrate(entries, journal, deadline):
    if journal.completed:
        for entry in entries.entries:
            deadline.check()
            entries.validate(entry, entry["target"])
        return
    _require(
        journal.document["status"] == "pending"
        and all(e["state"] == "original" for e in journal.document["entries"]),
        "incomplete-journal",
    )
    _fresh(journal.config)
    _qualify_primitives(journal, deadline)
    # Full prevalidation before the first mutation; individual revalidation still
    # occurs around each effect. Provider exclusive writer evidence is required.
    for entry in entries.entries:
        deadline.check()
        entries.validate(entry, entry["old"])
    for index, entry in enumerate(entries.entries):
        deadline.check()
        entries.validate(entry, entry["old"])
        journal.state(index, "owner-intent")
        deadline.check()
        entries.validate(entry, entry["old"])
        _fresh(journal.config)
        _chown(entry["fd"], 1000, 1000)
        intermediate = [1000, 1000, entry["old"][2]]
        entries.validate(entry, intermediate)
        journal.state(index, "owner-done")
        journal.state(index, "mode-intent")
        deadline.check()
        entries.validate(entry, intermediate)
        _fresh(journal.config)
        _chmod(entry["fd"], entry["target"][2])
        entries.validate(entry, entry["target"])
        journal.state(index, "done")
    for entry in entries.entries:
        deadline.check()
        entries.validate(entry, entry["target"])


def _undo(entries, journal, deadline):
    # Only a still-held inventory can be undone. Never reconstruct or replay
    # from an old journal; never call this after the persisted serving boundary.
    _require(
        not journal.completed and journal.document["status"] == "pending",
        "undo-forbidden",
    )
    for index in reversed(range(len(entries.entries))):
        deadline.check()
        entry = entries.entries[index]
        state = journal.document["entries"][index]["state"]
        _require(state in ("original", "owner-done", "done"), "undo-uncertain")
        expected = (
            entry["old"]
            if state == "original"
            else (
                [1000, 1000, entry["old"][2]]
                if state == "owner-done"
                else entry["target"]
            )
        )
        entries.validate(entry, expected)
    for index in reversed(range(len(entries.entries))):
        deadline.check()
        entry = entries.entries[index]
        state = journal.document["entries"][index]["state"]
        if state == "original":
            continue
        expected = (
            [1000, 1000, entry["old"][2]] if state == "owner-done" else entry["target"]
        )
        entries.validate(entry, expected)
        journal.state(index, "undo-intent")
        deadline.check()
        entries.validate(entry, expected)
        _fresh(journal.config)
        _chown(entry["fd"], *entry["old"][:2])
        entries.validate(entry, entry["old"][:2] + [expected[2]])
        deadline.check()
        _fresh(journal.config)
        _chmod(entry["fd"], entry["old"][2])
        entries.validate(entry, entry["old"])
        journal.state(index, "undone")
    journal.document["status"] = "undone"
    journal.save()


def _protected(path):
    # realpath is used only for immutable image-code paths, never store entries.
    root = os.stat("/")
    _require(
        root.st_uid == 0
        and root.st_gid == 0
        and not stat.S_IMODE(root.st_mode) & 0o022,
        "unprotected-code",
    )
    for variant in (path, os.path.realpath(path)):
        cursor = "/"
        for component in variant.split("/"):
            if not component:
                continue
            cursor = os.path.join(cursor, component)
            info = os.stat(cursor)
            _require(
                info.st_uid == 0
                and info.st_gid == 0
                and not stat.S_IMODE(info.st_mode) & 0o022,
                "unprotected-code",
            )


def _protected_tree(root, deadline):
    _protected(root)
    count = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            deadline.check()
            count += 1
            _require(count <= 100000, "code-inspection-limit")
            path = os.path.join(directory, name)
            if path == "/app/store_creds":
                # Pinned image Dockerfile explicitly creates this empty data
                # directory. It is not an application code/import ancestor.
                # No other writable descendant receives this exception.
                parent = os.open(
                    "/app", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                )
                try:
                    _empty_image_data_directory(parent, name)
                finally:
                    os.close(parent)
                if name in dirs:
                    dirs.remove(name)
            else:
                _protected(path)


def _empty_image_data_directory(parent, name):
    fd = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
    )
    try:
        _require(
            _meta(os.fstat(fd)) == [1000, 1000, 0o700]
            and _mount_id(fd) == _mount_id(parent),
            "image-data-unqualified",
        )
        _xattrs(fd)
        with os.scandir(fd) as children:
            _require(next(children, None) is None, "image-data-unqualified")
    finally:
        os.close(fd)


def _processes(deadline):
    count = 0
    # A bootstrap must itself be PID 1. No launcher/supervisor is accepted.
    _require(os.getpid() == 1, "unexpected-supervisor")
    for name in os.listdir("/proc"):
        if name.isdecimal():
            deadline.check()
            count += 1
            _require(count <= 128 and int(name) == os.getpid(), "competing-process")


def _app_argv(env):
    argv = ["/app/.venv/bin/python", "-B", "main.py", "--transport", "streamable-http"]
    tier, tools = env.get("TOOL_TIER", ""), env.get("TOOLS", "")
    _require(
        type(tier) is str
        and type(tools) is str
        and len(tier) <= 128
        and len(tools) <= 4096,
        "tool-selection-unqualified",
    )
    if tier:
        _require(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", tier),
            "tool-selection-unqualified",
        )
        argv += ["--tool-tier", tier]
    if tools:
        # Accepted image uses unquoted shell field expansion for TOOLS. Support
        # its ordinary whitespace-separated identifiers, rejecting glob syntax.
        selected = re.split(r"[ \t\n]+", tools.strip(" \t\n"))
        _require(
            all(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", value) for value in selected
            ),
            "tool-selection-unqualified",
        )
        argv += ["--tools"] + selected
    return argv


def _prctl(option, value=0):
    _require(
        _LIBC.prctl(option, ctypes.c_ulong(value), 0, 0, 0) == 0,
        "privilege-drop-failed",
    )


def _inherited_fds(deadline):
    # Current limits do not bound already-open descriptors. Enumerate genuine
    # procfs, then exclude enumeration descriptors after their contexts close.
    directory = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    observed = []
    try:
        _proc_descriptor(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                deadline.check()
                _require(
                    entry.name.isdecimal() and len(observed) < 1048576,
                    "fd-inspection-unqualified",
                )
                observed.append(int(entry.name))
    finally:
        os.close(directory)
    inherited = []
    for fd in observed:
        deadline.check()
        if fd < 3:
            continue
        try:
            os.fstat(fd)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            inherited.append(fd)
    return inherited


def _drop_privileges(deadline):
    try:
        deadline.check()
        os.umask(0o077)
        _prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
        _prctl(47, 4)  # PR_CAP_AMBIENT_CLEAR_ALL
        last = int(_read_bounded("/proc/sys/kernel/cap_last_cap", 32))
        _require(0 <= last <= 63, "capability-unqualified")
        for capability in range(last + 1):
            _prctl(24, capability)  # bounding set
        os.setgroups([1000])
        os.setresgid(1000, 1000, 1000)
        os.setresuid(1000, 1000, 1000)

        class Header(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

        class Data(ctypes.Structure):
            _fields_ = [
                ("effective", ctypes.c_uint32),
                ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32),
            ]

        header, data = Header(0x20080522, 0), (Data * 2)()
        _require(
            _LIBC.capset(ctypes.byref(header), ctypes.byref(data)) == 0,
            "privilege-drop-failed",
        )
        _require(
            os.getresuid() == (1000, 1000, 1000)
            and os.getresgid() == (1000, 1000, 1000)
            and os.getgroups() == [1000],
            "privilege-drop-failed",
        )
        status = _read_bounded("/proc/self/status", 32768)
        for label in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
            found = re.findall(rb"^" + label + rb":\s*([0-9a-f]+)$", status, re.M)
            _require(
                len(found) == 1 and int(found[0], 16) == 0, "privilege-drop-failed"
            )
        _require(
            re.search(rb"^NoNewPrivs:\s*1$", status, re.M), "privilege-drop-failed"
        )
        # Preserve only non-file standard I/O. A root-opened regular file or
        # directory in stdio is unacceptable even if later marked CLOEXEC.
        for fd in (0, 1, 2):
            info = os.fstat(fd)
            _require(
                stat.S_ISFIFO(info.st_mode)
                or stat.S_ISSOCK(info.st_mode)
                or (stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3)),
                "privileged-stdio",
            )
        for fd in _inherited_fds(deadline):
            deadline.check()
            os.close(fd)
        _require(not _inherited_fds(deadline), "privileged-fd-retained")
        deadline.check()
    except BootstrapError:
        raise
    except (OSError, ValueError):
        raise BootstrapError("privilege-drop-failed") from None


def _preflight(config, deadline):
    _require(
        sys.platform == "linux" and sys.flags.isolated and sys.flags.no_site,
        "interpreter-unqualified",
    )
    _require(os.getresuid() == (0, 0, 0), "bootstrap-requires-root")
    _validate_binding(config, os.environ)
    account = pwd.getpwnam("app")
    _require(
        (account.pw_uid, account.pw_gid, account.pw_dir) == (1000, 1000, "/home/app")
        and os.environ.get("HOME") == "/home/app",
        "home-account-unqualified",
    )
    _require(os.getcwd() == "/app", "wrong-working-directory")
    _processes(deadline)
    mountinfo = _read_bounded("/proc/self/mountinfo", 1024 * 1024).splitlines()
    _require(len(mountinfo) <= 4096, "mount-inspection-limit")
    mounts = [line.split() for line in mountinfo]
    _require(
        sum(fields[4] == b"/data" for fields in mounts) == 1
        and not any(fields[4].startswith(b"/data/") for fields in mounts),
        "mount-unqualified",
    )
    fd = os.open("/data", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _require(_meta(os.fstat(fd)) == [0, 0, 0o755], "unsafe-data-root")
        _require(
            any(
                int(fields[0]) == _mount_id(fd) and fields[4] == b"/data"
                for fields in mounts
            ),
            "mount-unqualified",
        )
        _xattrs(fd)
    finally:
        os.close(fd)
    for path in (
        LAUNCHER,
        __file__,
        "/usr/local/bin/python3.11",
        "/usr/local/lib/python3.11",
        "/app/.venv/bin/python",
        "/app/main.py",
    ):
        _protected(path)
    _protected_tree("/app", deadline)
    _protected_tree("/usr/local/lib/python3.11", deadline)
    _require(
        os.path.realpath(sys.executable) == "/usr/local/bin/python3.11",
        "interpreter-unqualified",
    )
    return _app_argv(os.environ)


def run(config):
    """Verify a bound mounted store, migrate if fresh, drop, then exec R run.

    The external coordinator must verify image identity and exclusive writers.
    Pending journals require separately authorized reconciliation, not replay.
    """
    try:
        config = _config(config)
        deadline = Deadline(120)
        _install_signals(deadline)
        inspection = Deadline(30)
        signal.setitimer(
            signal.ITIMER_REAL, max(0.001, inspection.end - time.monotonic())
        )
        _preflight(config, inspection)
        with _inventory("/data/oauth-proxy", inspection) as entries:
            signal.setitimer(
                signal.ITIMER_REAL, max(0.001, deadline.end - time.monotonic())
            )
            with Journal("/data", config, entries) as journal:
                _migrate(entries, journal, deadline)
                deadline.check()
                journal.serving()
        _drop_privileges(deadline)
        deadline.check()
        signal.setitimer(signal.ITIMER_REAL, 0)
        os.execv(
            "/usr/local/bin/python3.11",
            ["/usr/local/bin/python3.11", "-I", "-S", LAUNCHER, "run"],
        )
    except BootstrapError:
        raise
    except BaseException:
        raise BootstrapError("bootstrap-failed") from None


if __name__ == "__main__":
    try:
        run(parse_config(sys.argv[1:]))
    except BootstrapError as error:
        print("migration-refused:" + str(error), file=sys.stderr)
        sys.exit(1)
    except BaseException:
        print("migration-refused:bootstrap-failed", file=sys.stderr)
        sys.exit(1)
