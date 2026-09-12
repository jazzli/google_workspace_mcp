"""Protected stdlib-only launcher. Never repairs storage or elevates privileges.

The image defaults to run/1000:1000. root-compat requires an independently
selected root identity and is a temporary compatibility mode, not a retry.
"""

import ctypes
import errno
import os
import pwd
import re
import signal
import stat
import sys


class RuntimeBoundaryError(Exception):
    """Fixed classification only; do not expose underlying exceptions."""


def require(condition, code):
    if not condition:
        raise RuntimeBoundaryError(code)


def protected(path):
    for variant in (path, os.path.realpath(path)):
        cursor = "/"
        root = os.stat(cursor)
        require(
            root.st_uid == root.st_gid == 0 and not root.st_mode & 0o022,
            "unprotected-code",
        )
        for component in variant.split("/"):
            if not component:
                continue
            cursor = os.path.join(cursor, component)
            info = os.stat(cursor)
            require(
                info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
                "unprotected-code",
            )


def app_argv(env):
    argv = ["/app/.venv/bin/python", "-B", "main.py", "--transport", "streamable-http"]
    tier, tools = env.get("TOOL_TIER", ""), env.get("TOOLS", "")
    require(
        type(tier) is str
        and type(tools) is str
        and len(tier) <= 128
        and len(tools) <= 4096,
        "tool-selection-unqualified",
    )
    if tier:
        require(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", tier),
            "tool-selection-unqualified",
        )
        argv += ["--tool-tier", tier]
    if tools:
        selected = re.split(r"[ \t\n]+", tools.strip(" \t\n"))
        require(
            all(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", token) for token in selected
            ),
            "tool-selection-unqualified",
        )
        argv += ["--tools"] + selected
    return argv


def set_nnp():
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.prctl(38, ctypes.c_ulong(1), 0, 0, 0) == 0, "nnp-failed")


def _status():
    with open("/proc/self/status", "rb") as handle:
        data = handle.read(32769)
    require(len(data) <= 32768, "status-unqualified")
    return data


def _close_extra_fds():
    # Enumerating procfs finds inherited descriptors above a lowered rlimit.
    names = os.listdir("/proc/self/fd")
    require(
        len(names) <= 1048576 and all(name.isdecimal() for name in names),
        "fds-unqualified",
    )
    for name in names:
        fd = int(name)
        if fd < 3:
            continue
        try:
            os.close(fd)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def prepare(mode):
    require(mode in ("run", "root-compat"), "invalid-mode")
    require(sys.platform == "linux", "linux-required")
    account = pwd.getpwnam("app")
    require(
        (account.pw_uid, account.pw_gid, account.pw_dir) == (1000, 1000, "/home/app"),
        "account-unqualified",
    )
    if mode == "run":
        require(
            os.getresuid() == (1000, 1000, 1000)
            and os.getresgid() == (1000, 1000, 1000)
            and os.getgroups() == [1000],
            "nonroot-identity-required",
        )
    else:
        require(os.getresuid() == (0, 0, 0), "root-compat-requires-root")
    argv = app_argv(os.environ)
    for path in (
        "/usr/local/bin/python3.11",
        "/usr/local/lib/python3.11",
        "/opt/mcp-runtime/runtime_launcher.py",
        "/app/.venv/bin/python",
        "/app/.venv/lib/python3.11/site-packages",
        "/app/main.py",
    ):
        protected(path)
    for fd in (0, 1, 2):
        info = os.fstat(fd)
        require(
            stat.S_ISFIFO(info.st_mode)
            or stat.S_ISSOCK(info.st_mode)
            or (stat.S_ISCHR(info.st_mode) and info.st_rdev == os.makedev(1, 3)),
            "privileged-stdio",
        )
    set_nnp()
    status = _status()
    require(re.search(rb"^NoNewPrivs:\s*1$", status, re.M), "nnp-failed")
    if mode == "run":
        for label in (b"CapInh", b"CapPrm", b"CapEff", b"CapAmb"):
            found = re.findall(rb"^" + label + rb":\s*([0-9a-f]+)$", status, re.M)
            require(len(found) == 1 and int(found[0], 16) == 0, "active-capability")
    _close_extra_fds()
    os.environ["HOME"] = "/home/app"
    os.chdir("/app")
    os.umask(0o077)
    return argv


def main(argv):
    require(
        type(argv) is list and len(argv) == 1 and argv[0] in ("run", "root-compat"),
        "invalid-arguments",
    )
    require(
        sys.platform == "linux"
        and sys.version_info[:2] == (3, 11)
        and sys.flags.isolated
        and sys.flags.no_site
        and os.getpid() == 1,
        "interpreter-or-pid-unqualified",
    )
    require(
        os.path.realpath(sys.executable) == "/usr/local/bin/python3.11",
        "interpreter-unqualified",
    )

    def stop(signum, frame):
        raise RuntimeBoundaryError("startup-interrupted")

    for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    signal.setitimer(signal.ITIMER_REAL, 30)
    application = prepare(argv[0])
    signal.setitimer(signal.ITIMER_REAL, 0)
    os.execv(application[0], application)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except RuntimeBoundaryError as error:
        print("runtime-refused:" + str(error), file=sys.stderr)
        sys.exit(1)
    except BaseException:
        print("runtime-refused:startup-failed", file=sys.stderr)
        sys.exit(1)
