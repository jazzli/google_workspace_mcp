"""Stdlib Linux tests, with a bounded host-side disposable-container driver.

Run on the host with --image-id sha256:<cached-config-id>. No pulls, host
mounts, credentials, provider calls or published ports. The copied source is
unit-test input, not a qualified published image.
"""

import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

LAUNCHER = Path("/opt/mcp-runtime/runtime_launcher.py")


@unittest.skipUnless(
    sys.argv[1:] == ["--linux-unit"]
    and sys.platform == "linux"
    and os.geteuid() == 0
    and Path("/.dockerenv").is_file(),
    "explicit controlled Linux/root fixture invocation required",
)
class RuntimeTests(unittest.TestCase):
    def test_tool_names_cannot_become_application_options(self):
        for value in (
            "calendar --transport stdio",
            "calendar --single-user",
            "--",
            "calendar --tr stdio",
            "--help",
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(self.r.RuntimeBoundaryError),
            ):
                self.r.app_argv({"TOOLS": value})
        with self.assertRaises(self.r.RuntimeBoundaryError):
            self.r.app_argv({"TOOL_TIER": "--single-user"})

    def setUp(self):
        self.assertTrue(LAUNCHER.is_file(), "missing protected runtime launcher")
        spec = importlib.util.spec_from_file_location("runtime_launcher", LAUNCHER)
        self.r = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.r)

    def child(self, body, *, identity=True):
        pid = os.fork()
        if pid == 0:
            try:
                if identity:
                    os.setgroups([1000])
                    os.setresgid(1000, 1000, 1000)
                    os.setresuid(1000, 1000, 1000)
                body()
                os._exit(0)
            except BaseException as error:
                import traceback

                location = traceback.extract_tb(error.__traceback__)[-1].lineno
                classification = (
                    str(error)
                    if isinstance(error, self.r.RuntimeBoundaryError)
                    else type(error).__name__
                )
                print(
                    f"synthetic-child-failure:{classification}:line-{location}",
                    file=sys.stderr,
                    flush=True,
                )
                os._exit(1)
        self.assertEqual(os.waitpid(pid, 0)[1], 0, "child violated runtime contract")

    def test_run_never_accepts_root_or_automatically_selects_compatibility(self):
        with self.assertRaises(self.r.RuntimeBoundaryError):
            self.r.prepare("run")

    def test_root_compatibility_requires_root_and_cannot_elevate_app(self):
        def check():
            with self.assertRaises(self.r.RuntimeBoundaryError):
                self.r.prepare("root-compat")
            self.assertEqual(os.getresuid(), (1000, 1000, 1000))

        self.child(check)

    def test_unknown_mode_and_extra_arguments_are_rejected_before_exec(self):
        for args in (
            [],
            ["run", "anything"],
            ["sh"],
            ["--help"],
            ["root-compat", "run"],
        ):
            with (
                self.subTest(args=args),
                self.assertRaises(self.r.RuntimeBoundaryError),
            ):
                self.r.main(args)

    def test_saved_root_identity_is_not_hidden_by_effective_app_uid(self):
        def check():
            os.setgroups([1000])
            os.setresgid(1000, 1000, 1000)
            os.setresuid(1000, 1000, 0)
            with self.assertRaises(self.r.RuntimeBoundaryError):
                self.r.prepare("run")

        self.child(check, identity=False)

    def test_extra_groups_fail_instead_of_silently_retaining_authority(self):
        def check():
            os.setgroups([1000, 1234])
            os.setresgid(1000, 1000, 1000)
            os.setresuid(1000, 1000, 1000)
            with self.assertRaises(self.r.RuntimeBoundaryError):
                self.r.prepare("run")

        self.child(check, identity=False)

    def test_prepare_sets_nnp_private_creation_home_and_fixed_argv(self):
        def check():
            os.environ["HOME"] = "/tmp"
            os.environ["TOOL_TIER"] = "core"
            os.environ["TOOLS"] = "calendar  tasks\tcontacts"
            os.chdir("/tmp")
            argv = self.r.prepare("run")
            self.assertEqual(
                argv,
                [
                    "/app/.venv/bin/python",
                    "-B",
                    "main.py",
                    "--transport",
                    "streamable-http",
                    "--tool-tier",
                    "core",
                    "--tools",
                    "calendar",
                    "tasks",
                    "contacts",
                ],
            )
            self.assertEqual(os.getcwd(), "/app")
            self.assertEqual(os.environ["HOME"], "/home/app")
            status = Path("/proc/self/status").read_text()
            self.assertRegex(status, r"(?m)^NoNewPrivs:\s+1$")
            for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
                self.assertRegex(status, r"(?m)^" + name + r":\s+0+$")
            with tempfile.TemporaryDirectory(dir="/home/app") as folder:
                directory = Path(folder) / "private"
                directory.mkdir()
                record = directory / "synthetic"
                record.write_bytes(b"not-a-credential")
                self.assertEqual(directory.stat().st_mode & 0o7777, 0o700)
                self.assertEqual(record.stat().st_mode & 0o7777, 0o600)
            with self.assertRaises(PermissionError):
                with open("/app/main.py", "ab"):
                    pass

        self.child(check)

    def test_nnp_survives_actual_exec(self):
        def check():
            self.r.prepare("run")
            os.execv(
                "/usr/local/bin/python3.11",
                [
                    "/usr/local/bin/python3.11",
                    "-I",
                    "-S",
                    "-c",
                    "import pathlib,re; assert re.search(r'(?m)^NoNewPrivs:\\s+1$', pathlib.Path('/proc/self/status').read_text())",
                ],
            )

        self.child(check)

    def test_high_inherited_fd_is_closed_even_above_lowered_limit(self):
        def check():
            source = os.open("/app/main.py", os.O_RDONLY)
            os.dup2(source, 256, inheritable=True)
            os.close(source)
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
            self.r.prepare("run")
            with self.assertRaises(OSError):
                os.fstat(256)

        self.child(check)

    def test_privileged_file_stdio_is_rejected(self):
        def check():
            source = os.open("/app/main.py", os.O_RDONLY)
            os.dup2(source, 0)
            os.close(source)
            with self.assertRaises(self.r.RuntimeBoundaryError):
                self.r.prepare("run")

        self.child(check)

    def test_root_compatibility_preserves_mixed_metadata_and_is_expiry_independent(
        self,
    ):
        with tempfile.TemporaryDirectory() as folder:
            record = Path(folder) / "synthetic"
            record.write_bytes(b"synthetic-only")
            record.chmod(0o600)
            os.chown(record, 1000, 1000)
            before = record.stat()

            def check():
                os.environ["MIGRATION_EXPIRES_AT"] = "1"
                argv = self.r.prepare("root-compat")
                self.assertEqual(argv[:3], ["/app/.venv/bin/python", "-B", "main.py"])
                self.assertEqual(os.getresuid(), (0, 0, 0))
                self.assertEqual(record.read_bytes(), b"synthetic-only")
                self.assertEqual(
                    (record.stat().st_uid, record.stat().st_mode),
                    (before.st_uid, before.st_mode),
                )
                self.assertRegex(
                    Path("/proc/self/status").read_text(), r"(?m)^NoNewPrivs:\s+1$"
                )

            self.child(check, identity=False)

    def test_writable_code_ancestor_cannot_be_trusted(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder).chmod(0o777)
            code = Path(folder) / "script"
            code.write_text("synthetic")
            with self.assertRaises(self.r.RuntimeBoundaryError):
                self.r.protected(str(code))

    def test_tool_selection_is_a_fixed_argv_not_a_shell_program(self):
        self.assertEqual(
            self.r.app_argv({}),
            [
                "/app/.venv/bin/python",
                "-B",
                "main.py",
                "--transport",
                "streamable-http",
            ],
        )
        for field, value in [
            ("TOOLS", "calendar;id"),
            ("TOOLS", "$(id)"),
            ("TOOLS", "*.py"),
            ("TOOLS", "../main.py"),
            ("TOOLS", " "),
            ("TOOL_TIER", "core --extra"),
            ("TOOLS", "x" * 4097),
            ("TOOL_TIER", "x" * 129),
        ]:
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(self.r.RuntimeBoundaryError),
            ):
                self.r.app_argv({field: value})

    def test_failed_nnp_setup_prevents_application_continuation(self):
        def check():
            with patch.object(
                self.r, "set_nnp", side_effect=self.r.RuntimeBoundaryError("nnp-failed")
            ):
                with self.assertRaises(self.r.RuntimeBoundaryError):
                    self.r.prepare("run")

        self.child(check)


def host_driver(args):
    from packaged_docker import select_context
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--image-id", required=True)
    parser.add_argument(
        "--test-file", choices=["runtime", "migration"], default="runtime"
    )
    parser.add_argument(
        "--docker-context",
        choices=["default", "desktop-linux"],
        default="desktop-linux",
    )
    options = parser.parse_args(args)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", options.image_id):
        parser.error("an exact cached local image ID is required")
    name = "packaged-unit-" + str(uuid.uuid4())
    docker = select_context(options.docker_context)
    root = Path(__file__).resolve().parents[2]
    test_file = (
        root / "tests/container" / ("test_packaged_" + options.test_file + ".py")
    )

    def call(*argv, timeout=60, check=True):
        result = subprocess.run(
            docker + list(argv), capture_output=True, text=True, timeout=timeout
        )
        if check and result.returncode:
            raise RuntimeError("local Docker operation failed: " + argv[0])
        return result

    result = None
    try:
        # Register the exact name before create; no data/credential mounts.
        call("image", "inspect", options.image_id, "--format", "{{.Id}}")
        call(
            "create",
            "--name",
            name,
            "--pull",
            "never",
            "--platform",
            "linux/amd64",
            "--network",
            "none",
            "--user",
            "0:0",
            "--entrypoint",
            "/usr/local/bin/python3.11",
            options.image_id,
            "-I",
            "-S",
            "/packaged-tests.py",
            "--linux-unit",
        )
        call("cp", str(test_file), name + ":/packaged-tests.py")
        if (root / "docker").is_dir():
            # Explicit fixture archive ownership models COPY --chown=0:0.
            # Docker Desktop otherwise preserves this Mac's 501:20 ownership.
            import io
            import tarfile

            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                directory = tarfile.TarInfo("mcp-runtime")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                archive.addfile(directory)
                for filename in (
                    "runtime_launcher.py",
                    "content_permission_migration.py",
                ):
                    source = root / "docker" / filename
                    if source.exists():
                        if source.is_symlink() or not source.is_file():
                            raise RuntimeError("unsafe fixture source")
                        content = source.read_bytes()
                        entry = tarfile.TarInfo("mcp-runtime/" + filename)
                        entry.mode, entry.size = 0o644, len(content)
                        archive.addfile(entry, io.BytesIO(content))
            transfer = subprocess.run(
                docker + ["cp", "-", name + ":/opt"],
                input=buffer.getvalue(),
                capture_output=True,
                timeout=60,
            )
            if transfer.returncode:
                raise RuntimeError("fixture source transfer failed")
        result = call("start", "--attach", name, timeout=180, check=False)
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
    finally:
        call("rm", "--force", name, check=False)
        remaining = call(
            "container",
            "ls",
            "--all",
            "--filter",
            "name=^/" + name + "$",
            "--format",
            "{{.Names}}",
        )
        if remaining.stdout.strip():
            raise RuntimeError("local test container cleanup not verified")
        print(json.dumps({"unitContainer": name, "cleanup": "verified-absent"}))
    return result.returncode


if __name__ == "__main__":
    if sys.argv[1:] == ["--linux-unit"]:
        assert (
            sys.platform == "linux"
            and Path("/.dockerenv").is_file()
            and os.getuid() == 0
        )
        unittest.main(argv=[sys.argv[0]], verbosity=2)
    else:
        sys.exit(host_driver(sys.argv[1:]))
