"""Linux/root fixtures only; all contents and paths are synthetic."""

import importlib.util
import json
import hashlib
import os
from pathlib import Path
import resource
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HELPER = Path("/opt/mcp-runtime/content_permission_migration.py")
IMAGE = "ghcr.io/jazzli/google_workspace_mcp@sha256:" + "1" * 64


def bind(config):
    config = {k: v for k, v in config.items() if k != "manifest_sha256"}
    digest = hashlib.sha256(
        json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {**config, "manifest_sha256": digest}


@unittest.skipUnless(
    sys.argv[1:] == ["--linux-unit"]
    and sys.platform == "linux"
    and os.geteuid() == 0
    and Path("/.dockerenv").is_file(),
    "explicit controlled Linux/root fixture invocation required",
)
class EngineTests(unittest.TestCase):
    def test_tool_names_cannot_become_application_options(self):
        for value in (
            "calendar --transport stdio",
            "calendar --single-user",
            "--",
            "calendar --tr stdio",
            "--help",
        ):
            with self.subTest(value=value), self.assertRaises(self.b.BootstrapError):
                self.b._app_argv({"TOOLS": value})
        with self.assertRaises(self.b.BootstrapError):
            self.b._app_argv({"TOOL_TIER": "--single-user"})

    def setUp(self):
        self.assertTrue(
            HELPER.exists(),
            "missing metadata migration engine: synthetic records cannot be migrated safely",
        )
        spec = importlib.util.spec_from_file_location("bootstrap", HELPER)
        self.b = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.b)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.base.chmod(0o755)
        self.store = self.base / "oauth-proxy"
        self.store.mkdir(mode=0o755)
        self.record = self.store / "synthetic-sensitive-name"
        self.record.write_bytes(b"synthetic encrypted bytes\x00\xff")
        self.record.chmod(0o644)
        self.config = bind(
            {
                "operation_id": "11111111-2222-4333-8444-555555555555",
                "mutate_until": int(time.time()) + 600,
                "project_id": "10000000-0000-4000-8000-000000000001",
                "environment_id": "10000000-0000-4000-8000-000000000002",
                "service_id": "10000000-0000-4000-8000-000000000003",
                "volume_id": "10000000-0000-4000-8000-000000000004",
                "runtime_image": IMAGE,
                "migration_image": "ghcr.io/jazzli/google_workspace_mcp@sha256:"
                + "2" * 64,
                "helper_sha256": hashlib.sha256(HELPER.read_bytes()).hexdigest(),
            }
        )

    def snapshot(self):
        return self.b._inventory(str(self.store), self.b.Deadline(30))

    def migrate(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries) as journal:
                self.b._migrate(entries, journal, self.b.Deadline(120))
                journal.serving()

    def test_permission_mutation_must_preserve_bytes_and_private_modes(self):
        before = self.record.read_bytes()
        self.migrate()
        self.assertEqual(self.record.read_bytes(), before)
        self.assertEqual(
            (
                self.record.stat().st_uid,
                self.record.stat().st_gid,
                self.record.stat().st_mode & 0o7777,
            ),
            (1000, 1000, 0o600),
        )
        self.assertEqual(
            (
                self.store.stat().st_uid,
                self.store.stat().st_gid,
                self.store.stat().st_mode & 0o7777,
            ),
            (1000, 1000, 0o700),
        )
        self.assertEqual(
            (self.base.stat().st_uid, self.base.stat().st_mode & 0o7777), (0, 0o755)
        )

    def test_store_files_never_get_data_readable_descriptors(self):
        real_open = os.open

        def guarded_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if os.fstat(fd).st_ino == self.record.stat().st_ino:
                self.assertTrue(flags & os.O_PATH, "record opened for data access")
                with self.assertRaises(OSError):
                    os.read(fd, 1)
            return fd

        with patch.object(os, "open", guarded_open):
            self.migrate()

    def test_symlink_traversal_must_reject_without_touching_target(self):
        (self.store / "link").symlink_to(self.record)
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()
        self.assertEqual(self.record.stat().st_uid, 0)

    def test_hardlink_cannot_change_off_store_metadata(self):
        os.link(self.record, self.base / "outside")
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()
        self.assertEqual((self.base / "outside").stat().st_mode & 0o7777, 0o644)

    def test_unexpected_owner_special_modes_and_xattrs_reject(self):
        for alteration in ("owner", "mode", "xattr"):
            with self.subTest(alteration=alteration):
                os.chown(self.record, 1234 if alteration == "owner" else 0, 0)
                self.record.chmod(0o755 if alteration == "mode" else 0o644)
                if alteration == "xattr":
                    os.setxattr(self.record, "user.synthetic", b"test")
                with self.assertRaises(self.b.BootstrapError):
                    self.migrate()

    def test_partial_journal_cannot_replay(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries):
                pass
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()
        self.assertEqual(self.record.stat().st_uid, 0)

    def test_completed_store_accepts_safe_replacement_without_replaying(self):
        self.migrate()
        self.record.unlink()
        self.record.write_bytes(b"new synthetic version")
        os.chown(self.record, 1000, 1000)
        self.record.chmod(0o600)
        self.migrate()
        self.assertEqual(self.record.read_bytes(), b"new synthetic version")
        self.record.chmod(0o644)
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()
        self.assertEqual(self.record.stat().st_mode & 0o7777, 0o644)

    def test_changed_inode_is_not_blindly_mutated_or_undone(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries) as journal:
                old = self.store / "held-old"
                self.record.rename(old)
                self.record.write_bytes(b"replacement")
                with self.assertRaises(self.b.BootstrapError):
                    self.b._migrate(entries, journal, self.b.Deadline(120))
                with self.assertRaises(self.b.BootstrapError):
                    self.b._undo(entries, journal, self.b.Deadline(120))
                self.assertEqual(self.record.stat().st_uid, 0)
                self.assertEqual(old.stat().st_uid, 0)

    def test_undo_restores_only_known_current_metadata_and_stays_blocking(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries) as journal:
                self.b._migrate(entries, journal, self.b.Deadline(120))
                self.b._undo(entries, journal, self.b.Deadline(120))
        self.assertEqual(
            (self.record.stat().st_uid, self.record.stat().st_mode & 0o7777), (0, 0o644)
        )
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()

    def test_deadline_prevents_any_further_mutation(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries) as journal:
                deadline = self.b.Deadline(0)
                with self.assertRaises(self.b.BootstrapError):
                    self.b._migrate(entries, journal, deadline)
        self.assertEqual(self.record.stat().st_uid, 0)

    def test_errors_do_not_disclose_record_names(self):
        (self.store / "link-secret").symlink_to(self.record)
        try:
            self.migrate()
        except self.b.BootstrapError as error:
            self.assertNotIn("synthetic", str(error))
            self.assertNotIn("secret", str(error))
            self.assertNotIn(str(self.store), str(error))
        else:
            self.fail("unsafe tree accepted")

    def test_bad_config_cannot_begin_mutation(self):
        for update in (
            {"root": str(self.base)},
            {"mutate_until": int(time.time()) - 1},
            {"mutate_until": int(time.time()) + 1801},
            {"runtime_image": "wrong"},
            {"operation_id": "../outside"},
            {"mutate_until": True},
        ):
            with self.subTest(update=update), self.assertRaises(self.b.BootstrapError):
                self.b.run({**self.config, **update})
        self.assertFalse((self.base / ".content-permission-migration").exists())

    def test_nested_mount_id_is_rejected_even_on_same_device(self):
        real = self.b._mount_id

        def nested(fd):
            value = real(fd)
            return (
                value + 1 if os.fstat(fd).st_ino == self.record.stat().st_ino else value
            )

        with patch.object(self.b, "_mount_id", nested):
            with self.assertRaises(self.b.BootstrapError):
                self.migrate()

    def test_same_inode_remount_after_inspection_cannot_receive_metadata_changes(self):
        with self.snapshot() as entries:
            pinned = {entry["fd"] for entry in entries.entries}
            real = self.b._mount_id

            def changed_mount(fd):
                value = real(fd)
                return (
                    value + 1
                    if fd not in pinned
                    and os.fstat(fd).st_ino == self.record.stat().st_ino
                    else value
                )

            with self.b.Journal(str(self.base), self.config, entries) as journal:
                with patch.object(self.b, "_mount_id", changed_mount):
                    with self.assertRaises(self.b.BootstrapError):
                        self.b._migrate(entries, journal, self.b.Deadline(120))
        self.assertEqual(self.record.stat().st_uid, 0)

    def test_replaced_store_parent_cannot_be_ignored(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries) as journal:
                moved = self.base.with_name(self.base.name + "-held")
                self.base.rename(moved)
                self.base.mkdir(mode=0o755)
                try:
                    with self.assertRaises(self.b.BootstrapError):
                        self.b._migrate(entries, journal, self.b.Deadline(120))
                    self.assertEqual(
                        (moved / "oauth-proxy" / "synthetic-sensitive-name")
                        .stat()
                        .st_uid,
                        0,
                    )
                finally:
                    self.base.rmdir()
                    moved.rename(self.base)

    def test_privilege_drop_removes_ids_capabilities_and_inherited_fds(self):
        self.migrate()
        child = os.fork()
        if child == 0:
            try:
                privileged = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY)
                self.b._drop_privileges(self.b.Deadline(120))
                assert os.getresuid() == (1000, 1000, 1000)
                assert os.getresgid() == (1000, 1000, 1000)
                assert os.getgroups() == [1000]
                try:
                    os.fstat(privileged)
                except OSError:
                    pass
                else:
                    raise AssertionError("privileged fd retained")
                assert self.record.read_bytes() == b"synthetic encrypted bytes\x00\xff"
                replacement = self.store / "fresh"
                replacement.write_bytes(b"synthetic new bytes")
                assert replacement.stat().st_mode & 0o7777 == 0o600
                os.replace(replacement, self.record)
                try:
                    os.setuid(0)
                except PermissionError:
                    pass
                else:
                    raise AssertionError("root regained")
                os._exit(0)
            except BaseException:
                os._exit(1)
        self.assertEqual(
            os.waitpid(child, 0)[1], 0, "privilege drop or app access failed"
        )

    def test_privilege_drop_failure_blocks_continuation(self):
        child = os.fork()
        if child == 0:
            with patch.object(
                os, "setgroups", side_effect=PermissionError("synthetic")
            ):
                try:
                    self.b._drop_privileges(self.b.Deadline(120))
                except self.b.BootstrapError:
                    os._exit(0)
                os._exit(1)
        self.assertEqual(os.waitpid(child, 0)[1], 0)

    def test_high_inheritable_fd_above_lowered_limit_cannot_survive_exec(self):
        child = os.fork()
        if child == 0:
            try:
                read_fd, write_fd = os.pipe()
                os.dup2(write_fd, 256, inheritable=True)
                os.close(read_fd)
                os.close(write_fd)
                resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
                self.b._drop_privileges(self.b.Deadline(120))
                os.execv(
                    "/usr/local/bin/python3.11",
                    [
                        "/usr/local/bin/python3.11",
                        "-I",
                        "-S",
                        "-c",
                        "import errno,os\ntry: os.fstat(256)\nexcept OSError as e: os._exit(0 if e.errno == errno.EBADF else 2)\nelse: os._exit(3)",
                    ],
                )
            except BaseException:
                os._exit(1)
        self.assertEqual(
            os.waitpid(child, 0)[1],
            0,
            "inheritable FD256 survived lowered hard limit128 and application exec",
        )

    def test_unsupported_primitive_blocks_before_any_store_mutation(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries) as journal:
                with patch.object(
                    self.b, "_chmod", side_effect=self.b.BootstrapError("unsupported")
                ):
                    with self.assertRaises(self.b.BootstrapError):
                        self.b._migrate(entries, journal, self.b.Deadline(120))
        self.assertEqual((self.store.stat().st_uid, self.record.stat().st_uid), (0, 0))

    def test_journal_acknowledges_each_effect_only_after_durable_intent(self):
        real_chown = self.b._chown
        observed = []

        def inspect(fd, uid, gid):
            if os.fstat(fd).st_ino == self.record.stat().st_ino:
                path = (
                    self.base
                    / ".content-permission-migration"
                    / self.config["operation_id"]
                    / "journal.json"
                )
                document = json.loads(path.read_text())
                entry = next(
                    e
                    for e in document["entries"]
                    if e["path"] == "synthetic-sensitive-name"
                )
                observed.append(entry["state"])
            return real_chown(fd, uid, gid)

        with patch.object(self.b, "_chown", inspect):
            self.migrate()
        self.assertEqual(observed, ["owner-intent"])

    def test_failed_journal_sync_never_allows_unjournaled_mutation(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries) as journal:
                with patch.object(
                    os, "fsync", side_effect=OSError("synthetic failure")
                ):
                    with self.assertRaises((self.b.BootstrapError, OSError)):
                        self.b._migrate(entries, journal, self.b.Deadline(120))
        self.assertEqual((self.store.stat().st_uid, self.record.stat().st_uid), (0, 0))
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()

    def test_serving_journal_can_never_be_undone(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries) as journal:
                self.b._migrate(entries, journal, self.b.Deadline(120))
                journal.serving()
                with self.assertRaises(self.b.BootstrapError):
                    self.b._undo(entries, journal, self.b.Deadline(120))
        self.assertEqual(self.record.stat().st_uid, 1000)

    def test_writable_code_ancestor_is_rejected(self):
        code = self.base / "program"
        code.write_text("synthetic code")
        self.base.chmod(0o777)
        with self.assertRaises(self.b.BootstrapError):
            self.b._protected(str(code))

    def test_unsafe_filesystem_root_cannot_hide_behind_protected_code_ancestors(self):
        protected = self.base / "protected"
        protected.mkdir(mode=0o755)
        (protected / "code").write_text("synthetic code")
        (protected / "code").chmod(0o644)
        child = os.fork()
        if child == 0:
            try:
                self.base.chmod(0o777)
                os.chroot(self.base)
                os.chdir("/")
                self.b._protected("/protected/code")
            except self.b.BootstrapError:
                os._exit(0)
            except BaseException:
                os._exit(2)
            os._exit(1)
        self.assertEqual(
            os.waitpid(child, 0)[1],
            0,
            "writable filesystem root was accepted above protected code",
        )

    def test_exact_image_empty_data_directory_is_not_treated_as_code(self):
        try:
            self.b._protected_tree("/app", self.b.Deadline(30))
        except self.b.BootstrapError:
            self.fail(
                "accepted image empty data directory incorrectly rejected as writable code"
            )

    def test_data_directory_exception_rejects_nonempty_wrong_owner_or_link(self):
        candidate = self.base / "store_creds"
        candidate.mkdir(mode=0o700)
        os.chown(candidate, 1000, 1000)
        parent_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self.b._empty_image_data_directory(parent_fd, "store_creds")
            (candidate / "synthetic").write_bytes(b"synthetic only")
            with self.assertRaises(self.b.BootstrapError):
                self.b._empty_image_data_directory(parent_fd, "store_creds")
            (candidate / "synthetic").unlink()
            os.chown(candidate, 0, 0)
            with self.assertRaises(self.b.BootstrapError):
                self.b._empty_image_data_directory(parent_fd, "store_creds")
            candidate.rmdir()
            candidate.symlink_to(self.store)
            with self.assertRaises((self.b.BootstrapError, OSError)):
                self.b._empty_image_data_directory(parent_fd, "store_creds")
        finally:
            os.close(parent_fd)

    def test_other_writable_code_descendant_does_not_get_data_exception(self):
        candidate = self.base / "store_creds"
        candidate.mkdir(mode=0o700)
        os.chown(candidate, 1000, 1000)
        with self.assertRaises(self.b.BootstrapError):
            self.b._protected_tree(str(self.base), self.b.Deadline(30))

    def test_application_arguments_preserve_accepted_tool_selection(self):
        argv = self.b._app_argv({"TOOL_TIER": "core", "TOOLS": "one  two\tthree"})
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
                "one",
                "two",
                "three",
            ],
        )
        with self.assertRaises(self.b.BootstrapError):
            self.b._app_argv({"TOOLS": "*.py"})

    def test_alarm_and_termination_cancel_inflight_work(self):
        for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT):
            child = os.fork()
            if child == 0:
                try:
                    self.b._install_signals(self.b.Deadline(120))
                    os.kill(os.getpid(), sig)
                    os._exit(3)
                except self.b.BootstrapError:
                    os._exit(0)
            self.assertEqual(os.waitpid(child, 0)[1], 0)

    def test_strict_cli_and_canonical_manifest(self):
        argv = [
            part
            for key, value in self.config.items()
            for part in ("--" + key.replace("_", "-"), str(value))
        ]
        self.assertEqual(self.b.parse_config(argv), self.config)
        for invalid in (
            argv + ["--root", "/tmp"],
            argv + ["--operation-id", self.config["operation_id"]],
            ["--oper", self.config["operation_id"]] + argv[2:],
            argv + ["--command", "true"],
            argv + ["--apply"],
            ["--mutate-until=1"] + argv,
        ):
            with (
                self.subTest(invalid=invalid[-2:]),
                self.assertRaises(self.b.BootstrapError),
            ):
                self.b.parse_config(invalid)
        for update in (
            {"project_id": "../bad"},
            {"volume_id": "x"},
            {"runtime_image": IMAGE + ";true"},
            {"migration_image": IMAGE},
            {"helper_sha256": "0" * 63},
            {"mutate_until": True},
            {"mutate_until": 0},
            {"extra": "ignored"},
        ):
            with self.subTest(update=update), self.assertRaises(self.b.BootstrapError):
                self.b._config(bind({**self.config, **update}))
        with self.assertRaises(self.b.BootstrapError):
            self.b._config(
                {**self.config, "service_id": "10000000-0000-4000-8000-000000000005"}
            )

    def test_provider_binding_and_protected_helper_hash(self):
        target = {
            "RAILWAY_PROJECT_ID": self.config["project_id"],
            "RAILWAY_ENVIRONMENT_ID": self.config["environment_id"],
            "RAILWAY_SERVICE_ID": self.config["service_id"],
            "RAILWAY_VOLUME_ID": self.config["volume_id"],
            "RAILWAY_VOLUME_MOUNT_PATH": "/data",
        }
        self.b._validate_binding(self.config, target)
        with self.assertRaises(self.b.BootstrapError):
            self.b._validate_binding(
                self.config,
                {**target, "RAILWAY_SERVICE_ID": target["RAILWAY_VOLUME_ID"]},
            )
        with self.assertRaises(self.b.BootstrapError):
            self.b._validate_binding(
                bind({**self.config, "helper_sha256": "0" * 64}), target
            )

    def test_expired_fresh_operation_has_no_journal_or_store_effect(self):
        self.config = bind({**self.config, "mutate_until": int(time.time()) - 1})
        self.assertEqual(self.b._config(self.config), self.config)
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()
        self.assertFalse((self.base / ".content-permission-migration").exists())
        self.assertEqual(self.record.stat().st_uid, 0)

    def test_completed_expired_operation_is_verification_only(self):
        self.migrate()
        journal = (
            self.base
            / ".content-permission-migration"
            / self.config["operation_id"]
            / "journal.json"
        )
        before = journal.read_bytes()
        with (
            patch.object(
                self.b.time, "time", return_value=self.config["mutate_until"] + 1
            ),
            patch.object(
                os, "mkdir", side_effect=AssertionError("mkdir during verify")
            ),
            patch.object(
                self.b, "_chown", side_effect=AssertionError("chown during verify")
            ),
            patch.object(
                self.b, "_chmod", side_effect=AssertionError("chmod during verify")
            ),
            patch.object(
                self.b.Journal, "save", side_effect=AssertionError("save during verify")
            ),
        ):
            self.migrate()
        self.assertEqual(journal.read_bytes(), before)

    def test_expired_pending_operation_is_blocked_without_effect(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries):
                pass
        journal = (
            self.base
            / ".content-permission-migration"
            / self.config["operation_id"]
            / "journal.json"
        )
        before = journal.read_bytes()
        with patch.object(
            self.b.time, "time", return_value=self.config["mutate_until"] + 1
        ):
            with self.assertRaises(self.b.BootstrapError):
                self.migrate()
        self.assertEqual(journal.read_bytes(), before)
        self.assertEqual(self.record.stat().st_uid, 0)

    def test_fresh_operation_after_completed_root_fallback_preserves_history(self):
        self.migrate()
        journal = (
            self.base
            / ".content-permission-migration"
            / self.config["operation_id"]
            / "journal.json"
        )
        before = journal.read_bytes()
        fresh = self.store / "root-fallback-record"
        fresh.write_bytes(b"synthetic newer encrypted record")
        fresh.chmod(0o600)
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()
        self.config = bind(
            {**self.config, "operation_id": "22222222-2222-4333-8444-555555555555"}
        )
        self.migrate()
        self.assertEqual((fresh.stat().st_uid, fresh.stat().st_gid), (1000, 1000))
        self.assertEqual(journal.read_bytes(), before)
        self.assertEqual(fresh.read_bytes(), b"synthetic newer encrypted record")

    def test_prior_pending_blocks_new_operation_without_new_journal(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries):
                pass
        self.config = bind(
            {**self.config, "operation_id": "22222222-2222-4333-8444-555555555555"}
        )
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()
        self.assertFalse(
            (
                self.base
                / ".content-permission-migration"
                / self.config["operation_id"]
            ).exists()
        )

    def test_expiry_between_intent_and_effect_blocks_effect(self):
        with self.snapshot() as entries:
            with self.b.Journal(str(self.base), self.config, entries) as journal:
                original = journal.state

                def expire(index, state):
                    original(index, state)
                    if state == "owner-intent":
                        clock.return_value = self.config["mutate_until"] + 1

                with (
                    patch.object(
                        self.b.time, "time", return_value=time.time()
                    ) as clock,
                    patch.object(journal, "state", expire),
                ):
                    with self.assertRaises(self.b.BootstrapError):
                        self.b._migrate(entries, journal, self.b.Deadline(120))
        self.assertEqual(self.store.stat().st_uid, 0)

    def test_uncertain_effect_leaves_pending_and_forbids_replay(self):
        original = self.b._chown

        def interrupted(fd, uid, gid):
            original(fd, uid, gid)
            if os.fstat(fd).st_ino == self.store.stat().st_ino:
                raise self.b.BootstrapError("synthetic-uncertain-effect")

        with patch.object(self.b, "_chown", interrupted):
            with self.assertRaises(self.b.BootstrapError):
                self.migrate()
        self.assertEqual(self.store.stat().st_uid, 1000)
        self.assertEqual(self.record.stat().st_uid, 0)
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()

    def test_corrupt_truncated_and_duplicate_journals_fail_closed(self):
        self.migrate()
        journal = (
            self.base
            / ".content-permission-migration"
            / self.config["operation_id"]
            / "journal.json"
        )
        for content in (b"{", b'{"version":1,"version":1}', b"null", b"[]"):
            journal.write_bytes(content)
            with self.assertRaises(self.b.BootstrapError):
                self.migrate()
            self.assertEqual(journal.read_bytes(), content)

    def test_unknown_history_name_is_not_echoed(self):
        self.migrate()
        bad = self.base / ".content-permission-migration" / "private-looking-name"
        bad.mkdir()
        with self.assertRaises(self.b.BootstrapError) as result:
            self.migrate()
        self.assertNotIn("private-looking-name", str(result.exception))

    def test_inventory_entry_and_depth_limits_refuse_without_journal(self):
        for i in range(511):
            (self.store / ("fixture-" + str(i))).touch()
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()
        self.assertFalse((self.base / ".content-permission-migration").exists())
        for p in self.store.glob("fixture-*"):
            p.unlink()
        path = self.store
        for i in range(9):
            path = path / "nested"
            path.mkdir()
        with self.assertRaises(self.b.BootstrapError):
            self.migrate()
        self.assertFalse((self.base / ".content-permission-migration").exists())


if __name__ == "__main__":
    assert (
        sys.argv[1:] == ["--linux-unit"]
        and sys.platform == "linux"
        and os.getuid() == 0
        and Path("/.dockerenv").is_file()
    )
    unittest.main(argv=[sys.argv[0]], verbosity=2)
