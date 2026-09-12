"""Host-only contract tests for the minimal, allowlisted image build."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BuildTests(unittest.TestCase):
    def test_context_contains_only_explicit_public_files(self):
        import io
        import tarfile
        from build_packaged_images import context

        for stage, filename in [
            ("runtime", "runtime_launcher.py"),
            ("migration", "content_permission_migration.py"),
        ]:
            data, hashes = context(stage)
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                self.assertEqual(archive.getnames(), ["Dockerfile", filename])
                self.assertTrue(
                    all(
                        m.uid == m.gid == 0 and m.mode == 0o644
                        for m in archive.getmembers()
                    )
                )
            self.assertEqual(len(hashes), 2)

    def test_dockerfiles_add_only_protected_runtime_code(self):
        runtime = (ROOT / "docker/Dockerfile.runtime").read_text()
        migration = (ROOT / "docker/Dockerfile.content-migration").read_text()
        self.assertIn(
            "FROM ghcr.io/jazzli/google_workspace_mcp@sha256:8af597d77f12ec7bf1319354065af3843c09426f4469374f698ee7e675d32f43",
            runtime,
        )
        self.assertIn(
            "COPY --chown=0:0 --chmod=0755 runtime_launcher.py /opt/mcp-runtime/runtime_launcher.py",
            runtime,
        )
        self.assertIn(
            "COPY --chown=0:0 --chmod=0644 content_permission_migration.py /opt/mcp-runtime/content_permission_migration.py",
            migration,
        )
        self.assertIn("FROM ${RUNTIME_IMAGE}", migration)
        for source in (runtime, migration):
            self.assertIn("USER 1000:1000", source)
            self.assertNotIn("RUN ", source)
            self.assertNotIn("COPY .", source)
            self.assertNotIn("ADD ", source)
        self.assertIn(
            'ENTRYPOINT ["/usr/local/bin/python3.11", "-I", "-S", "/opt/mcp-runtime/runtime_launcher.py"]',
            runtime,
        )
        self.assertIn('CMD ["run"]', runtime)
        self.assertNotIn("content_permission_migration", runtime)


if __name__ == "__main__":
    unittest.main(verbosity=2)
