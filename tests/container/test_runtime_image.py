"""Opt-in behavioral checks against a locally built, disposable Docker image.

Set WORKSPACE_MCP_TEST_IMAGE and optionally WORKSPACE_MCP_TEST_DOCKER_CONTEXT.
No host directories, credentials, network, or published ports enter containers.
"""

import json
import os
import subprocess
import textwrap
import time

import pytest

IMAGE = os.environ.get("WORKSPACE_MCP_TEST_IMAGE")
CONTEXT = os.environ.get("WORKSPACE_MCP_TEST_DOCKER_CONTEXT", "default")
pytestmark = pytest.mark.skipif(
    not IMAGE, reason="requires an explicit local test image"
)
ISOLATION = ["--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges"]
PYTHON = "/app/.venv/bin/python"


def docker(*args, source=None, timeout=60):
    result = subprocess.run(
        ["docker", "--context", CONTEXT, *args],
        input=textwrap.dedent(source) if source else None,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def image_python(source):
    return docker(
        "run",
        "--rm",
        "-i",
        *ISOLATION,
        "--entrypoint",
        PYTHON,
        IMAGE,
        "-B",
        "-",
        source=source,
    )


def test_interpreter_and_packages_have_protected_paths():
    # Keep this image invariant independent of separately delivered maintenance
    # tooling: both resolved targets and original path ancestors must be safe.
    image_python("""
        import stat
        import sys
        from pathlib import Path
        python = Path('/app/.venv/bin/python')
        packages = Path('/app/.venv/lib/python3.11/site-packages')
        assert sys.version_info[:2] == (3, 11)
        assert python.resolve(strict=True) == Path(sys.executable).resolve(strict=True)
        assert packages.resolve(strict=True) == packages
        for path, directory in [(python, False), (packages, True)]:
            resolved = path.resolve(strict=True)
            for ancestor in (resolved, *resolved.parents, *path.parents):
                info = ancestor.lstat()
                assert info.st_uid == 0 and not info.st_mode & 0o022, str(ancestor)
                if ancestor != resolved or directory:
                    assert stat.S_ISDIR(info.st_mode), str(ancestor)
                else:
                    assert stat.S_ISREG(info.st_mode), str(ancestor)
    """)


def test_code_and_dependencies_are_root_owned_and_not_writable():
    image_python("""
        import os
        import stat
        from pathlib import Path
        assert os.geteuid() != 0, 'service must remain non-root'
        for root, directories, files in os.walk('/app', followlinks=False):
            if root == '/app':
                directories.remove('store_creds')
            for path in [Path(root), *(Path(root) / n for n in directories + files)]:
                info = path.lstat()
                assert info.st_uid == 0, f'non-root owner: {path}'
                if stat.S_ISLNK(info.st_mode):
                    info = path.resolve(strict=True).stat()
                assert info.st_uid == 0 and not info.st_mode & 0o022, f'unsafe: {path}'
                assert not os.access(path, os.W_OK), f'app-writable: {path}'
        for name in ['/app/main.py', '/app/.venv/pyvenv.cfg', '/app/core/__init__.py']:
            try:
                with open(name, 'ab'):
                    pass
            except PermissionError:
                continue
            raise AssertionError(f'app may modify {name}')
    """)


def test_only_data_locations_are_writable():
    image_python("""
        import os
        import sys
        from pathlib import Path
        sys.path.insert(0, '/app')
        from auth.google_auth import get_default_credentials_dir
        from core.attachment_storage import STORAGE_DIR
        home = Path.home()
        assert home == Path('/home/app')
        store = Path('/app/store_creds')
        assert store.stat().st_uid == os.geteuid()
        assert store.stat().st_mode & 0o777 == 0o700
        locations = [store, Path(get_default_credentials_dir()), STORAGE_DIR,
                     home / '.google_workspace_mcp/logs', home / '.fastmcp/oauth-proxy']
        for path in locations:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            probe = path / 'synthetic-write-probe'
            probe.write_bytes(b'synthetic test data')
            probe.unlink()
        assert not any(store.iterdir()), 'image must not contain stored credentials'
        assert not Path('/app/.credentials').exists()
        assert not Path('/app/.env.oauth21').exists()
    """)


@pytest.mark.parametrize(
    "selection",
    [{}, {"TOOL_TIER": "core", "TOOLS": "calendar"}, {"TOOLS": "calendar tasks"}],
)
def test_http_startup_on_read_only_image_without_runtime_sync(selection):
    # Synthetic inputs only. No OAuth exchange is made; all egress is disabled.
    environment = {
        "PORT": "8765",
        "MCP_ENABLE_OAUTH21": "true",
        "GOOGLE_OAUTH_CLIENT_ID": "synthetic-container-test.apps.googleusercontent.com",
        "GOOGLE_OAUTH_CLIENT_SECRET": "synthetic-container-test-not-a-credential",
        "WORKSPACE_MCP_OAUTH_PROXY_STORAGE_BACKEND": "disk",
        **selection,
    }
    env_args = [
        arg for key, value in environment.items() for arg in ("-e", f"{key}={value}")
    ]
    container = docker(
        "run",
        "-d",
        *ISOLATION,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev",
        "--tmpfs",
        "/home/app:rw,nosuid,nodev,uid=1000,gid=1000,mode=700",
        *env_args,
        IMAGE,
    )
    try:
        ready = False
        for _ in range(90):
            if docker("inspect", "-f", "{{.State.Running}}", container) != "true":
                pytest.fail("synthetic container exited: " + docker("logs", container))
            ready = (
                docker(
                    "exec",
                    container,
                    PYTHON,
                    "-B",
                    "-c",
                    """
import urllib.request
try:
    with urllib.request.urlopen('http://127.0.0.1:8765/health', timeout=1) as response:
        print(response.status == 200)
except OSError:
    print(False)
""",
                )
                == "True"
            )
            if ready:
                break
            time.sleep(0.5)
        assert ready, "synthetic health check did not become ready"
        result = json.loads(
            docker(
                "exec",
                "-i",
                container,
                PYTHON,
                "-B",
                "-",
                source="""
            import json
            import os
            import urllib.error
            import urllib.request
            from pathlib import Path
            try:
                urllib.request.urlopen('http://127.0.0.1:8765/mcp', timeout=2)
            except urllib.error.HTTPError as error:
                status = error.code
            else:
                raise AssertionError('MCP must require authentication')
            command = Path('/proc/1/cmdline').read_bytes().split(b'\\0')
            print(json.dumps({'uid': os.geteuid(), 'status': status,
                              'command': [item.decode() for item in command if item]}))
        """,
            )
        )
        assert result["uid"] != 0
        assert result["status"] == 401
        assert result["command"][:3] == [PYTHON, "-B", "main.py"]
        assert result["command"][3:5] == ["--transport", "streamable-http"]
        if "TOOL_TIER" in selection:
            assert "--tool-tier" in result["command"]
        if "TOOLS" in selection:
            assert (
                result["command"][-len(selection["TOOLS"].split()) :]
                == selection["TOOLS"].split()
            )
    finally:
        docker("rm", "-f", container)
