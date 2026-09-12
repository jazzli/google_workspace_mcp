"""Explicit local Docker boundary shared by public qualification drivers."""

import json
import os
import subprocess


def command(context_name, endpoint, environ):
    if context_name not in {"default", "desktop-linux"}:
        raise ValueError("unsupported-docker-context")
    if any(environ.get(key) for key in ("DOCKER_HOST", "DOCKER_CONTEXT")):
        raise ValueError("implicit-docker-override")
    if (
        not isinstance(endpoint, str)
        or not endpoint.startswith("unix:///")
        or len(endpoint) <= len("unix:///")
        or len(endpoint) > 4096
        or any(c.isspace() or ord(c) < 32 for c in endpoint)
    ):
        raise ValueError("nonlocal-docker-endpoint")
    return ["docker", "--context", context_name]


def select_context(context_name, *, runner=subprocess.run, environ=None):
    environ = os.environ if environ is None else environ
    # Validate name and environment before invoking even context inspection.
    command(context_name, "unix:///preflight", environ)
    try:
        result = runner(
            [
                "docker",
                "context",
                "inspect",
                context_name,
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode or len(result.stdout) > 8192:
            raise ValueError("docker-context-unavailable")
        prefix = command(context_name, json.loads(result.stdout), environ)
        result = runner(
            prefix + ["info", "--format", "{{.OSType}}/{{.Architecture}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode or result.stdout.strip() not in {
            "linux/amd64",
            "linux/x86_64",
            "linux/arm64",
            "linux/aarch64",
        }:
            raise ValueError("unsupported-docker-daemon")
        return prefix
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        raise ValueError("docker-preflight-failed") from None
