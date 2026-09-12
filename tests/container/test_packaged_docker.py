"""Fail closed before any build/fixture can target a remote Docker daemon."""

import json
from types import SimpleNamespace

import pytest
from packaged_docker import command, select_context


@pytest.mark.parametrize("name", ["default", "desktop-linux"])
def test_local_context_is_explicit(name):
    assert command(name, "unix:///var/run/docker.sock", {}) == [
        "docker",
        "--context",
        name,
    ]


@pytest.mark.parametrize(
    "name,endpoint,env",
    [
        ("remote", "unix:///var/run/docker.sock", {}),
        ("--host=x", "unix:///var/run/docker.sock", {}),
        ("default", "tcp://example.invalid:2375", {}),
        ("desktop-linux", "ssh://example.invalid", {}),
        ("default", "unix:///tmp/a\nsocket", {}),
        ("default", "unix://relative.sock", {}),
        ("default", "unix:///var/run/docker.sock", {"DOCKER_HOST": "tcp://x"}),
        ("default", "unix:///var/run/docker.sock", {"DOCKER_CONTEXT": "remote"}),
    ],
)
def test_remote_or_implicit_selection_rejected(name, endpoint, env):
    with pytest.raises(ValueError):
        command(name, endpoint, env)


def test_preflight_checks_endpoint_then_linux_without_mutations():
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        assert kwargs["timeout"] == 15
        if args[1:3] == ["context", "inspect"]:
            return SimpleNamespace(
                returncode=0, stdout=json.dumps("unix:///var/run/docker.sock")
            )
        assert args == [
            "docker",
            "--context",
            "default",
            "info",
            "--format",
            "{{.OSType}}/{{.Architecture}}",
        ]
        return SimpleNamespace(returncode=0, stdout="linux/x86_64\n")

    assert select_context("default", runner=runner, environ={}) == [
        "docker",
        "--context",
        "default",
    ]
    assert len(calls) == 2


@pytest.mark.parametrize(
    "output,status", [("not-json", 0), ('"tcp://x"', 0), ('"unix:///x"', 1)]
)
def test_unknown_endpoint_never_reaches_daemon(output, status):
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=status, stdout=output)

    with pytest.raises(ValueError):
        select_context("default", runner=runner, environ={})
    assert len(calls) == 1


def test_override_fails_before_even_inspecting_context():
    with pytest.raises(ValueError):
        select_context(
            "default",
            runner=lambda *a, **kw: pytest.fail("unexpected call"),
            environ={"DOCKER_HOST": "tcp://x"},
        )


@pytest.mark.parametrize(
    "info,status", [("windows/amd64", 0), ("linux/unknown", 0), ("linux/amd64", 1)]
)
def test_unsupported_or_unavailable_daemon_is_rejected(info, status):
    def runner(args, **kwargs):
        return (
            SimpleNamespace(returncode=0, stdout='"unix:///var/run/docker.sock"')
            if args[1:3] == ["context", "inspect"]
            else SimpleNamespace(returncode=status, stdout=info)
        )

    with pytest.raises(ValueError):
        select_context("default", runner=runner, environ={})


def test_builder_subprocess_uses_selected_prefix(monkeypatch):
    import build_packaged_images as builder

    prefix = command("default", "unix:///var/run/docker.sock", {})
    monkeypatch.setattr(builder, "DOCKER", prefix)
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert args[:3] == prefix
        assert kwargs["timeout"] == 180
        return SimpleNamespace(returncode=0, stdout=b"[]", stderr=b"")

    monkeypatch.setattr(builder.subprocess, "run", run)
    builder.docker("image", "inspect", "sha256:" + "a" * 64)
    builder.docker("build", "-", data=b"public-fixture")
    assert len(calls) == 2


def test_layer_export_uses_selected_prefix(monkeypatch):
    import verify_packaged_layers as layers

    prefix = command("default", "unix:///var/run/docker.sock", {})
    monkeypatch.setattr(layers, "DOCKER", prefix)
    identifiers = [layers.BASE_ID, "sha256:" + "a" * 64, "sha256:" + "b" * 64]
    monkeypatch.setattr(
        layers,
        "inspect",
        lambda i: {
            "Config": {"User": "1000:1000"},
            "RootFS": {"Layers": identifiers[: identifiers.index(i) + 1]},
        },
    )

    def popen(args, **kwargs):
        assert args == prefix + ["image", "save", *identifiers[1:]]
        raise RuntimeError("controlled-export-stop")

    monkeypatch.setattr(layers.subprocess, "Popen", popen)
    with pytest.raises(RuntimeError, match="controlled-export-stop"):
        layers.verify(*identifiers[1:])


def test_linux_driver_uses_selected_prefix_for_transfer_and_cleanup(
    monkeypatch, capsys
):
    import packaged_docker
    import test_packaged_runtime as driver

    prefix = command("default", "unix:///var/run/docker.sock", {})
    monkeypatch.setattr(
        packaged_docker,
        "select_context",
        lambda name: prefix if name == "default" else pytest.fail("wrong context"),
    )
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        assert args[:3] == prefix
        assert kwargs["timeout"] <= 180
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(driver.subprocess, "run", run)
    assert (
        driver.host_driver(
            ["--docker-context", "default", "--image-id", "sha256:" + "a" * 64]
        )
        == 0
    )
    assert [args[3] for args in calls] == [
        "image",
        "create",
        "cp",
        "cp",
        "start",
        "rm",
        "container",
    ]
    assert "verified-absent" in capsys.readouterr().out
