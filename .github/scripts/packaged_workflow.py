"""Reviewable fixed workflow definition; render as the JSON subset of YAML.

Strict equality is intentional: unreviewed steps, permissions and routing cannot
silently enter this narrow workflow. Both definition and rendered file belong
in the same reviewed source commit. This module performs no external actions.
"""

import json

PINS = {
    "checkout": "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
    "python": "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "uv": "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
    "node": "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
    "upload": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "download": "actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0",
    "login": "docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9",
    "attest": "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
}
BASE_SHA = "7d7f2a7d714fe0e1e450b8a5267db357d18c4da6"
INSTALL_SCANNER = """set -euo pipefail
archive="$RUNNER_TEMP/trivy.tar.gz"
install_dir="$RUNNER_TEMP/trivy-bin"
curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 --output "$archive" "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz"
echo "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a  $archive" | sha256sum --check --strict
mkdir -p "$install_dir"
tar -xzf "$archive" -C "$install_dir" trivy
chmod 0755 "$install_dir/trivy"
echo "$install_dir" >> "$GITHUB_PATH"
"""


def action(name, pin, options, **extra):
    return {"name": name, "uses": PINS[pin], "with": options, **extra}


def download(name, artifact, directory):
    return action(
        name,
        "download",
        {"artifact-ids": artifact, "path": "${{ runner.temp }}/" + directory},
    )


def upload(name, directory, identity, *, attempt_always=False):
    value = action(
        name,
        "upload",
        {
            "name": identity + "-${{ github.run_id }}-${{ github.run_attempt }}",
            "path": "${{ runner.temp }}/" + directory,
            "if-no-files-found": "error",
            "retention-days": 14,
            "compression-level": 0,
        },
        id=identity,
    )
    if attempt_always:
        value["if"] = "always()"
    return value


def workflow():
    jobs = {}
    for phase, timeout in [
        ("validate", 5),
        ("build-test", 30),
        ("publish", 15),
        ("verify-published", 30),
    ]:
        steps = [
            action(
                "Checkout exact reviewed workflow/source",
                "checkout",
                {
                    "ref": "${{ github.workflow_sha }}",
                    "path": "source",
                    "fetch-depth": 0,
                    "persist-credentials": False,
                },
            ),
            action("Set up Python", "python", {"python-version": "3.11"}),
        ]
        permissions = {"contents": "read"}
        job = {
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": timeout,
            "permissions": permissions,
            "steps": steps,
        }
        if phase == "build-test":
            job["needs"] = "validate"
        elif phase == "publish":
            job["needs"] = "build-test"
            job["permissions"] = {
                "contents": "read",
                "packages": "write",
                "id-token": "write",
                "attestations": "write",
            }
        elif phase == "verify-published":
            job["needs"] = ["build-test", "publish"]
            job["permissions"] = {
                "contents": "read",
                "packages": "read",
                "attestations": "read",
            }
            job["env"] = {
                "RUNTIME_DIGEST": "${{ needs.publish.outputs.runtime_digest }}",
                "MIGRATION_DIGEST": "${{ needs.publish.outputs.migration_digest }}",
            }
        if phase in ("publish", "verify-published"):
            steps.append(
                download(
                    "Download exact tested pair from this run",
                    "${{ needs.build-test.outputs.artifact_id }}",
                    "packaged-pair",
                )
            )
            if phase == "verify-published":
                steps.append(
                    download(
                        "Download exact publication record from this run",
                        "${{ needs.publish.outputs.pair_artifact }}",
                        "packaged-published",
                    )
                )
            steps.append(
                action(
                    "Log in with job-scoped registry permissions",
                    "login",
                    {
                        "registry": "ghcr.io",
                        "username": "${{ github.actor }}",
                        "password": "${{ github.token }}",
                    },
                )
            )
        if phase in ("build-test", "verify-published"):
            steps += [
                action(
                    "Checkout immutable base application source",
                    "checkout",
                    {
                        "ref": BASE_SHA,
                        "path": "base-source",
                        "persist-credentials": False,
                    },
                ),
                action("Set up Node", "node", {"node-version": "22.23.2"}),
                action("Set up uv", "uv", {}),
                {
                    "name": "Install checksum-pinned scanner",
                    "shell": "bash",
                    "run": INSTALL_SCANNER,
                },
                {
                    "name": "Install frozen test dependencies",
                    "working-directory": "source",
                    "run": "uv sync --frozen --extra test",
                },
            ]
        steps.append(
            {
                "name": "Validate complete workflow contract",
                "run": "python3 source/.github/scripts/packaged_release.py validate-workflow --workflow source/.github/workflows/packaged-container-publish.yml",
            }
        )
        steps.append(
            {
                "name": "Execute fixed " + phase + " boundary",
                "id": "phase",
                "run": "python3 source/.github/scripts/packaged_pipeline.py " + phase,
                "env": {"GH_TOKEN": "${{ github.token }}"},
            }
        )
        if phase == "build-test":
            steps.append(
                upload(
                    "Transfer tested pair without rebuilding",
                    "packaged-pair",
                    "tested-pair",
                )
            )
            job["outputs"] = {
                "artifact_id": "${{ steps.tested-pair.outputs.artifact-id }}"
            }
        if phase == "publish":
            for role in ("runtime", "migration"):
                subject = {
                    "subject-name": "ghcr.io/jazzli/google_workspace_mcp",
                    "subject-digest": "${{ steps.phase.outputs." + role + "_digest }}",
                    "push-to-registry": True,
                    "create-storage-record": False,
                }
                steps.append(
                    action(
                        "Attest " + role + " standard provenance",
                        "attest",
                        subject.copy(),
                    )
                )
                steps.append(
                    action(
                        "Attest " + role + " exact pair receipt",
                        "attest",
                        {
                            **subject,
                            "predicate-type": "https://github.com/jazzli/google_workspace_mcp/packaged-container-release/v1",
                            "predicate-path": "${{ runner.temp }}/packaged-published/"
                            + role
                            + "-predicate.json",
                        },
                    )
                )
            steps.append(
                upload(
                    "Retain known partial or complete publication evidence",
                    "packaged-published",
                    "published-pair",
                    attempt_always=True,
                )
            )
            job["outputs"] = {
                role + "_digest": "${{ steps.phase.outputs." + role + "_digest }}"
                for role in ("runtime", "migration")
            }
            job["outputs"]["pair_artifact"] = (
                "${{ steps.published-pair.outputs.artifact-id }}"
            )
        if phase == "verify-published":
            steps.append(
                upload(
                    "Retain independently verified acceptance evidence",
                    "packaged-published",
                    "accepted-pair",
                )
            )
            steps.append(
                upload(
                    "Retain fresh post-pull test and cleanup reports",
                    "packaged-pair/post-pull",
                    "post-pull-evidence",
                )
            )
        jobs[phase] = job
    return {
        "name": "Manual packaged container publication",
        "on": {
            "workflow_dispatch": {
                "inputs": {
                    "source_sha": {
                        "description": "Reviewed full overlay and workflow commit SHA",
                        "required": True,
                        "type": "string",
                    }
                }
            }
        },
        "permissions": {},
        "concurrency": {
            "group": "manual-container-publication",
            "cancel-in-progress": False,
        },
        "env": {"SOURCE_SHA": "${{ inputs.source_sha }}"},
        "jobs": jobs,
    }


if __name__ == "__main__":
    print(json.dumps(workflow(), indent=2))
