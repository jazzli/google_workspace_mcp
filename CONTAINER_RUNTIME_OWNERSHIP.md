# Container runtime ownership

The image runs the service as the non-root `app` user. Application code and
build-installed Python dependencies remain root-owned and are not writable by
that user, the group, or other users. This also makes their paths suitable for
separately authorized maintenance that requires a protected interpreter and
package directory.

Dependencies are installed with `uv sync --frozen --no-dev --extra disk` during
the build. Startup invokes `/app/.venv/bin/python -B` directly: it does not sync
dependencies, install development tools, or write bytecode into the runtime.
The Docker command and bundled Helm override preserve HTTP transport, tool
selection, and the Helm single-user conditional. Python receives signals directly.

## Writable data and migration

- `/app/store_creds` is app-owned with mode `0700`, preserving the Compose data
  location. It is excluded from image build contexts.
- The app user's home remains writable. Default credentials, logs, attachments,
  and disk-backed OAuth state can be created under `/home/app`.
- Other paths under `/app`, including `.venv`, are intentionally not writable.
  Custom data paths must use an explicitly writable directory or mounted volume.
- An existing bind mount or volume overrides image ownership. Check effective
  UID/GID and access separately before upgrading; the entrypoint does not
  recursively change ownership of live data.
- Custom start-command overrides must not run dependency synchronization.
  Align them with the direct-Python entrypoint before adopting this image.

This change does not alter OAuth scopes, storage encryption, credentials,
authorization policy, dependency locks, or maintenance guards.

## Local image tests

Build from a clean checkout with no local credential files. Use a local Docker
engine and retain the image identifier with verification evidence.

```sh
docker build --platform linux/amd64 -t workspace-runtime:test .
uv sync --frozen --extra test
WORKSPACE_MCP_TEST_IMAGE=workspace-runtime:test \
  uv run --frozen --extra test pytest tests/container/test_runtime_image.py -q
```

Set `WORKSPACE_MCP_TEST_DOCKER_CONTEXT` if the local engine uses a named context
(for example `desktop-linux` on Docker Desktop). The default is `default`.
These tests are opt-in; ordinary pytest runs skip them if no image is specified.

The six behavioral cases check:

1. Root-owned, non-group/other-writable interpreter and package paths, including
   resolved targets and original ancestors.
2. Root-owned code/dependencies and actual write denial for the app user.
3. Writable data paths, private `store_creds`, and absence of baked-in credentials.
4. Default startup on a read-only root filesystem with writable temporary home.
5. The same startup with tier-filtered Calendar tools.
6. The same startup with explicit Calendar/Tasks selection.

Startup cases also require a non-root Python PID 1, health `200`, and an
unauthenticated MCP response of `401`. Containers have no host mounts, published
ports, external network, or additional capabilities. Only synthetic OAuth
configuration is used; no authorization exchange or Google API call is made.

Image tests validate container behavior, not deployed volume permissions,
authenticated recovery, or a fully rendered/running Helm deployment. Production
deployment and live verification remain separate release operations.
