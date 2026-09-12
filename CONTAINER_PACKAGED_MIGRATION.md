# Packaged runtime and Content metadata migration

Local candidate implementation. These files do not publish images or authorize
deployment. No existing root Dockerfile or publication workflow is changed.

## Artifact and process contract

| Artifact | Added content | Default | Explicit maintenance use |
| --- | --- | --- | --- |
| R | Root-protected stdlib runtime launcher | UID/GID 1000, `run` | `root-compat` requires an already-root process |
| M | Exact R plus root-protected metadata helper | Same non-root R startup | Root, helper entrypoint and a complete bound operation |

R derives from the exact accepted base in `docker/Dockerfile.runtime`. M must
derive from the exact qualified R artifact. Neither Dockerfile installs packages,
rebuilds the application, downloads code at startup or embeds an operational
manifest. The default invocation cannot select root compatibility automatically.
R contains no metadata migration engine.

The launcher runs as PID 1 using Python 3.11 isolated stdlib mode, validates
protected code and the actual process identity, sets no-new-privileges, closes
inherited extra descriptors, sets HOME and umask, then execs:

```text
/app/.venv/bin/python -B main.py --transport streamable-http
```

Optional TOOL_TIER and whitespace-separated TOOLS become validated argv tokens,
not shell programs. Identifiers must start with an ASCII alphanumeric character;
leading options, shell metacharacters and unknown launcher modes are rejected.

Non-root startup requires real/effective/saved UID/GID 1000, supplementary group
1000, and zero inheritable/permitted/effective/ambient capabilities. The capability
bounding set is measured separately: unprivileged R need not clear that set to
qualify this boundary. M clears all capability sets, including bounding, before
execing R. Root compatibility is a temporary root posture, not a non-root success.

## Metadata engine

The helper operates only on `/data/oauth-proxy` and uses
`/data/.content-permission-migration` for a root-only durable journal. The target
identity is fixed to 1000:1000. Generic provider identifiers are supplied as
non-secret arguments and matched against runtime metadata; the coordinator must
independently verify actual image identity and authorization.

Required flags are:

```text
--operation-id --mutate-until --project-id --environment-id --service-id
--volume-id --runtime-image --migration-image --helper-sha256 --manifest-sha256
```

Each flag takes one value. Duplicates, abbreviations, unknown fields, caller
paths/commands, malformed identifiers and mismatched hashes are rejected. The
manifest hash binds canonical sorted-key JSON of the other nine fields: integer
mutate_until and strings for the remaining fields. Field names use underscores.
No operation values belong in the image.

Record access is metadata-only: pinned no-follow/O_PATH descriptors, same-mount
checks, bounded inventory and intent-before-effect/fsync journal ordering.
Symlinks, hardlinks, special files, unexpected owners/modes and xattrs reject.
Store limits are 512 entries and depth eight. Journal history is bounded to 16
operations; the helper does not prune it.

Fresh mutation requires an unexpired window of at most 30 minutes. Startup and
mutation work retain their own bounded deadlines. A completed matching operation
can restart after expiry using verification only: no repair, journal creation,
or journal rewrite. Serving processes are not killed when mutation authority
expires. Pending or corrupt history blocks automatic replay, including a fresh
operation ID. Durable possible application use forbids inode-based undo.

Fallback is an explicit deployment of the same R in root-compatibility mode
against the **current** store, never an automatic helper action or stale data
restore. New root-owned records following a fully completed migration require a
fresh inventory and separately selected operation before returning to non-root.
Pending operations require diagnosis; changing the UUID is not recovery.

## Local reproduction

Use a disposable Linux/amd64 Docker environment and the exact cached accepted
base. The supplied host harnesses accept explicit `--docker-context default`
(CI) or `--docker-context desktop-linux` (local default). They inspect the named
context and require a local Unix socket and a Linux daemon before fixture work.
`DOCKER_HOST` and `DOCKER_CONTEXT` environment overrides are rejected; no driver
starts a daemon or silently changes context.
No real data, credentials, host directories, published ports or provider access
are needed.

```sh
python3 tests/container/build_packaged_images.py runtime
python3 tests/container/build_packaged_images.py migration --runtime <R-local-config-id>
python3 tests/container/verify_packaged_layers.py --runtime <R-local-config-id> --migration <M-local-config-id>
python3 tests/container/test_packaged_runtime.py --image-id <R-local-config-id>
python3 tests/container/test_packaged_runtime.py --image-id <M-local-config-id> --test-file migration
```

Replace placeholders with the emitted full `sha256:...` local image IDs.
Builders send only an in-memory tar containing the selected Dockerfile and its
one source file. No repository tree is sent. Builds use no build-step network or
dependency steps. M uses a temporary local alias bound to the exact input R ID,
checks identity and ancestry and removes that alias; it is not a release tag.

The layer verifier streams the local OCI export without extracting it, compares
base/R ancestry and checks every added member's ownership, mode, type and source
bytes. The Linux unit driver injects the current public source into a disposable
fixture; those tests alone do **not** qualify built image bytes. Run exact-image
startup tests and the public synthetic pair rehearsal too:

```sh
node tests/container/rehearse_packaged_pair.mjs --docker-context desktop-linux <R-local-config-id> <M-local-config-id>
```

Use Node 22.23.2. The runner retains all eight transition stages, interrupted
migration/fallback, expired authority, wrong-key and mount/entry-boundary tests.
It creates only synthetic named volumes and containers, registers their exact
names before creation, limits work to 600 seconds plus 120 seconds for cleanup,
and permits at most 128 resources. Present or unknown cleanup results fail.

The existing container tests can be run for each image with:

```sh
WORKSPACE_MCP_TEST_DOCKER_CONTEXT=desktop-linux WORKSPACE_MCP_TEST_IMAGE=<local-config-id> python -m pytest tests/container/test_runtime_image.py -q
```

Ordinary host pytest deliberately skips controlled Linux/root fixtures. The
explicit unit driver requires a real controlled Linux/root container; skips are
not accepted as Linux qualification. Default application tests need no Docker.

## Release and live gates

Local config IDs are not registry manifest digests, signatures or provenance.
Before live use: review and commit source through the approved delivery path;
publish R and M separately with source/base bindings; pull and verify exact
published artifacts; confirm provider command tokenization, exclusive volume
handoff, rollback eligibility and fresh cost/window limits.

The synthetic application-factory encrypted DCR tests and separate PID 1 HTTP
checks do not prove Google authorization, refresh-token validity, OAuth end-to-end
persistence or live Railway behavior. Those require their own bounded acceptance.
