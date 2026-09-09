# Read-only client inspector — local review, not deployed

Prepared 2026-09-09 for Jazz's personal MCP failed-registration investigation.
The owner approved local preparation and synthetic verification only. This is
application-owned storage code; infrastructure remains responsible for any
future execution envelope. The inspector remains read-only. The separately
prepared one-shot maintenance module described below adds an exact retirement
process; no authenticated transport, deployment hook or live operation is enabled.

`core/oauth_client_inspection.py` accepts an explicit canonical disk directory,
expected file owner, exact downstream public client metadata and an already
constructed, in-process storage Fernet object. A future caller must independently
verify the authorized project/environment/service/deployment and protected owner
policy. These checks are **not implemented by this local adapter**. Do not run it
on production, export credential-bearing files for inspection, or pass key
material through command arguments, chat, logs or repository files.

The provider model must already be loaded in a separately authorized application
runtime. The inspector checks `sys.modules` and refuses an uninitialized runtime;
it never imports FastMCP itself, because that import can load `.env` or
`FASTMCP_ENV_FILE` and configure logging. No process-attachment or application
endpoint is provided here. Adding an execution route is a separate design and
authorization decision, not permission to work around this guard.

## Narrow contract

- Requires FastMCP 3.2.4, MCP 1.27.0 and py-key-value-aio 0.4.4.
- Supports only the application's `core.storage.make_sanitized_file_store`
  layout: passthrough collection, canonical lowercase UUID-v4 key, default
  metadata directory, BasicSerializationAdapter and Fernet wrapper version 1.
- Opens exactly the collection info and one client record, without directory
  enumeration. Uses no-follow descriptor-relative reads, owner/mode/link/size
  checks, bounded JSON input and post-read identity checks. Metadata may be
  0600/0644; client files must be 0600. Root and collection cannot be writable
  by group/others. File contents and mtime are unchanged; access time may change.
  The complete collection-info schema must be valid. Checks are not a lock or
  an atomic cross-process snapshot; any future mutation must revalidate under
  its own exclusive coordination and authority.
- Reuses the provider's serialization, strict encryption wrapper and
  ProxyDCRClient/PydanticAdapter schema. Does not instantiate FileTreeStore:
  collection setup can create an info file even with `auto_create=False`.
- Rejects plaintext fallback, corrupt ciphertext, schema failures, unexpected
  envelope versions, TTL-bearing registrations and changed filesystem bindings.
- Matches client ID/name, one exact loopback callback, public method `none`, no
  client secret/CIMD document, exact nonduplicated scopes and the two canary grant
  types. It returns only a fixed classification, `related_state: unknown` and
  `cleanup_ready: false`. It does not return records or exception messages.

`matched` means only the observed registration matched expectations.
`candidate_missing` means only that one candidate file was not found in the
validated mapping; it is **not** authenticated absence or token revocation proof.
Other results are `invalid_input`, `unsupported_runtime`, `unreadable_or_unsafe`,
`invalid_record`, or `mismatch`. None authorizes mutation.

## Important unresolved limit

The pinned proxy keys transactions by random transaction ID, codes by code,
upstream token sets by independent token ID, JTI mappings by JTI, and refresh
metadata by token hash. It supplies no client-ID index for those related stores.
This inspector therefore cannot prove related-state absence from a client ID.
It must not scan unrelated records to fill that gap. Client retirement and local
attempt removal require a separate exact execution envelope. Jazz subsequently
accepted related state **unknown** only for the historical failed Content
bootstrap specified in the maintenance target below. This policy exception
does not alter the inspector's factual result or authorize local execution now.

References: [FastMCP 3.2.4 proxy storage](https://github.com/PrefectHQ/fastmcp/blob/v3.2.4/src/fastmcp/server/auth/oauth_proxy/proxy.py),
[proxy models](https://github.com/PrefectHQ/fastmcp/blob/v3.2.4/src/fastmcp/server/auth/oauth_proxy/models.py),
and this checkout's `uv.lock` and `core/storage.py`. No upstream Google OAuth
application, user grant, production key or token is a cleanup target here.

## Synthetic verification

Run with this checkout's locked Python environment:

```sh
FASTMCP_ENV_FILE=/dev/null .venv/bin/python -m pytest tests/core/test_oauth_client_inspection.py tests/core/test_storage.py -q
```

Fixtures create fresh throwaway keys and records through the actual application
FileTree factory, encryption wrapper and provider schema. No owner credentials,
real canary state, production filesystem or external endpoint is used. Passing
tests do not mean the inspector has been run live or monitoring has recovered.

Local September 9 evidence: 37 inspector tests and 32 adjacent storage/OAuth
tests passed (69 total); Ruff lint/format checks passed. Independent review found
and then rechecked fixes for the import-time dotenv side effect, a directory
permission snapshot race and incomplete collection metadata validation. Each
had a witnessed failing synthetic regression before correction. Catalog
`make check` separately passed 94 tests, 30 records and enforcement validation.
No source was committed, published or deployed by this preparation.

## Exact one-shot maintenance contract (local preparation only)

`core/oauth_client_maintenance.py` is a standalone sibling of the inspector.
It contains no server route, startup hook, generic command facility, credential
file loader, SSH registration or live transport. The only target is the literal
`TARGET` table in that source: the historical Content deployment and failed
client/attempt from the September 9 recovery plan. Any deployment/source drift
fails closed and requires a revised reviewed target. Pinned package versions
remain FastMCP 3.2.4, MCP 1.27.0 and py-key-value-aio 0.4.4.

The strict request is one JSON object (maximum 16,384 bytes) with exactly:

| Field | Contract |
| --- | --- |
| `schema` | integer 1 (boolean rejected) |
| `request_id` | canonical lowercase UUID v4, unique per invocation |
| `mode` | literal `inspect` or `retire` |
| `issued_at`, `expires_at` | UTC ISO calendar timestamps with `T`, seconds, optional 1–6 fractional digits, and `Z` or `+00:00`; issued ≤ now < expires; lifetime ≤300 seconds |
| `approval_sha256` | lowercase 64-hex hash of the protected approved envelope; caller verifies what that hash authorizes |
| `artifact_sha256` | lowercase 64-hex combined reviewed-source digest described below |
| `target` | exact `TARGET` object, including types and every field |
| `scopes` | exact sorted, duplicate-free protected-policy scope array |
| `filesystem` | exactly `root`, `collection`, `info`, `candidate` |

Directory identities are arrays of decimal strings in this order:
`dev, ino, uid, gid, mode, nlink`. File identities append
`size, mtime_ns, ctime_ns`. These are strings to avoid JavaScript integer
precision loss. `candidate` may be null only for a candidate-missing
observation, which never becomes verified retirement. Only exact metadata and
the one client candidate are read; unrelated stores are never scanned.

Duplicate JSON fields, nonfinite numbers, unknown fields, unsafe paths/keys,
wrong callback/scopes, malformed/plaintext/corrupt records and changed
filesystem bindings fail closed. Request data is not self-authorizing.

The result is at most 4,096 bytes with exactly `request_id`, `target`, `mode`,
`result`, `related_state`. Target is always the fixed table; related state is
always `unknown`. Results are `matched`, `retired_verified`,
`candidate_missing`, `invalid_request`, `unsupported_runtime`,
`target_mismatch`, `runtime_key_unavailable`, `invalid_record`, `mismatch`,
`filesystem_changed`, or `uncertain`. Invalid requests have null request ID and
mode so attacker-controlled input is never echoed. `parse_result(bytes, request)`
validates shape and correlation, not transport authenticity.

`source_digest()` hashes, in order, `oauth_client_maintenance.py` then
`oauth_client_inspection.py`. For each it appends UTF-8 filename, NUL, ASCII
decimal byte length, NUL, then the exact source bytes to SHA-256. The request
must already bind this digest. `build_bundle(request)` returns exactly those
two byte payloads plus `request.json`; it does not silently rewrite the request.

The authenticated root-side runner calls `stage_bundle(bundle)` to create one
fresh `/tmp/oauth-client-maintenance-<random>` directory (0700) and the three
fixed files (0600). The returned `StagedBundle` owns its descriptor and identity;
`verify()` checks identity, ownership/modes, links, sizes, hashes, before/after
file stats and exact named contents. A partial creation closes descriptors and
retains only that partial stage for explicit reconciliation. For local
synthetic tests only, the trusted caller can pass its current `owner_uid`.
The production `main` still requires root; no UID/path is accepted on the wire.

`stage.invoke(transport, request, context)` verifies once, invokes once and
attempts exact cleanup, even on timeout. Context has exactly
`approval_sha256`, `artifact_sha256`, `scopes`, `runtime_target`, independently
obtained from the authenticated operator's approved envelope and protected
policy. The helper adds `stage_identity` and `stage_files` to stdin. The fixed
argv is `/app/.venv/bin/python -I -B -S <owned-stage>/oauth_client_maintenance.py`.
The trusted callable accepts `(argv, *, input: bytes, timeout: 30,
output_limit: 4096)` and returns stdout bytes. It must enforce timeout and the
output cap, discard stderr, reject nonzero exit, and never retry. This callable
is a programmatic authenticated-process capability, not a receipt-file CLI or
JSON claim that a transport is authenticated. The live implementation and
authentication/delivery setup remain the outer controller's responsibility.

The `-S` flag disables site/.pth startup hooks before the module can install its
controls. The entry requires Python 3.11 and isolated/no-bytecode/no-site flags;
after controls and stage verification it appends only the fixed canonical
`/app/.venv/lib/python3.11/site-packages` directory, without running site hooks.
Before any genuine FastMCP imports, `main` redirects stdout/stderr, disables
logging, warnings, exception output, core dumps and bytecode, and sets
`FASTMCP_ENV_FILE=/dev/null`, `FASTMCP_LOG_ENABLED=false` and
`FASTMCP_TEST_MODE=false`. It then verifies the root-owned stage and source
digests, parses the request, and checks the exact Railway project, environment,
service, deployment and source commit against runtime identity variables.
It verifies disk backend/directory selection using the canonical application
rules and refuses Valkey selection. The volume ID is an authenticated outer
attestation, not independently discoverable from environment metadata.
The outer controller must freshly verify actual runtime UID, executable,
dependency installation, target and volume before any live staging.

Only after those checks does the process use its existing
`FASTMCP_SERVER_AUTH_GOOGLE_JWT_SIGNING_KEY` internally. Missing runtime delivery
stops; there is no fallback to upstream client secret, credential files, dotenv,
Railway variable export or another process's environment. The canonical
low-entropy JWT derivation and high-entropy storage derivation run in memory.
No key enters source, arguments, output or operator evidence.

`execute_request(...)` and `process_request(...)` expose trusted Python
dependency boundaries for synthetic tests and the fixed entry. They must not
be exposed as public application APIs. The former accepts explicit runtime
identity, approved hash/scopes, source digest, root/UID and in-process signing
override; the latter checks runtime identity/environment and reads only that
override. Standalone consumers must install `controlled_runtime()` first.

Inspection and retirement use separate fresh request UUIDs. Retirement verifies
the current exact filesystem identity, authenticates/decrypts and matches the
record through the existing inspector, rechecks that same snapshot immediately
before exact descriptor-relative unlink, fsyncs the directory and verifies
absence through the validated mapping. `candidate_missing` is never promoted
to `retired_verified`. `retired_verified` says nothing about token revocation,
in-flight requests or related-store absence.

POSIX does not offer an atomic compare-inode-and-unlink operation. An outside
writer can race the last check; approved maintenance requires coordinated
writers. Neither local locks nor this process can stop nonparticipating
production writers. Cleanup has the same final name-operation race against
another process with the same privileged identity; it revalidates the stage,
removes only three named files and its empty directory, and never recurses.
Changed identities, unexpected contents, cleanup failures and uncertain
transport/deletion retain the outer checkpoint and require reconciliation.
No assumption of a successful retry is safe after timeout.

The process rejects reused UUIDs in the same process, but cannot detect replay
across fresh processes. The outer controller must durably record dispatch before
retirement, reject cross-process replay, and preserve the request/outcome record.
The two-file/one-request remote stage deliberately contains no replay database.

Synthetic tests exercise real pinned serializers, encryption and models,
isolated process imports/output, staging files and a fake authenticated process
capability. Local macOS tests do not prove a root/Linux production invocation,
production permissions, provider state, authentication or recovery completion.
