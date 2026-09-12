# Manual publication of the packaged R/M pair

This is a separate, manually dispatched release path for the runtime overlay
**R** and the metadata-migration overlay **M**. It does not deploy either image,
operate a provider, read runtime credentials, or grant migration authority.
The existing full-application publisher and its receipt format are unchanged.

## Source and artifact identity

The fixed accepted base is named in `packaged_release.py`: its manifest, config,
application commit, original publisher commit and original run are separate
identities. The base application source is checked out independently to verify
the unchanged `/app` bytes. Its Docker user is `app`; the new overlays explicitly
declare `1000:1000`.

The new overlay commit must equal both the workflow commit and event commit in
an authorized `workflow_dispatch` on `main`. The workflow accepts only that full
source SHA, not another repository, base, command or image. It checks reviewed
source membership and clean checkout state. An uncommitted local experiment is
not a GitHub release and must not fabricate a release receipt or run identity.

R adds exactly one layer to the accepted base. M adds exactly one layer to the
complete R ancestry. Each build uses a two-file in-memory tar context, no package
installation, and no build-step network. The four qualified launcher/helper and
Dockerfile hashes are fixed. Image config digests identify tested local bytes;
published manifest digests are obtained only from registry publication and
verified against raw manifest bytes and those same configs.

## Four isolated jobs

| Job | Limit | Authority and required result |
| --- | --- | --- |
| `validate` | 5 minutes | Read-only source and accepted-base provenance checks |
| `build-test` | 30 minutes | Read-only registry access; build once, qualify and archive both exact images |
| `publish` | 15 minutes | Registry/attestation writes; load the tested archive, push both roles and attest the pair; no candidate execution |
| `verify-published` | 30 minutes | Read-only verification of both subjects; digest pulls, logout, fresh qualification, then acceptance |

All jobs use GitHub-hosted `ubuntu-24.04` runners. Workflow-level permissions are
empty, each job grants only its listed permissions, action revisions are full
commit SHAs, and concurrency is shared with the original publisher using
`manual-container-publication` with cancellation disabled. Attempts other than
the first fail closed: a rerun is not an authorized retry.

The source workflow is the JSON subset of YAML. `packaged_workflow.py` renders
the reviewable fixed definition to stdout; `validate-workflow` requires exact
structural equality. Review and update both files together. This intentionally
small contract disallows additional triggers, steps or authority by default.

## Qualification and transport

Qualification requires the host non-integration suite, all 14 runtime and 42
migration Linux cases, all six original exact-image tests for **each** role,
Trivy 0.74.0 secret scans, application inventory/source checks, layer inspection,
and the complete eight-stage synthetic storage rehearsal. The source scanner
excludes only `.git` and the installed `.venv`; image scans examine each saved
image. Scan findings cause failure and the potentially sensitive report is
removed instead of uploaded. This is secret scanning, not a vulnerability audit.

Host-only skips for Linux/image cases are not success evidence for those cases:
they must pass in the separate Linux and exact-image runs. Required cases,
stage names, faults and cleanup counts are validated, not just a claimed pass
flag. Report hashes bind the evidence to the build receipt.
Host-suite case identities are SHA-256 hashes of each original JUnit class/name,
so large parameter fixtures cannot inflate the receipt; required Linux/image
case names remain explicit. The original complete JUnit report is also hashed.
The rehearsal has
30 seconds of preflight, 600 seconds of work, a separate 120-second cleanup
budget and a 128-resource ceiling. The parent allows an additional exit margin.
Unknown or present owned resources fail qualification.

Docker contexts are explicitly selected: `desktop-linux` locally, `default` on
the hosted runner. The socket must be local Unix and the daemon Linux. No
implicit Docker host/context override or daemon start is permitted. Test
containers use synthetic data, no provider credentials, no host mounts, no
published ports and no network. Synthetic encrypted storage checks are distinct
from process/HTTP checks; neither proves live Google authorization persistence.

The build job saves both images in one archive and transfers it by the immutable
artifact ID from the same run. The publisher verifies its SHA-256 and config
bytes **before** Docker load, rechecks loaded identities, and never rebuilds.
Unique run/attempt/source tags are conveniences, not acceptance identities. Tag
availability must be positively classified; network or auth errors do not mean
the tag is absent. Existing tags are never overwritten intentionally.

## Provenance and acceptance

Each role receives standard SLSA provenance and a custom predicate containing
its role and the **entire same pair record**. The pair binds both manifest/config
digests, overlay/workflow source, run/attempt and the build receipt hash.

The independent verifier uses `gh attestation verify --bundle-from-oci` with
the exact repository, workflow, source ref, source digest, signer digest,
predicate type and hosted-runner requirement. The Python predicate validator
validates the successfully verified statements; it is not a cryptographic
replacement for `gh`. Both roles and both predicate types must pass before
either candidate is executed. After digest pulls and config checks it logs out
of the registry and runs fresh image scans, layer checks, exact-image tests and
the full rehearsal. Only then can `accept-pair` return `status: accepted` and
`liveReady: false`.

The historical base is verified using its historical publisher identity and
custom receipt, not the new overlay identity. Missing or ambiguous evidence
fails closed; it is not permission to rebuild the base or request new access.

## Failure and delivery boundaries

Publication is not atomic. One push or attestation may succeed before another
fails. The publisher retains known digests with `incomplete-not-accepted`; a
partial pair must not be deployed. Preserve and reconcile the actual registry
and attestation state before proposing another run. Do not automatically retry,
overwrite tags, delete published artifacts or treat known pushed bytes as an
accepted pair. Build, publication and verification artifacts have 14-day
retention; retain a reviewed non-secret acceptance record in the appropriate
operational source of truth before that evidence expires.

The distinct gates are:

1. Local implementation and synthetic qualification (no release claim).
2. Explicit source-delivery approval: reviewed commit, PR and merge, without an
   administrator bypass.
3. Separate authorization to activate/dispatch this manual publisher for the
   exact merged source and verify the resulting pair.
4. Separate provider-specific migration design, fresh inventory, bounded
   authorization, rollback/cleanup and live verification.

Adding this workflow locally does not authorize any later gate. No dispatch or
production command is part of the local qualification procedure. See
`CONTAINER_PACKAGED_MIGRATION.md` for local build and synthetic rehearsal commands.
