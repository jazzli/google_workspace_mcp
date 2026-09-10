# Manual container publication

Container publication is intentionally separate from ordinary pull-request and
merge validation. The publication workflow accepts only a manually supplied,
full commit SHA from reviewed `main` history. It does not publish on pushes,
pull requests, branches, or version tags, and it does not deploy to Railway.

The workflow builds one Linux/amd64 image from a clean checkout of that exact
commit. Before publication it checks the source and image inventories, runs a
fail-closed secret scan, and executes the frozen non-integration test suite with
all six opt-in container cases against the built image. The tested Docker archive
is transferred to a separate publication job; that job cannot rebuild or run the
selected source and is the only job granted package and attestation write access.

Publication creates a run-unique discovery tag containing the workflow run,
attempt, and full source SHA. Registry tags remain mutable and are never the
release identity. Consumers must use the returned `ghcr.io/...@sha256:...`
registry digest. The exact digest reported by the push is checked against a
manifest whose config digest must equal the tested image ID.

That registry digest receives standard GitHub build provenance and a custom
signed receipt binding it to the selected source SHA, source tree, Linux/amd64
platform, tested image ID, archive checksum, actual test totals, resolved
`python:3.11-slim` material digest from BuildKit metadata, and the uv version
reported by the built image. A final package-read-only job verifies both
attestations against the retained build receipt, pulls the digest with the
repository-scoped workflow token, logs out of GHCR before any selected-source
test executes, checks that the pulled image ID and source-relative `/app`
contents match, and repeats the six container tests.

## Release boundary

Merging these controls does not authorize publication. Keep the GitHub workflow
disabled until its trigger and permission contract has been reviewed on the
default branch. Enabling it and dispatching it are separate owner-approved
actions. A successful local test or local image ID is not publication evidence.
The workflow does not change GHCR package visibility; public visibility and
anonymous availability remain separate live checks after first publication.

After an authorized run, retain the workflow/run URL, requested source SHA,
source tree, immutable registry digest, Linux/amd64 manifest identity,
attestation verification, actual test totals, and the retained tested-artifact
receipt. Publication is complete only when the digest-pull verification job is
green. Production promotion and rollback remain separate, explicitly approved
operations.

The current Dockerfile inherits the moving `python:3.11-slim` base and installs
`uv` without a fixed version. The workflow records the artifact it actually
tested and promotes without rebuilding it; it does not claim that rebuilding the
same source later will be bit-for-bit reproducible. Stronger input pinning needs
its own reviewed source change.
