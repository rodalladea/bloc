# container execution for bloc

Status: proposed

## Problem and scope

Operators need a distribution path before identity features arrive. This record
covers the container execution slice of [the task](https://github.com/rodalladea/bloc/issues/2)
and the [confirmed design](https://github.com/rodalladea/bloc/issues/2#design-source). It extends the
foundation's delivery path; identity, storage, migrations, automatic deployment,
cloud provisioning, and protocol readiness remain out of scope.

## Rules and decisions

The design records Rodrigo Dalla Dea's scope confirmation on 2026-10-15. The
request to plan it also requests ADR and BDD documents, without commits. Source
engineering defaults and the planning value/matrix defaults are explicit proposals;
implementation evidence below does not claim maintainer acceptance of the proposed ADR.
[ADR 0003](../adr/0003-initial-distribution.md) records rationale and trust boundaries.
The [task](https://github.com/rodalladea/bloc/issues/2) is the decision record if links
later diverge; ask before building a conflicting contract.

The scaffold has no identity authorization. Cluster changes use operator access;
publishing uses maintainer-triggered workflow permissions, and PR code gets no
publication writes. No real credentials or identity fixtures belong in tests.
Existing HTTP expectations remain in [scaffold HTTP](scaffold-http.md).

## Open questions and assumptions

See the task's Unresolved table: GHCR visibility is a go-live prerequisite and
new planning defaults remain open for correction. Container scenarios below passed locally on 2026-10-15. Helm/Kubernetes
coverage is recorded separately in the Helm behavior record. Local A/B artifacts must be labeled test fixtures
and never published as fictitious public releases. Repeat upgrades with the real
published predecessor at the first feature release.

## Scenarios

### distribution-container-01: run the scaffold on both platforms

Given the built image on each of `linux/amd64` and `linux/arm64`, without a Rust toolchain or external service
When an operator starts it and requests the scaffold resources
Then `/`, `/fragments/status`, `/assets/app.css`, and `/assets/htmx.min.js` return 200 with the content types and body markers in scaffold-http-01; `/healthz` returns 200 with exactly `ok\n`; existing security headers and the 404 results in scaffold-http-02 remain unchanged.

Task criterion: 1.

### distribution-container-02: container defaults

Given no environment overrides
When the image starts with a mapped host port
Then HTTP is reachable through `0.0.0.0:3000` and the effective log filter is `info`; running from source still defaults to `127.0.0.1:3000`.

Task criterion: 2.

### distribution-container-03: environment overrides

Given `BLOC_BIND_ADDR=0.0.0.0:4000` and `RUST_LOG=off`
When the image starts
Then HTTP responds on port 4000 and the normal tracing startup message is suppressed, using the existing environment semantics.

Task criterion: 3.

### distribution-container-04: startup rejection

Given each of an invalid bind value `not-an-address` and a listener already occupying the configured address
When bloc starts in the container
Then the process exits nonzero with diagnostic output and does not become a healthy server.

Task criterion: 4.

### distribution-container-05: restricted runtime

Given the image runs as a nonzero UID with a read-only root filesystem and no persistent volume
When an operator requests `/healthz`
Then the response is 200 with `ok\n`, without writable application files or an external database.

Task criterion: 5.

### distribution-container-06: termination

Given an idle running container on each supported architecture
When the operator sends SIGTERM with a 30-second stop budget
Then the application receives the signal and exits before forced termination at 30 seconds.

Task criterion: 6.

### distribution-container-07: platform boundary

Given a candidate multi-platform image
When an operator inspects its runnable platform manifests
Then the supported executable platforms are exactly `linux/amd64` and `linux/arm64`; an unsupported `linux/s390x` pull has no matching executable manifest (attestation manifests are not executable platforms).

Task criterion: 7.

### distribution-container-08: inspect traceability and notices

Given a built image candidate
When a reviewer inspects its metadata, attestations, build inputs, and packaged notices
Then source and revision identify the repository and tested commit, provenance and an SBOM are available, base images use reviewed digests covering both platforms, and the bloc and bundled-asset license notices are present; validation records native execution or the emulation fallback actually used.

Task criterion: 8.

## Verification

| Scenario | Delivery / coverage | Evidence |
| --- | --- | --- |
| distribution-container-01 | Implemented / passed locally | `python3 tests/distribution/container.py --check C1 --image "$BLOC_TEST_IMAGE" --platform "$BLOC_TEST_PLATFORM" --oci-layout "$BLOC_TEST_LAYOUT" --revision "$BLOC_TEST_REVISION"`; both platforms. |
| distribution-container-02 | Implemented / passed locally | `python3 tests/distribution/container.py --check C2 --image "$BLOC_TEST_IMAGE" --platform "$BLOC_TEST_PLATFORM" --oci-layout "$BLOC_TEST_LAYOUT" --revision "$BLOC_TEST_REVISION"`; both platforms. |
| distribution-container-03 | Implemented / passed locally | `python3 tests/distribution/container.py --check C3 --image "$BLOC_TEST_IMAGE" --platform "$BLOC_TEST_PLATFORM" --oci-layout "$BLOC_TEST_LAYOUT" --revision "$BLOC_TEST_REVISION"`; both platforms. |
| distribution-container-04 | Implemented / passed locally | `python3 tests/distribution/container.py --check C4 --image "$BLOC_TEST_IMAGE" --platform "$BLOC_TEST_PLATFORM" --oci-layout "$BLOC_TEST_LAYOUT" --revision "$BLOC_TEST_REVISION"`; both platforms. |
| distribution-container-05 | Implemented / passed locally | `python3 tests/distribution/container.py --check C5 --image "$BLOC_TEST_IMAGE" --platform "$BLOC_TEST_PLATFORM" --oci-layout "$BLOC_TEST_LAYOUT" --revision "$BLOC_TEST_REVISION"`; both platforms. |
| distribution-container-06 | Implemented / passed locally | `python3 tests/distribution/container.py --check C6 --image "$BLOC_TEST_IMAGE" --platform "$BLOC_TEST_PLATFORM" --oci-layout "$BLOC_TEST_LAYOUT" --revision "$BLOC_TEST_REVISION"`; both platforms. |
| distribution-container-07 | Implemented / passed locally | `python3 tests/distribution/container.py --check C7 --image "$BLOC_TEST_IMAGE" --platform "$BLOC_TEST_PLATFORM" --oci-layout "$BLOC_TEST_LAYOUT" --revision "$BLOC_TEST_REVISION"`; both platforms. |
| distribution-container-08 | Implemented / passed locally | `python3 tests/distribution/container.py --check C8 --image "$BLOC_TEST_IMAGE" --platform "$BLOC_TEST_PLATFORM" --oci-layout "$BLOC_TEST_LAYOUT" --revision "$BLOC_TEST_REVISION"`; both platforms. |

Local evidence: candidate index
`sha256:8472bfabcf3869fb10ca2f4d8307ca3e22678428a6582f7e318306f1918134cc`,
source label `e0cbb1de97c1ba6d4c745539f768448fcbcbfa3e` plus the uncommitted
packaging diff. Linux arm64 ran natively in Docker Desktop; linux amd64 ran
under Docker Desktop emulation on the same aarch64 host. All C1–C8 passed.
C8 additionally queried both pinned base-image indexes for both executable
platforms. `python3 tests/distribution/source.py` passed C2's unchanged source
loopback default using the actual source binary and HTTP.

These are local fixture artifacts, not published releases. The release workflow
must rerun checks on its tagged revision and retain that revision's attestations.
