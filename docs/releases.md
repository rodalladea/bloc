# repository setup and releases

## Hosting setup

The canonical repository is [rodalladea/bloc](https://github.com/rodalladea/bloc),
owned and maintained by Rodrigo Dalla Dea (@rodalladea). These are the intended
settings; verify them on GitHub when administering the repository:

- Enable private vulnerability reporting. Private security and conduct contact:
  rodalladea@catap.io. Keep GOVERNANCE.md and CODEOWNERS current.
- Protect `main`: require PRs, resolved discussions, an up-to-date branch, and the
  `check` and `pr-title` checks, including for administrators. Disallow force
  pushes and deletion. Require zero approvals while Rodrigo is the sole
  maintainer; do not require code-owner or last-push approval. Revisit independent
  approval when a second active maintainer joins.
- Allow squash merges and use the PR title for the commit subject. Limit bypasses
  and workflow write permissions. Delete merged branches automatically. Enable
  dependency alerts and security updates, secret scanning, and push protection.
- Give Actions read-only default token permissions and disable workflow PR
  approval. Require maintainer approval before running first-time contributors'
  fork workflows.
- Keep issues enabled and documentation in the repository; a separate wiki and
  project board are unnecessary at this stage. Keep description and topics aligned
  with the scaffold's actual capabilities.
- Bootstrap the empty repository once, then use PRs. Verify hosted CI and the
  required checks after setup. Do not claim settings are enabled until verified.

## Release procedure

Distribution targets `ghcr.io/rodalladea/bloc` and
`oci://ghcr.io/rodalladea/charts/bloc`. The first version is `0.0.1`. Git/image tags
use `v0.0.1`; Cargo, the bloc lockfile entry, chart version and appVersion use
`0.0.1`. `publish = false` still prevents crates.io publication. Chart-only changes
consume a new unified version. No floating image aliases are published.

The distribution workflow runs on PRs, `main`, and `v*` tags. Only a maintainer's
complete numeric `vX.Y.Z` tag on a commit belonging to reviewed `main` can enter
publication. Prerelease, partial, leading-zero and disagreeing versions fail
admission. Publishing never deploys to an operator's cluster.

Before the first public release, confirm both GHCR package permissions and public
visibility. The public source repository does not make its packages public.
A first upload can create a private package: the anonymous gate then fails and
leaves the release incomplete. Correct visibility and rerun with original evidence.
This repository change does not itself publish a release or confirm package access.

1. Review the proposed [ADR 0003](adr/0003-initial-distribution.md), behavior
   evidence, security issues, licenses, and limitations. Authentication remains
   unimplemented; the first release is explicitly a scaffold.
2. Set all version fields together and move appropriate Unreleased changelog notes
   into a dated release section. Review the PR and its distribution checks.
3. Merge the reviewed source. The maintainer explicitly creates and pushes its
   numeric version tag. Never create a fake public release to test upgrades.
4. The tagged revision reruns Rust formatting, lint, tests, documentation and
   dependency audit. Native amd64 and arm64 jobs build attested OCI artifacts and
   exercise the exact bytes locally. The combined image is checked for both
   platforms, provenance and SBOM, then the chart is tested against Helm 4.3.1 /
   Kubernetes 1.36.5, including a failing upgrade and recovery.
5. Only after these gates pass does Actions retain the candidate bundle. The
   publisher inspects existing identities, uploads only missing verified artifacts,
   verifies all content anonymously, and pulls with Docker on each platform and
   Helm using empty credential configuration. The GitHub completion record comes
   last, with revision, version, platforms, tested tool versions, digests, limitations
   and explicit-version installation/recovery instructions.

See [installation](install.md) for the operator procedures. Local A/B fixtures
rehearse lifecycle changes before a predecessor exists. Repeat with the actual
published predecessor at the first feature release. Retain historical packages
for rollback; retention is not a promise of security support for old releases.

## Partial publication and retries

There is no transaction spanning GHCR and GitHub. An upload may survive a later
failure. The workflow reports the incomplete stage and preserves available bytes
and evidence; do not delete or replace those packages to make a rerun pass.

Same-ref workflow concurrency encloses inspection, validation and publication,
with cancellation disabled. Candidate artifacts are named
`candidate-vX.Y.Z-<revision>` and retained for 90 days (subject to repository limits).
Recovery accepts artifacts only from this repository's tag/push distribution
workflow at the same source revision. Archive integrity, embedded source/version,
image/chart digests, required checks and the validation baseline are checked again.

- Missing artifacts with no existing version may be built and validated.
- A partial release with original evidence reuses matching bytes and publishes
  only missing artifacts. It does not rebuild an uploaded version.
- A digest/source conflict, missing original evidence for an existing version,
  or inaccessible registry stops the attempt. Use a new version when original
  identities cannot be established; never overwrite a version.
- A matching completed release is verification-only: image digest, chart digest,
  and release record remain unchanged.

Rerun the original tag workflow through Actions. No manual `workflow_dispatch`
publication entry point or automatic tag creation is provided. Save the candidate
bundle and run logs before their retention expires if a recovery may take longer.
Do not alter the `evidence.json` checklist to bypass a failed validation.

## Automation boundaries and checks

Actions are pinned to full commit SHAs. Preparation has only contents/actions/
packages reads. Build and cluster validation have no publication writes. Only the
publisher receives `contents: write` and `packages: write`; its short-lived
`github.token` supplies registry credentials. It receives no kubeconfig and runs
no deployment commands. Never run untrusted PR code with publication permissions.

Run the README Rust checks and `cargo audit`. Distribution proofs live in
`tests/distribution/`; the workflow invokes
`scripts/distribution/validate.sh` after the two native platform jobs.
`tests/distribution/setup-cluster.sh` creates only disposable kind resources and
uses a separately owned ingress controller fixture. It requires Docker, the
pinned Helm/kind clients, kubectl, Python 3.11+, curl and OpenSSL. It does not use a
production Kubernetes context. Detailed local results and gaps belong in the
BDD evidence tables, not in a claim that all hosted workflow paths have run.

The OCI adapter follows the [OCI distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md).
Action metadata was checked against the official tagged commits; Helm/kind tool
archives use release-published SHA256 checksums. Review pins and dependency
updates before changing them. The registry itself can be modified by administrators;
immutability is enforced by this workflow, not asserted as a registry guarantee.
