# 0003: initial distribution through GHCR and Helm

Status: proposed

## Context

bloc currently serves a dependency-free HTTP scaffold. Operators must compile
source, and the manual release procedure produces no container or chart. The
[design](https://github.com/rodalladea/bloc/issues/2#design-source) records Rodrigo Dalla Dea's
2026-10-15 decision to establish distribution before identity features. The
planning request asks for an ADR and BDD records without committing anything.

This ADR records that confirmed product direction and its explicitly identified
engineering defaults. It does not invent acceptance of the new record under
[governance](../../GOVERNANCE.md), claim packaging exists, or authorize a release.
It extends [ADR 0001](0001-foundation.md) without rewriting its historical decision.
The [task](https://github.com/rodalladea/bloc/issues/2) is the implementation decision
record, including exact contracts and unresolved bootstrap/default review items.

## Options

| Option | Tradeoff and disposition |
| --- | --- |
| Continue source-only delivery until identity features | Defers deployment discovery to feature delivery; rejected by the confirmed distribution-first scope |
| Public GHCR image plus OCI Helm chart | Selected: one registry and explicit operator installation, covering the confirmed Linux platforms |
| Private packages or multiple registries | Credentials or extra publication/support boundaries are unnecessary for the chosen anonymous consumption path |
| Independently version chart and application | Allows chart-only releases but creates separate compatibility identities; deferred until a concrete need appears |
| Floating image aliases or chart tag selection | Convenient updates but no stable deployment identity; use an immutable unified version and multi-platform digest |
| Automatically deploy after publishing | Would require operator cluster authority; excluded by the explicit installation/upgrade model |
| Bundle ingress controller and certificate issuance | Owns infrastructure outside bloc; use operator-provided controller, DNS, and existing TLS secret |
| Claim atomic publication across artifacts | Registry and GitHub writes can fail independently; retain intermediate artifacts and use a verified completion record |

## Decision

Publish the image at `ghcr.io/rodalladea/bloc` and the OCI chart at
`oci://ghcr.io/rodalladea/charts/bloc`, with anonymous consumption verified for
both. Runnable image platforms are `linux/amd64` and `linux/arm64`, both exercised
before announcement. Non-root, read-only operation requires no persistent storage.
Source-local startup remains loopback; the container defaults to `0.0.0.0:3000`.

Start at `0.0.1`: Git and image tags use `v0.0.1`; Cargo, chart version and
appVersion use `0.0.1`. Reconcile the currently unpublished Cargo `0.1.0` and
lockfile during implementation. Retain `publish = false` for crates.io. Use only
complete numeric release versions, no floating aliases, and select the chart's
image by the multi-platform digest. Chart-only changes consume a unified version.

A maintainer pushes a tag from reviewed `main`. The release workflow checks
ancestry, version agreement, Rust checks, dependency audit, both image platforms,
and chart exercises on that revision. PR execution cannot publish. Pin actions
to reviewed full SHAs before privileged publishing and use the short-lived
workflow token with writes limited to the jobs requiring them. Pin build inputs
and retain source/revision metadata, provenance, SBOM, and license notices.

Serialize release publication for each version through inspection and writes.
Verify existing identities before reuse. An image or chart upload may survive a
later failure; do not replace it on retry or rebuild over it. Recover the original
verified artifacts and evidence, or use a new version. A matching completed
release is a verification-only retry. Publish the GitHub completion record only
after both artifacts can be pulled anonymously with the recorded identities.
This is an enforced workflow contract, not a claim that registry administrators
are technically unable to mutate packages outside the workflow.

The chart creates a namespaced Deployment and ClusterIP Service. Default to one
replica, Service port 80 targeting 3000, no Ingress, 30 seconds termination grace,
and RollingUpdate with zero unavailable and one surge replica. Preserve the
source's security, resource and probe defaults in the task. Both probes use
`/healthz` only because the scaffold has no dependencies; readiness is not an
identity or dependency safety assertion. Optional Ingress uses operator-owned
infrastructure, with TLS at the controller and HTTP upstream. It grants no trust
to forwarded identity headers.

Operators save values externally, select explicit chart versions, and perform
upgrades/rollbacks themselves. Document five-minute Helm operation timeouts and
report a failed upgrade as failed even if recovery works. Report recovery failure
separately. Publishing has no deployment authority. Uninstall removes chart-owned
resources, retaining operator-owned TLS secrets and infrastructure.

### Planning defaults

Select **Helm 4.3.1 and Kubernetes 1.36.5** as the initial test baseline. The
[Helm release](https://github.com/helm/helm/releases/tag/v4.3.1),
[compatibility policy](https://helm.sh/docs/topics/version_skew/), and
[Kubernetes release listing](https://kubernetes.io/releases/) were checked on
2026-10-15 after Context7 queries. This is a baseline to exercise, not a passing
test claim. No Helm 3 or all-distribution compatibility claim follows from it.
The exact chart keys, types and validation are in the task's Public chart values
section. Those planning defaults are open for correction before acceptance.

## Consequences

Public package names, saved values, and version identities become operator
contracts. Renaming or changing them later requires compatibility work. One
version simplifies matching artifacts but makes chart-only fixes full releases.
Digest pinning preserves deployment identity rather than silently taking updates.

A release is larger than a successful build: anonymous retrieval, two-platform
execution, cluster installation and failed-upgrade recovery must all have evidence.
Package visibility is a real first-publication prerequisite; a public GitHub
repository does not establish it. Failure after an upload leaves incomplete
packages, and evidence loss can consume a version. Retain historical artifacts
for rollback without promising perpetual security maintenance.

The initial resource settings are bootstrap defaults, not sizing measurements.
Rolling updates need spare capacity and do not guarantee availability through
node failure. Future stateful features must define migration, readiness and
rollback limits separately. Identity, storage, automatic deployment, controllers,
certificate issuance, native downloads and a monitoring stack remain out of scope.

## Behavior and verification

- [Container execution](../behaviors/distribution-container.md): distribution-container-01 through -08.
- [Helm installation/recovery](../behaviors/distribution-helm.md): distribution-helm-01 through -13.
- [Release publication](../behaviors/distribution-release.md): distribution-release-01 through -15.
- [Implementation task](https://github.com/rodalladea/bloc/issues/2): 36 criteria, surface walk, all nine sweep dimensions, public value contract and unresolved items.

All distribution scenarios are planned with missing runtime evidence. Use labeled
local A/B test artifacts before a predecessor exists; never publish fake releases
for tests. Repeat upgrade verification with the actual published predecessor at
the first feature release. This ADR does not supersede the existing scaffold HTTP
behavior or claim authentication, protocol conformance or production readiness.
