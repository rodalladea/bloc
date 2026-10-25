# helm installation and recovery for bloc

Status: proposed

## Problem and scope

Operators need a distribution path before identity features arrive. This record
covers the helm installation and recovery slice of [the task](https://github.com/rodalladea/bloc/issues/2)
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
new planning defaults remain open for correction. Local distribution scenarios run against Helm 4.3.1 / Kubernetes 1.36.5.
This is a bounded test baseline, not universal compatibility. Local A/B artifacts must be labeled test fixtures
and never published as fictitious public releases. Repeat upgrades with the real
published predecessor at the first feature release.

## Scenarios

### distribution-helm-01: default installation

Given Helm 4.3.1, Kubernetes 1.36.5, and a disposable namespace with capacity for the workload
When an operator installs an explicit chart version using the documented five-minute wait procedure
Then one replica becomes ready behind a ClusterIP Service on port 80 targeting port 3000, port-forwarded `/healthz` returns 200 with `ok\n`, and the chart creates no Ingress or cluster-wide resources.

Task criterion: 9.

### distribution-helm-02: runtime policy

Given default chart values
When the operator inspects the installed workload
Then it runs non-root with a read-only root filesystem, all Linux capabilities dropped, privilege escalation disabled, RuntimeDefault seccomp, and no mounted service-account token; requests are 100m CPU and 64Mi memory, memory limit is 128Mi, and no CPU limit is set.

Task criterion: 10.

### distribution-helm-03: rollout policy

Given a ready default installation and capacity for a surge Pod
When an operator upgrades to a valid distinguishable local test artifact
Then the Deployment uses RollingUpdate with maxUnavailable 0, maxSurge 1, and terminationGracePeriodSeconds 30; the rollout completes and the selected new digest serves HTTP.

Task criterion: 11.

### distribution-helm-04: operator configuration

Given the [task’s public value contract](https://github.com/rodalladea/bloc/issues/2#public-chart-values) and a reachable mirror of the same test image
When an operator renders and installs with replicaCount 2, the mirror repository/digest, logLevel debug, requests 200m/96Mi, memory limit 192Mi, and scheduling constraints matching the test node
Then the resulting workload has two replicas, uses the selected digest, exposes the selected log filter, resources and scheduling constraints, and remains reachable on chart-controlled port 3000.

Task criterion: 12.

### distribution-helm-05: reject invalid values

Given each invalid fixture in the [task’s public value contract](https://github.com/rodalladea/bloc/issues/2#public-chart-values)
When an operator attempts the documented install or upgrade with schema validation enabled
Then the command exits nonzero naming the invalid value before applying chart resources; a prior successful installation remains unchanged.

Task criterion: 13.

### distribution-helm-06: optional ingress

Given an existing ingress controller, working DNS, and an operator-owned TLS secret for `bloc.example.test`
When the operator enables Ingress using the configured class, hostname, annotations, and TLS secret
Then the rendered namespaced Ingress routes `/` to the Service and HTTPS `/healthz` returns 200 with `ok\n`; TLS terminates at the supplied controller and its upstream uses HTTP.

Task criterion: 14.

### distribution-helm-07: missing ingress prerequisites

Given Ingress is enabled but each of controller, DNS, or TLS secret is missing in a separate fixture
When the operator follows installation troubleshooting
Then the runbook distinguishes that missing prerequisite from Pod health and does not claim external HTTPS works merely because the Pod is ready; the chart provisions zero controllers or certificates.

Task criterion: 15.

### distribution-helm-08: probe failure

Given the installed process is made unresponsive in a disposable test
When the readiness and liveness probes fail
Then both probes target `/healthz` on port 3000 with periodSeconds 10, timeoutSeconds 2 and failureThreshold 3; readiness failure excludes the Pod from Service traffic and liveness failure causes a restart with Kubernetes events.

Task criterion: 16.

### distribution-helm-09: saved-values upgrade

Given a successful local fixture release A and a different candidate B, with saved operator values outside the cluster
When the operator follows the explicit-version upgrade procedure with the saved values
Then Helm records a new revision selecting B, preserves those values, and HTTP verification succeeds without compiling Rust or editing deployment templates.

Task criterion: 17.

### distribution-helm-10: failed upgrade recovery

Given a successful release A and a candidate B whose Pods cannot become ready
When the operator follows the upgrade procedure using a five-minute timeout and rollback-on-failure
Then the command reports upgrade failure with a nonzero exit, attempts restoration of the previous successful revision, and the restored A passes HTTP verification.

Task criterion: 18.

### distribution-helm-11: recovery failure

Given a failed upgrade whose restoration is also prevented, such as by a lost Kubernetes connection
When the documented recovery procedure runs
Then the outcome remains failed and separately identifies recovery failure and inspection steps; it does not report a successful installation.

Task criterion: 19.

### distribution-helm-12: explicit rollback

Given successful distinguishable revisions A then B in Helm history
When the operator selects A using the documented rollback and five-minute wait procedure
Then Helm restores A and HTTP verification confirms A serves again.

Task criterion: 20.

### distribution-helm-13: uninstall ownership

Given an installed release plus operator-owned TLS secret and ingress infrastructure
When the operator uninstalls the release
Then chart-owned resources are removed, the operator-owned secret and infrastructure remain, and there is no bloc persistent data to remove.

Task criterion: 21.

## Verification

The batched launcher runs C9–C18/C20–C21 and C19 concurrently in separate
PID-specific namespaces. Only the lifecycle process creates the test Ingress.
Both processes must succeed. The 2026-10-25 maintainer-approved
[CI efficiency revision](ci-efficiency.md#release-scheduling-revision-2026-10-25)
changes only the intentionally failing C18/C19 upgrades to 60-second fixture
budgets. Normal operations and the operator runbook retain five minutes. C18 now
also requires Helm to report completed automatic rollback; the remaining scenario
assertions are retained. `test_parallel.py` verifies concurrent start, complete
scenario selection, and failure propagation from either process.

| Scenario | Delivery / coverage | Evidence |
| --- | --- | --- |
| distribution-helm-01 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C9 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-02 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C10 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-03 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C11 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-04 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C12 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-05 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C13 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-06 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C14 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-07 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C15 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-08 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C16 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-09 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C17 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-10 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C18 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-11 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C19 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-12 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C20 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |
| distribution-helm-13 | Implemented / passed locally | `python3 tests/distribution/cluster.py --check C21 --image "$BLOC_TEST_IMAGE"` with the fixture environment in `.checks/initial-distribution.md`. |

The batched command `bash tests/distribution/setup-cluster.sh <verified-OCI-layout>`
builds the exact disposable kind node baseline when absent, supplies a local OCI
registry and mirror, and creates operator-owned Traefik/TLS fixtures outside the
chart. It runs all C9–C21 and writes `evidence/cluster.log`.

A and B are explicitly local fixtures. Their packaged chart defaults select
different image digests; ordinary saved operator values remain identical across
the A→B upgrade. The mirror exercise is separate. Probe failure stops the bloc
process from the disposable node's parent PID namespace. Recovery failure cuts a
localhost API proxy after an invalid B is applied, leaving the real cluster
reachable for inspection and subsequent explicit restoration.

HTTPS uses synthetic `bloc.example.test` with curl's explicit resolution and a
locally generated certificate; no public DNS or certificates were provisioned.
Missing DNS, selected controller and TLS secret are exercised independently of
healthy Pod/Service HTTP. This proves the local routing contract, not an external
cloud load balancer or production infrastructure.

Local evidence on 2026-10-15: `evidence/cluster-ingress.log` records successful
C9–C12, C14–C15, C17, C20–C21 on the final fixture implementation. Earlier
full runs passed C13's twelve rejection fixtures, C16's actual probe exclusion
and restart, and C18's five-minute failed upgrade followed by restored HTTP.
C19's original exact-word diagnostic assertion was corrected with explicit user
approval; it now checks Helm's actual failed prior-release lookup diagnostic
and retains failed-state/manual-restoration assertions. Its final targeted
result is recorded separately in `evidence/cluster-recovery.log`.

The user-approved corrected C19 proof completed with exit 0: failed upgrade,
failed automatic recovery, retained failing B state, explicit restoration of A,
and HTTP verification all passed on the stated baseline. All C9–C21 now have
local runtime evidence across these focused runs.
