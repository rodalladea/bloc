# CI build efficiency

Status: agreed

## Problem and scope

Maintainers need faster CI feedback without losing compatibility or release
validation. The maintainer-approved scope retains PostgreSQL 17/18, native
amd64/arm64 distribution and capacity gates, and Debian slim. Application
behavior, capacity limits and publication authority remain unchanged.

## Rules and decisions

Documentation-only changes skip compilation and database fixtures. Distribution
scripts/tests and workflows other than CI run source/policy checks without
database fixtures. Templates, assets, charts, shared tests and unknown paths
retain full checks. Renames include both the removed and added paths. Failed
selection retains source and database jobs unless the workflow is cancelled.

Caches are accelerators, never validation evidence. Rust caches advance per
revision and restore within a compatible toolchain/manifest prefix; distribution
may fall back to the main check lane.
The auditor cache includes its installation script and toolchain; the installer
checks the pinned executable version. BuildKit caches are architecture-specific
and replace the previous local export to avoid retaining unreferenced blobs.

Distribution smoke-tests and capacity-tests the same retained image digest on
each native runner. A failed pull, smoke test or capacity test blocks platform
success and candidate validation. Both native records remain mandatory. The
standalone manual capacity workflow remains available.

## Open questions and assumptions

Hosted cache hit rates and elapsed-time improvements require a subsequent
GitHub Actions run. Local checks cannot establish those measurements.

## Scenarios

### ci-efficiency-01: select checks without hiding runtime changes

Given documentation, distribution-only, runtime or unknown changed paths
When CI selects its jobs
Then documentation skips compilation and databases, distribution-only changes
retain source checks, and runtime or unknown changes retain both database suites.

### ci-efficiency-02: reuse the pinned auditor without skipping the audit

Given an absent, outdated or correctly pinned auditor executable
When the installer prepares dependency auditing
Then only the correctly pinned executable is reused, installation failure stops
validation, and the workflow still executes the advisory audit.

### ci-efficiency-03: measure the image that will be distributed

Given the retained native image layout for amd64 or arm64
When platform validation runs
Then smoke and capacity checks use its same digest without another build,
and any pull, smoke or capacity failure blocks that platform.

## Verification

| Scenario | Delivery / coverage | Evidence |
| --- | --- | --- |
| ci-efficiency-01 | Automated policy coverage | `tests/test_ci_changes.py::ChangesTests.test_runtime_and_shared_fixtures_keep_both_database_suites`, `test_mixed_or_unknown_changes_cannot_hide_runtime_validation`, `test_renaming_runtime_into_documentation_still_selects_database_checks`, `test_selection_failure_keeps_source_and_database_jobs_enabled` |
| ci-efficiency-02 | Automated policy coverage | `tests/test_ci_auditor.py::AuditorTests.test_correct_version_reuses_binary_and_missing_or_wrong_version_installs`; `tests/distribution/test_validation.py::ValidationTests.test_source_checks_overlap_and_every_failure_blocks_candidate_evidence` |
| ci-efficiency-03 | Automated policy coverage | `tests/distribution/test_platform.py::PlatformTests.test_capacity_measures_the_same_digest_without_rebuilding`, `test_pull_smoke_or_capacity_failure_cannot_pass_the_platform`, `test_distribution_waits_for_both_measured_platforms` |

Run the Python checks using the test environment in [README](../../README.md#development):

```sh
python3 -m unittest discover -s tests -p 'test_ci_*.py' -v
python3 -m unittest discover -s tests/distribution -p 'test_*.py' -v
```

Workflow structure checks use the test-only PyYAML dependency with safe loading.
They inspect job dependencies, matrix entries, conditions and command arguments;
YAML indentation and mapping order are not part of the contract. They cover the
explicit conjunctions used by these gates, not arbitrary GitHub expressions.

Policy tests do not establish native capacity or hosted cache behavior. Use the
manual Distribution workflow to verify both real platform images, paired capacity
records, cache restore/save and cluster validation. Keep execution-specific logs,
measurements and results in CI artifacts and the pull request description.

## Release scheduling revision (2026-10-25)

Decision source: the maintainer requested a branch from main implementing the
release optimizations discussed in chat. The following scenarios supersede the
previous scheduling and fixture-budget descriptions, without changing application
limits, normal operator timeouts or immutable publication/retry rules.

### ci-efficiency-04: overlap capacity with cluster validation

Given a newly admitted version or manual validation run
When both native image builds finish
Then native smoke/capacity measurements and source/cluster validation run in
independent jobs against those builds. Only successful results from both paths
can produce the original candidate evidence and enter publication. Missing,
failed, cancelled or mismatched native evidence cannot complete a candidate.

### ci-efficiency-05: share accelerators through main

Given a reviewed change on main affecting the native build or release fixtures
When release cache warming runs
Then both native build caches and the pinned disposable node image are prepared
without publication permissions. Releases may restore main's caches; different
version tags need not read each other's cache scopes. BuildKit may restore an
older architecture-compatible cache and determines which layers remain valid.
Rust may restore main's compatible check-lane cache but still executes all checks.

### ci-efficiency-06: bound intentional failures independently of operator waits

Given the C18 unavailable-image fixture or C19 disconnected-API fixture
When the deliberate failed upgrade runs
Then Helm uses a 60-second timeout with rollback-on-failure; C18 still requires
failed upgrade, successful automatic restoration and healthy A; C19 still requires
failed automatic restoration, retained B and successful explicit restoration.
Successful operations and the documented operator procedure retain five minutes.

Verification: `tests/distribution/test_efficiency.py` covers scheduling, cache
scope/warming configuration and fixture command budgets. `tests/distribution/test_completion.py` and `test_node_image.py`
cover refusal to generate evidence on unsuccessful inputs. Hosted
native measurements, node cache transfer costs and total workflow timing remain
required before claiming an elapsed-time improvement. Both native capacity
measurements still run afresh: unified version changes alter application/image
identity, so chart-only releases do not reuse an older version's measurements.


| Scenario | Local proof | Remaining boundary |
| --- | --- | --- |
| ci-efficiency-04 | `EfficiencyTests.test_cluster_validation_and_native_measurements_share_builds_without_waiting_for_each_other`, `CompletionTests.test_completion_requires_both_bounds_and_current_manifest_identities`, `test_missing_measurement_or_failed_validation_never_completes`, `test_completed_candidate_cannot_be_overwritten`; retained OCI completion round trip passed | Hosted scheduling and both fresh native runs |
| ci-efficiency-05 | `EfficiencyTests.test_main_warms_the_same_native_build_cache_as_releases`, `NodeImageTests.test_absent_cached_present_and_failed_node_images`; actionlint passed | Hosted cache hits and transfer cost |
| ci-efficiency-06 | `EfficiencyTests.test_deliberate_failed_upgrades_use_one_minute_without_shortening_normal_operations`; real C18/C19 passed on Helm 4.3.1 / Kubernetes 1.36.5 | No claim of a full hosted release run |

Author evidence, including local recovery outputs and limitations:
`projects/bloc/.checks/release-pipeline-efficiency-2026-10-25.md`
([Drive](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=4436673fdb817bf7184e3ccf42815bac19dae34aeaa69ef2)).
The complete C18/C19 scenarios took 114.17s/149.07s, including their setup and
cleanup; these are not the durations of the individual 60-second Helm operations.
The OCI completion proof used retained v0.4.1 bytes/measurements, not fresh native
benchmarks. Both temporary namespaces, registry and node-registry configuration
were removed after the local recovery proof.
