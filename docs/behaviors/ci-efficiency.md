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
revision and restore only within a compatible lane/toolchain/manifest prefix.
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
