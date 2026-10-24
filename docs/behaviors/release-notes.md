# Version-specific release notes

Status: implemented

## Problem and scope

The maintainer requested English release titles and descriptions that reflect each
version instead of repeating administrator-access copy (chat, 2026-10-24).
This change covers future publication. At the maintainer’s explicit request
(chat, 2026-10-24), existing release titles and change descriptions are corrected
once, preserving their distribution metadata and identity evidence. Automated
retries still follow the [retry policy](../releases.md#partial-publication-and-retries).
No artifact, deployment or identity protocol behavior changes.

## Rules and decisions

Use `bloc vX.Y.Z` as the title and the exact matching dated CHANGELOG.md section
as the change description. Keep distribution identities and recovery instructions.
Reject missing, empty or duplicate version sections before uploading artifacts.

## Open questions and assumptions

None. The repository changelog remains English and is reviewed with release source.

## Scenarios

### release-notes-01: Match the version

Given dated sections for multiple versions and Unreleased changes,
when a version is published,
then only its change section appears, with a version-specific title and retained
artifact identity evidence and recovery instructions.

### release-notes-02: Reject unavailable notes

Given a missing, empty or duplicate dated version section,
when publication starts,
then it fails before artifact uploads or a GitHub release is created.

## Verification

| Scenario | Coverage | Evidence in tests/distribution/test_release.py |
| --- | --- | --- |
| release-notes-01 | Automated | test_release_notes_select_only_matching_changelog_section; test_release_title_and_identity_evidence; test_c34_notes_contain_identities_and_recovery |
| release-notes-02 | Automated | test_release_notes_reject_missing_empty_and_duplicate_versions; test_missing_changelog_stops_before_artifact_upload |

New selection/rejection tests failed before implementation. Publication-policy
tests passed: 38 distribution tests, using Helm 4.3.1 and the pinned test-only
YAML parser. All five published releases were edited and read back; their tags,
assets, distribution text and identity markers were preserved. No artifacts or tags
are republished when correcting existing release metadata.
