# immutable release publication for bloc

Status: proposed

## Problem and scope

Operators need a distribution path before identity features arrive. This record
covers the immutable release publication slice of [the task](https://github.com/rodalladea/bloc/issues/2)
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
new planning defaults remain open for correction. Local release decision and registry exercises passed on 2026-10-15.
Actual anonymous GHCR access remains a go-live check. Local A/B artifacts must be labeled test fixtures
and never published as fictitious public releases. Repeat upgrades with the real
published predecessor at the first feature release.

## Scenarios

### distribution-release-01: pull-request validation

Given an untrusted pull request
When its validation workflows execute
Then Rust formatting, lint, tests, documentation, dependency audit, image smoke checks on both platforms, and relevant chart exercises run with no publication write credentials and create no public release.

Task criterion: 22.

### distribution-release-02: release admission

Given each of `v0.0`, `v0.0.1-rc.1`, a `v0.0.1` tag with Cargo version 0.1.0, and a valid version tag on a commit outside main
When release validation evaluates that input
Then it rejects the invalid tag, version disagreement, or ancestry respectively before publishing artifacts, with a diagnostic identifying the cause; tags filtered from workflow triggering are also covered by validator tests.

Task criterion: 23.

### distribution-release-03: required checks gate publication

Given a valid main-branch tag
When any required Rust check, audit, image build, platform smoke check, or chart exercise fails
Then the run fails before release artifact promotion and creates no published GitHub release; the successful path reruns these checks on the tagged revision rather than trusting the tag.

Task criterion: 24.

### distribution-release-04: one version across artifacts

Given the first releasable main revision
When the maintainer publishes tag `v0.0.1` after validation
Then Cargo.toml and the bloc Cargo.lock entry, chart version, and chart appVersion all read `0.0.1`; image tag `v0.0.1` resolves to the verified multi-platform digest and the packaged chart selects that digest.

Task criterion: 25.

### distribution-release-05: anonymous artifact consumption

Given both verified artifacts have been published
When a client with an empty registry credential configuration pulls image `ghcr.io/rodalladea/bloc:v0.0.1` on each supported platform and chart `oci://ghcr.io/rodalladea/charts/bloc` at version `0.0.1`
Then all pulls succeed anonymously and match the recorded source revision and image/chart digests before a GitHub release is published.

Task criterion: 26.

### distribution-release-06: private package gate

Given either GHCR package is private
When the workflow verifies anonymous artifact access
Then publication remains incomplete with a failed access check and no published GitHub release until visibility is corrected and identities are verified.

Task criterion: 27.

### distribution-release-07: partial publication

Given the image upload succeeded and chart upload or verification fails
When the release run terminates
Then it reports the incomplete stage, preserves uploaded artifacts and available validation evidence, and does not publish a GitHub completion record.

Task criterion: 28.

### distribution-release-08: reuse verified artifacts

Given a partial publication with recoverable original artifacts and validation evidence
When the maintainer retries the same version
Then the workflow verifies source identity and digests, reuses matching existing artifacts without rebuilding over or replacing them, and publishes only the missing verified artifacts before completing.

Task criterion: 29.

### distribution-release-09: refuse conflicting or unverifiable retries

Given a same-version artifact has a different digest or source revision, or its original artifact/evidence cannot be recovered
When the release is retried
Then publication stops without replacing the artifact and directs the maintainer to a new version.

Task criterion: 30.

### distribution-release-10: completed release retry

Given a completed release with matching identities
When the same version is retried
Then verification succeeds without changing its image digest, chart digest, or existing release record.

Task criterion: 31.

### distribution-release-11: serialize publication

Given two release runs target the same version
When they reach publication
Then at most one run at a time can inspect and publish that version; the later run checks existing identities through the retry rules before writing.

Task criterion: 32.

### distribution-release-12: publication trust boundary

Given a release workflow is configured
When a reviewer evaluates its effective actions and permissions
Then actions are pinned to reviewed full commit SHAs, only publication jobs have the required writes, and GHCR publishing uses the short-lived repository workflow token with zero added long-lived registry credentials.

Task criterion: 33.

### distribution-release-13: release completion record

Given both artifacts and anonymous pulls have passed validation
When the workflow publishes the GitHub release
Then notes contain version, source revision, linux/amd64 and linux/arm64, the tested Helm/Kubernetes versions, image and chart digests, limitations, and version-pinned install/recovery instructions; the first release is explicitly labeled a scaffold.

Task criterion: 34.

### distribution-release-14: immutable version catalog

Given a completed release and a later chart-only change
When the maintainer releases that change
Then it receives a new unified numeric version, previous release artifacts remain available for rollback, and the publication workflow creates no latest, major-only, or minor-only image aliases.

Task criterion: 35.

### distribution-release-15: operator-directed deployment

Given a running installation and a newly published release
When publication completes
Then the installed Helm revision and selected image digest stay unchanged because the publishing workflow has no cluster deployment step or cluster credentials.

Task criterion: 36.

## Verification

| Scenario | Delivery / coverage | Evidence |
| --- | --- | --- |
| distribution-release-01 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c22`. |
| distribution-release-02 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c23`. |
| distribution-release-03 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c24`. |
| distribution-release-04 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c25`. |
| distribution-release-05 | Partial — real GHCR access pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c26`. |
| distribution-release-06 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c27`. |
| distribution-release-07 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c28`. |
| distribution-release-08 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c29`. |
| distribution-release-09 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c30`. |
| distribution-release-10 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c31`. |
| distribution-release-11 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c32`. |
| distribution-release-12 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c33`. |
| distribution-release-13 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c34`. |
| distribution-release-14 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c35`. |
| distribution-release-15 | Implemented / local policy and workflow proof; hosted pending | `python3 -m unittest discover -s tests/distribution -p test_release.py -k test_c36`. |

Local verification on 2026-10-15: all 15 `test_release.py` tests passed;
all five `test_artifacts.py` artifact-trust tests passed; actionlint 1.7.12
accepted all workflows. `tests/distribution/registry.py` exercised the actual
local OCI registry adapter, image/chart uploads, partial chart failure and reuse,
completed retry, source conflict, anonymous Docker pulls on both platforms and
an actual Helm pull with package-byte equality.

C26's local registry exercise does not establish GHCR visibility or publication
permission. Both real GHCR packages must pass the workflow's anonymous pulls
before a GitHub completion record can be created. No publication was authorized
or performed. C22–C25 and C27–C36 combine executable decision tests with workflow
contract assertions; they are not evidence that GitHub hosted the workflow yet.

### First publication recovery

The maintainer requested completion of all 36 criteria, merge, and issue closure
on 2026-10-15. PR #3 was merged and tag `v0.0.1` identifies
`a13a6adacb3b31a3d54fc862aea1eee3aa2605bd`.
[Run 38841600719](https://github.com/rodalladea/bloc/actions/runs/38841600719)
passed native platform and source/cluster validation, then uploaded both artifacts.
Both anonymous Docker pulls succeeded, but the second platform cleared local
`RepoDigests` and caused a false verification failure before the Helm pull.

Given a second platform pull clears local `RepoDigests`, when Docker reports the
verified registry digest, then consumption verification accepts that pull.
A missing or different reported digest still fails. Full anonymous OCI content
verification remains required before CLI consumption and release completion.
`test_c26_pull_verifies_reported_digest_without_local_repo_digests` and
`test_c26_pull_rejects_missing_or_conflicting_digest` cover this regression.
The failure was also reproduced with the published image on Docker 28.5.1.

Recovery verification on 2026-10-16 passed against the retained original bundle:
source/version, all required validation entries, image provenance/SBOM, chart
identity, every anonymous registry blob, Docker pulls for both platforms, and
Helm package-byte equality. The corrected consumer ran locally with empty
Docker/Helm credential configuration. The maintainer's authorized recovery then
created the [v0.0.1 release record](https://github.com/rodalladea/bloc/releases/tag/v0.0.1).
No tag, image, or chart was replaced. The original hosted run remains failed;
this is a documented local recovery, not a claim that its publisher passed.

Image: `sha256:35fe08468d867beec22d2530f69e008329db06a7455f55f5e75628864d5fa42e`.
Chart: `sha256:0283630212f6cc0d16d3855885690f21df93f74a422412796007e6e04226ca64`.
C26 is now verified against public GHCR; together with the existing criterion
proofs this completes 36/36. Earlier pending-publication statements above are
historical verification records, superseded by this recovery evidence.
