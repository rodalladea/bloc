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

There is no automated publishing and `publish = false` prevents accidental registry
publication. A maintainer explicitly authorizes each release.

1. Review security issues, supported features, migration/rollback notes, and known
   limitations. Confirm private reporting works before any authentication release.
2. Run all CI checks and dependency audit. Review dependency licenses and notices.
3. Update Cargo.toml/Cargo.lock together and move Unreleased notes to a versioned,
   dated changelog section. Use Semantic Versioning; document pre-1.0 breaking changes.
4. Merge the release PR, tag the reviewed revision `vX.Y.Z`, and publish release
   notes describing actual capabilities and verification.
5. If distributing binaries later, add reproducible build instructions, checksums,
   provenance, and a supported-platform matrix before promising these artifacts.

CI actions use major-version tags for now. Pin them to reviewed full commit SHAs
before enabling publishing or workflows that handle secrets; keep pins updated
through dependency review. Never execute untrusted PR code with privileged tokens.
