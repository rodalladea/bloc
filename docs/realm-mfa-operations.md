# realm MFA secret operations

Status: implemented for development and evaluation; no production acceptance. Realm-user MFA
is separate from installation-administrator access. The approved
[projects/bloc/.design/realm-mfa-secret-encryption-rfc.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=9079e744fda4686a70c20cd55497b85881aa2257adab7c7a),
file ID `9079e744fda4686a70c20cd55497b85881aa2257adab7c7a`, defines the contract.

## Provisioning and upgrade

Back up the database and escrow encryption keys separately. Stop incompatible
replicas, run the explicit migration using migrator credentials, provision the
keyring and initialize its registry using operator credentials. Start compatible
replicas and check `/readyz`. Binary-only rollback onto the changed schema is
unsupported. Serving replicas never migrate. The installation security UUID is
persisted in the database and must survive restore with its ciphertext.

`BLOC_MFA_KEYRING_FILE` names a read-only operator-owned UTF-8 JSON file, at most
16 KiB. Its object has `format_version: 1` and `keys`, an array of 1–16 entries
with UUID `id` and canonical padded standard Base64 `key` encoding 32 independently
OS-random bytes. Unknown fields, duplicate IDs/material and invalid encodings are
rejected. No active designation appears in the file. Do not put key bytes in
environment variables, command arguments, chart values, the database or logs.
Use a separately controlled secret provisioning process; bloc does not generate
replacement keys. Limit file permissions and disable secret-bearing core dumps.

The chart references an existing Secret through `mfa.keyringSecretName` and
`mfa.keyringSecretKey`. Runtime and the attached operator Pod mount it; migrator
and ordinary maintenance do not. A serving process retains its startup snapshot;
restart after changing the file. Missing required nonretired keys or an empty
active registry refuse readiness. Extra staged material is never selected locally
as the writer key.

## Attached operator commands

Use the existing operator database credential and CA-file environment fields.
All mutations audit transactionally. Existing audit retention remains 90 days for
success events and seven days for aggregated denials. Status prints key IDs, registry generation,
states and reference counts, never material. Exit codes are 0 success, 2 invalid
input/configuration, 3 state conflict and 1 operational/unavailable failure.

```sh
bloc mfa keys initialize --key-id UUID
bloc mfa keys status
bloc mfa keys stage --key-id UUID
bloc mfa keys activate --key-id UUID --expected-generation N --confirm-replicas-restarted
bloc mfa keys reencrypt --from UUID --batch-size 100
bloc mfa keys retire --key-id UUID --expected-generation N --confirm-backup-escrow
```

Initialize only an empty registry. For rotation, distribute a keyring containing
old and new material, restart every serving replica, stage the new ID, inspect
status and activate with its current generation. The replica confirmation records
operator responsibility; bloc cannot atomically verify filesystem distribution.
Activation makes the previous writer decrypt-only. Every encrypted write checks
the database writer generation; rotation never changes factor identity or epoch.

Re-encryption processes one batch of 1–100 records (default 100), authenticates
each owner/purpose binding and conditionally replaces ciphertext only if record
revision and registry generation still match. A failed batch rolls back; retry
skips converted records. Inspect counts and repeat until no source references
remain. Expired records awaiting deletion and retained revoked factors still count.
Retirement refuses active/referenced keys. Retired IDs are terminal and never
reused. Physical removal is an offline operator action after logical retirement.

## Backup, restore and trust limits

Record registry generation and IDs in backup manifests, never material. Retain
separately controlled offline escrow until every dependent backup is destroyed
or explicitly abandoned. The escrow confirmation is not proof an external backup
exists. Exercise recovery with matching escrow before relying on it.

Restore the matching keyring before compatible binary readiness. Existing
`bloc admin invalidate-access` sets the durable recovery fence. Temporary MFA
flows, recovery links, saved-code generations and previous session epochs become
invalid. Complete existing attached administrator recovery; successful completion
sets every TOTP replay floor to at least the completion time step plus one.
Lost keys have no cryptographic bypass: keep data and use explicitly authorized
re-enrollment rather than manufacturing MFA success.

Database-only compromise lacks key material but can alter metadata and
availability or roll back an entire consistent database. Runtime compromise can
decrypt TOTP and temporary handoffs; a compromised origin can steal proofs.
Memory clearing reduces owned-buffer lifetime but cannot erase all compiler,
allocator or OS copies. XChaCha20Poly1305 makes no NIST/RFC conformance claim.
Independent security review, both PostgreSQL majors, two replicas, qualified
real-browser testing and final-source native Linux amd64/arm64 capacity remain
acceptance gates.

## Assisted factor recovery

Open the realm user's **Factor recovery** action after confirming the person's
identity through your organization's established process. The action requires
that confirmation and the current installation administrator password. It issues
one purpose-specific link with a fragment code and a separate manual code for
browsers without JavaScript. The fragment is removed locally before submission;
the user explicitly exchanges the code with a CSRF-protected form.

Issuing a replacement link invalidates the previous link and its temporary
recovery forms. Issuance leaves working factors and ordinary sessions intact.
A user must confirm their current password before the link is consumed. That
confirmation ends ordinary sessions and permits factor replacement only. The
old factors remain active until the replacement transaction succeeds. An expired
or canceled recovery attempt does not remove them.

Realm policy controls this path independently of saved recovery codes. An
administrator can issue at most three successful links for a user in an hour;
existing admission limits also apply. The configured link lifetime is five to
sixty minutes. Do not log, paste into tickets, or retain the link or manual code.
If both saved codes and assisted recovery are unavailable, an administrator must
change the applicable realm policy; possession of a password-reset link grants
no factor-replacement authority.
