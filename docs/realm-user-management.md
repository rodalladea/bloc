# realm and user management

The installation administrator manages independent directories at `/admin/realms`.
No realm is created automatically. A realm contains its own users; equal emails
in different realms identify independent records. Directory users cannot sign in.
This increment creates no credentials, email verification, providers or identity
protocols. The installation administrator remains a separate identity.

Create a realm, then use **View users** to create and manage its users. Names may
repeat; immutable UUIDs distinguish directories. User emails are unverified and
unique within their realm, including suspended users. Email normalization trims
surrounding whitespace and lowercases the domain while preserving local-part case
and aliases. Display names are optional. Names allow at most 128 Unicode scalars
and 512 UTF-8 bytes, without control characters.

Realm and user statuses are independent. Suspending a realm leaves its users'
statuses unchanged and permits continued directory management. Reactivating it
leaves individually suspended users suspended. Combined directory status is active
only when both records are active; this status does not authenticate anyone.
Lifecycle confirmation carries the version viewed when opening the action.

A stale form returns a conflict. Reload the current record and review it before
editing again; bloc never automatically replays a mutation. A repeated creation
form creates no second record. If a response is lost, review the directory or
record before submitting again. Current-version normalized no-ops preserve the
record version, timestamp and audit count. Cancellation uses safe navigation.
Lists use 50-row keyset pages; there is no count, search or filter contract.

## storage and operation

Run explicit migrations with migrator credentials before serving the new binary.
Migration `0003_directory.sql` extends the exact checksum contract; serving replicas
never migrate. Old and new binary/schema contracts are incompatible. Coordinate the
upgrade rather than running mixed incompatible replicas. Back up and restore using
the existing [administrator operations](administrator-access.md) procedures; the
restore recovery fence also denies directory access until recovery completes.

Runtime credentials have only guarded operations; operator credentials have no
directory capability. Every read and mutation rechecks current administrator
session authority under the installation lock. Mutations serialize with sign-out,
credential replacement and restore fencing. User operations carry both parent and
user UUIDs. No transfer or deletion capability is provided.

Every actual mutation and its single targeted success event commit atomically.
Unavailable authority or audit append failure returns 503 and commits no directory
change. Events carry immutable realm/user targets, administrator, database time
and a generated request UUID, without profile values or secret material. Existing
maintenance retains success events for 90 days and denial aggregates for seven
days, deleting at most 1,000 of each category per invocation. Existing operational
failure reporting applies; these periods do not promise an exact deletion deadline.

See [ADR 0005](adr/0005-tenant-user-directories.md) and the
[behavior contract](behaviors/realm-user-management.md) for scope and proof mapping.
Production authentication approval, MFA, native capacity and identity-protocol
conformance remain separate requirements.

## Upgrade from tenant terminology

Run `bloc database migrate` using migrator credentials before starting the new
binary. Migration 4 renames directories and ownership columns in place, preserving
records and historical audit actions. New events use realm action names.
Administration URLs now start at `/admin/realms`; update bookmarks and integrations
that use `/admin/tenants`. Mixed old/new binaries are unsupported. See
[ADR 0006](adr/0006-realm-terminology.md).
