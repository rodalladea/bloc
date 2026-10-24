# 0006: realm terminology for independent identity directories

Status: accepted — 2026-10-24

## Context

The requester decided to rename the existing tenant concept to realm. The
independent identity directories in [ADR 0005](0005-tenant-user-directories.md)
represent identity boundaries rather than an organization/customer hierarchy.

## Options

- Keep tenant terminology: rejected by the requester.
- Add realms underneath tenants: explicitly rejected; no new hierarchy is needed.
- Rename the existing boundary to realm: selected.

## Decision

Use realm in application code, administration screens, URLs, storage and current
documentation. Users belong immutably to one realm; email uniqueness and lifecycle
rules are unchanged. No new authentication or protocol capability is introduced.
See the [behavior record](../behaviors/realm-user-management.md).

Administration moves to `/admin/realms`; old tenant URLs are unsupported rather
than replaying or redirecting state-changing requests. Upgrade requires an explicit
forward migration before serving the new binary. Existing checksum migrations
remain byte-for-byte unchanged. Tables and ownership columns are renamed in place,
retaining UUIDs, names, emails, versions, lifecycle states and timestamps.
Guarded operations retain their authorization and privilege boundaries.

New audit events and denial observations use realm action names. Historical tenant
actions remain unchanged and valid, with their targets preserved under renamed
columns. Historical constraint/index names and source artifact paths may retain
tenant terminology. Accepted older ADRs and released changelog entries remain
historical records.

## Consequences

This is a breaking administration URL and schema change. Mixed old/new executable
rollouts remain unsupported; exact checksum readiness rejects incompatible schemas.
Deployments must run `bloc database migrate` with migrator credentials. No tenant
layer, data transfer, identity linking or additional realm is created implicitly.
