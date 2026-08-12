# Plugin authentication SDK contracts

Silo consumes the plugin SDK's typed `auth_provider.v1` contracts for managed
roles and prospective configuration testing. Older plugins that still emit the
reviewed `silo.auth.managed-role.v1` claim protocol remain compatible, but new
providers should use the SDK messages.

## Authentication-provider connection testing

An auth capability opts in with
`auth_provider.connection_test.config_keys` and implements the separate
`AuthProviderConfiguration.TestConnection` service. Silo validates and merges
the operator's prospective configuration, launches an isolated temporary
plugin instance, and sends only the global configuration entries named by the
installed descriptor. The values are never persisted by the test path.

The service is optional. An auth provider without the typed descriptor remains
unsupported for connection testing; Silo never falls back to a metadata
provider, `request_router.v1`, or `Authenticate`.

## Managed roles

An auth capability advertises every role it may manage through
`auth_provider.managed_roles.supported_roles`. Silo currently requires the
exact complete set `USER` and `ADMIN` so every promotion can be explicitly
demoted. Successful authentication returns one typed
`managed_silo_role` assertion.

The assertion is authoritative only when all of the following are true at the
time of authentication:

- the installed capability advertises the complete SDK managed-role contract;
- the persisted auth binding is enabled;
- the operator enabled `managed_roles_enabled` on that binding;
- the returned role is exact and was advertised.

The binding lookup runs inside the role-transition transaction. Enabling,
disabling, or deleting the binding therefore affects the next login without a
server restart. A plugin cannot grant itself authority through its manifest or
response alone. Typed and legacy role protocols in one response are rejected.

## Local authorization snapshots

On first promotion to administrator, Silo snapshots the account's current
normal-user permissions and access-group assignment. Repeated administrator
logins do not overwrite that snapshot. Manual authorization changes made while
the account is managed do not replace it; the original snapshot wins on
demotion.

Demotion restores the snapshot and clears it. An intentionally NULL access
group restores the ungrouped state. If a snapshotted group was deleted, Silo
uses the current default group. With no usable snapshot or default group,
demotion restores default normal-user permissions and a NULL access group;
NULL means ungrouped/no group ceiling, not total library lockout.

The role update and main `auth_sessions` revocation commit atomically. After
commit, Silo revokes Jellyfin and ABS compatibility sessions through their
owning stores. A compatibility-store failure is logged with the user ID and
does not misreport the committed database transition as failed.
