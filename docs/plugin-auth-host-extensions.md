# Authentication plugin host extensions

Silo currently uses the SDK-native `auth_provider.v1` and `request_router.v1` services plus two narrowly scoped manifest conventions. These conventions are temporary host extensions and should move into the Silo plugin SDK if other hosts or providers adopt them.

## Connection testing

An authentication capability that supports configuration testing advertises:

```json
{
  "connection_test": true,
  "connection_test_config_keys": ["ldap"]
}
```

The plugin manifest must also expose a `request_router.v1` capability with the same capability ID. When an administrator tests a configuration key, Silo selects the single auth capability whose `connection_test_config_keys` contains that exact key and calls the SDK `TestConnection` RPC with that capability ID. A successful transport call is insufficient: the response must be present and contain `ok: true`.

Exact auth ownership takes priority over the legacy metadata-provider connection check. Multiple auth owners are rejected as ambiguous. An auth capability with missing, malformed, or unsupported connection-test metadata fails without falling back to an unrelated provider. Metadata-only plugins retain their previous behavior when no auth capability advertises connection testing.

## Managed roles

An auth capability may request authority over the Silo `user` and `admin` roles with:

```json
{
  "managed_role_contract": "silo.auth.managed-role.v1",
  "role_values": ["user", "admin"]
}
```

After successful authentication, an authoritative role response contains all three fixed claims:

```json
{
  "silo_role_contract": "silo.auth.managed-role.v1",
  "silo_role_managed": true,
  "silo_role": "admin"
}
```

`silo_role` may be `user` or `admin`. Silo applies no role when the marker is absent or false. A true marker fails closed unless the installed capability advertised the exact v1 contract and the response contract and role are exact. A bare `silo_role` claim never grants role authority.

Before promoting a normal user, Silo snapshots locally owned permissions and access-group assignment on the capability-scoped external identity. Repeated admin logins do not overwrite that snapshot. Demotion restores it and revokes the user's active sessions in the same database transaction. If a legacy managed administrator has no snapshot, Silo uses current normal-user default permissions and the current default access group; if no default group exists, the restored group is empty.

External identities are immutable and scoped by plugin installation, capability ID, and external subject. User creation and claiming that identity commit atomically. A competing first login resolves to the existing owner and cannot repoint the identity.

Successful managed-role transitions are logged after commit with the plugin installation ID, capability ID, user ID, previous role, new role, and contract version. Raw claims and directory data are not logged.
