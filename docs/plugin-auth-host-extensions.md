# Authentication plugin host extensions

Silo uses the SDK-native `auth_provider.v1` service plus one narrowly scoped managed-role convention. This convention is a temporary host extension and should move into the Silo plugin SDK if other hosts or providers adopt it.

## Connection testing

The current plugin SDK has no generic or authentication-provider connection-test RPC. Silo therefore reports connection testing as unsupported when an installed manifest contains an auth provider, rather than routing auth configuration through the media-oriented `request_router.v1` service or falling back to a metadata provider. Metadata-only plugins retain their existing probe behavior. Adding auth configuration probes requires an SDK-owned typed contract with explicit config ownership and positive acknowledgement.

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

`silo_role` may be `user` or `admin`. Silo applies no role when the marker is absent or false. A true marker fails closed unless the operator explicitly enabled **Allow managed Silo roles** on the auth binding, the installed capability advertised the exact v1 contract, and the response contract and role are exact. Existing and new bindings default to unauthorized. A bare `silo_role` claim never grants role authority.

Before promoting a normal user, Silo snapshots locally owned permissions and access-group assignment on the capability-scoped external identity. Repeated admin logins do not overwrite that snapshot. Demotion restores it and revokes the user's active sessions in the same database transaction. If a legacy managed administrator has no snapshot, Silo uses current normal-user default permissions and the current default access group; if no default group exists, the restored group is empty.

External identities are immutable and scoped by plugin installation, capability ID, and external subject. User creation and claiming that identity commit atomically. A competing first login resolves to the existing owner and cannot repoint the identity.

The capability-scoping migration assigns a legacy identity only when its installation has exactly one auth binding that matches an installed `auth_provider.v1` capability. Installations with zero or multiple matches abort the migration atomically so an operator can resolve the binding data; the migration never guesses or copies one legacy subject into several capability namespaces.

Credential providers are always resolved by installation and capability. The current OAuth launch URL is installation-scoped; an installation exposing more than one auth capability is therefore rejected as ambiguous for OAuth instead of selecting a capability by registration or map order.

Successful managed-role transitions are logged after commit with the plugin installation ID, capability ID, user ID, previous role, new role, and contract version. Raw claims and directory data are not logged.
