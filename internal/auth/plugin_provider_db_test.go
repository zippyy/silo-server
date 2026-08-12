package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/access"
	"github.com/Silo-Server/silo-server/internal/models"
	"github.com/Silo-Server/silo-server/internal/plugins"
)

type pluginProviderDBFixture struct {
	t              *testing.T
	pool           *pgxpool.Pool
	installationID int
	capabilityID   string
	prefix         string
}

func newPluginProviderDBFixture(t *testing.T) *pluginProviderDBFixture {
	t.Helper()
	dsn := os.Getenv("SILO_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("SILO_REQUIRE_AUTH_DB_TESTS") == "1" {
			t.Fatal("SILO_REQUIRE_AUTH_DB_TESTS=1 requires SILO_TEST_DATABASE_URL")
		}
		t.Skip("SILO_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	prefix := "plugin-hardening-" + uuid.NewString()
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	// The concurrency fixtures hold several connections at once: a table
	// blocker plus two concurrent logins, each of which keeps its authority
	// decision transaction open while the provisioning transaction runs, plus
	// the pg_stat_activity poll. The pgxpool default of max(4, NumCPU) is
	// enough on a workstation but starves the blocker/poll on 2-vCPU CI
	// runners. Give the fixture a fixed ceiling so connection count is
	// deterministic regardless of runner size.
	poolConfig.MaxConns = 12
	poolConfig.ConnConfig.RuntimeParams["application_name"] = prefix
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping test database: %v", err)
	}
	var hardened bool
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) = 2
			FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name = 'plugin_auth_identities'
			  AND column_name IN ('capability_id', 'managed_role_snapshot_access_group_present')`).Scan(&hardened); err != nil {
		pool.Close()
		t.Fatalf("check plugin identity migration: %v", err)
	}
	if !hardened {
		pool.Close()
		if os.Getenv("SILO_REQUIRE_AUTH_DB_TESTS") == "1" {
			t.Fatal("SILO_REQUIRE_AUTH_DB_TESTS=1 requires all plugin auth hardening migrations")
		}
		t.Skip("plugin auth identity hardening migration is not applied")
	}

	var installationID int
	if err := pool.QueryRow(ctx, `
		INSERT INTO plugin_installations (plugin_id, version, install_path)
		VALUES ($1, 'test', $2)
		RETURNING id`, prefix, "/tmp/"+prefix).Scan(&installationID); err != nil {
		pool.Close()
		t.Fatalf("create plugin installation: %v", err)
	}
	capabilityID := "ldap"
	if _, err := pool.Exec(ctx, `
		INSERT INTO plugin_capabilities (
			plugin_installation_id, capability_type, capability_id, metadata
		) VALUES ($1, 'auth_provider.v1', $2, '{"auth_provider":{"managed_roles":{"supported_roles":["MANAGED_SILO_ROLE_USER","MANAGED_SILO_ROLE_ADMIN"]}}}'::jsonb)`, installationID, capabilityID); err != nil {
		pool.Close()
		t.Fatalf("create plugin auth capability: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO plugin_auth_bindings (
			plugin_installation_id, capability_id, enabled, auto_provision, managed_roles_enabled
		) VALUES ($1, $2, true, true, true)`, installationID, capabilityID); err != nil {
		pool.Close()
		t.Fatalf("create plugin auth binding: %v", err)
	}

	fixture := &pluginProviderDBFixture{
		t:              t,
		pool:           pool,
		installationID: installationID,
		capabilityID:   capabilityID,
		prefix:         prefix,
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM plugin_installations WHERE id = $1`, installationID); err != nil {
			t.Errorf("delete plugin installation: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE email LIKE $1`, prefix+"%"); err != nil {
			t.Errorf("delete plugin test users: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM access_groups WHERE name LIKE $1`, prefix+"%"); err != nil {
			t.Errorf("delete plugin test access groups: %v", err)
		}
		pool.Close()
	})
	return fixture
}

func (f *pluginProviderDBFixture) provider(_ bool) *PluginProvider {
	return NewPluginProviderWithClientFactory(
		PluginProviderConfig{
			InstallationID: f.installationID,
			CapabilityID:   f.capabilityID,
		},
		NewSessionRepository(f.pool),
		NewUserRepository(f.pool),
		f.pool,
		nil,
		WithAuthProviderAuthorityStore(plugins.NewRuntimeConfigStore(f.pool)),
	)
}

func (f *pluginProviderDBFixture) response(subject, displayName, email, role string) *pluginv1.AuthenticateResponse {
	response := &pluginv1.AuthenticateResponse{
		ExternalSubject: subject,
		DisplayName:     displayName,
		Email:           email,
	}
	if role != "" {
		switch role {
		case managedRoleUser:
			response.ManagedSiloRole = &pluginv1.ManagedSiloRoleAssertion{Role: pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_USER}
		case managedRoleAdmin:
			response.ManagedSiloRole = &pluginv1.ManagedSiloRoleAssertion{Role: pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_ADMIN}
		default:
			f.t.Fatalf("unsupported fixture role %q", role)
		}
	}
	return response
}

func (f *pluginProviderDBFixture) createIdentityUser(
	ctx context.Context,
	role string,
	permissions []string,
	groupID *int64,
	subject string,
) (*models.User, PluginIdentityKey) {
	user, err := NewUserRepository(f.pool).Create(ctx, models.CreateUserInput{
		Email:         fmt.Sprintf("%s-%s@example.test", f.prefix, uuid.NewString()),
		Username:      f.prefix + "-" + uuid.NewString(),
		Password:      "test-only-password",
		Role:          role,
		Permissions:   permissions,
		AccessGroupID: groupID,
	})
	if err != nil {
		f.t.Fatalf("create test user: %v", err)
	}
	key := PluginIdentityKey{
		InstallationID:  f.installationID,
		CapabilityID:    f.capabilityID,
		ExternalSubject: subject,
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		f.t.Fatalf("begin identity claim: %v", err)
	}
	claimed, err := NewPluginIdentityRepository(f.pool).ClaimTx(ctx, tx, key, user.ID)
	if err != nil || !claimed {
		_ = tx.Rollback(ctx)
		f.t.Fatalf("claim identity = %v, %v; want true, nil", claimed, err)
	}
	if err := tx.Commit(ctx); err != nil {
		f.t.Fatalf("commit identity claim: %v", err)
	}
	return user, key
}

func (f *pluginProviderDBFixture) createGroup(ctx context.Context, suffix string) int64 {
	group, err := access.NewGroupStore(f.pool).Create(ctx, access.CreateGroupInput{
		Name:               f.prefix + "-" + suffix,
		AllowedPermissions: []string{string(PermissionMetadataCuration)},
	})
	if err != nil {
		f.t.Fatalf("create access group: %v", err)
	}
	return group.ID
}

func TestPluginManagedRoleAuthorizationFollowsBindingWithoutReconstructionDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx := context.Background()
	user, key := f.createIdentityUser(ctx, managedRoleUser, nil, nil, "entryUUID:dynamic-role-binding")
	provider := f.provider(true)
	response := f.response(key.ExternalSubject, user.Username, user.Email, managedRoleAdmin)

	store := plugins.NewRuntimeConfigStore(f.pool)
	binding, err := store.GetAuthBinding(ctx, f.installationID, f.capabilityID)
	if err != nil {
		t.Fatal(err)
	}
	binding.ManagedRolesEnabled = false
	if err := store.UpsertAuthBinding(ctx, *binding); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); err == nil {
		t.Fatal("disabled binding accepted authoritative administrator claims")
	}
	unchanged, err := NewUserRepository(f.pool).GetByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Role != managedRoleUser {
		t.Fatalf("disabled binding changed role to %q", unchanged.Role)
	}

	binding.ManagedRolesEnabled = true
	if err := store.UpsertAuthBinding(ctx, *binding); err != nil {
		t.Fatal(err)
	}
	promoted, err := provider.CompleteOAuth(ctx, response)
	if err != nil {
		t.Fatalf("same provider did not observe enabled binding: %v", err)
	}
	if promoted.Role != managedRoleAdmin {
		t.Fatalf("enabled binding role=%q, want admin", promoted.Role)
	}

	binding.ManagedRolesEnabled = false
	if err := store.UpsertAuthBinding(ctx, *binding); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); err == nil {
		t.Fatal("same provider retained managed-role authority after binding was disabled")
	}
	stillPromoted, err := NewUserRepository(f.pool).GetByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stillPromoted.Role != managedRoleAdmin {
		t.Fatalf("unauthorized claim mutated existing role to %q", stillPromoted.Role)
	}

	binding.Enabled = false
	binding.ManagedRolesEnabled = true
	if err := store.UpsertAuthBinding(ctx, *binding); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); err == nil {
		t.Fatal("disabled binding retained managed-role authority")
	}
	if _, err := f.pool.Exec(ctx, `
		DELETE FROM plugin_auth_bindings
		WHERE plugin_installation_id = $1 AND capability_id = $2`, f.installationID, f.capabilityID); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); err == nil {
		t.Fatal("deleted binding retained managed-role authority")
	}
}

func TestPluginManagedRoleAuthorizationToggleConcurrentLoginDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	user, key := f.createIdentityUser(ctx, managedRoleUser, nil, nil, "entryUUID:concurrent-role-toggle")
	provider := f.provider(true)

	toggle, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = toggle.Rollback(context.Background()) }()
	if _, err := toggle.Exec(ctx, `
		UPDATE plugin_auth_bindings
		SET managed_roles_enabled = false
		WHERE plugin_installation_id = $1 AND capability_id = $2`, f.installationID, f.capabilityID); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, loginErr := provider.CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, managedRoleAdmin))
		result <- loginErr
	}()

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err := f.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND application_name = $1
			  AND wait_event_type = 'Lock'
			  AND query ILIKE '%FROM plugin_auth_bindings%'
			  AND query ILIKE '%FOR SHARE%'`, f.prefix).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 1 {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("managed-role login did not wait for the concurrent binding update")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := toggle.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err == nil {
		t.Fatal("login accepted administrator claims after the concurrent disable committed")
	}
	unchanged, err := NewUserRepository(f.pool).GetByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Role != managedRoleUser {
		t.Fatalf("concurrent disable/login changed role to %q", unchanged.Role)
	}
}

func TestPluginAuthenticationFollowsBindingWithoutReconstructionDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx := context.Background()
	provider := f.provider(false)
	store := plugins.NewRuntimeConfigStore(f.pool)
	binding, err := store.GetAuthBinding(ctx, f.installationID, f.capabilityID)
	if err != nil {
		t.Fatal(err)
	}

	existing, key := f.createIdentityUser(ctx, managedRoleUser, nil, nil, "entryUUID:dynamic-binding")
	response := f.response(key.ExternalSubject, existing.Username, existing.Email, "")
	if _, err := provider.CompleteOAuth(ctx, response); err != nil {
		t.Fatalf("enabled binding rejected existing identity: %v", err)
	}

	binding.Enabled = false
	if err := store.UpsertAuthBinding(ctx, *binding); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled binding error=%v, want ErrInvalidCredentials", err)
	}

	binding.Enabled = true
	if err := store.UpsertAuthBinding(ctx, *binding); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); err != nil {
		t.Fatalf("re-enabled binding rejected existing identity: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE plugin_installations SET enabled = false WHERE id = $1`, f.installationID); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled installation error=%v, want ErrInvalidCredentials", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE plugin_installations SET enabled = true WHERE id = $1`, f.installationID); err != nil {
		t.Fatal(err)
	}

	binding.AutoProvision = false
	if err := store.UpsertAuthBinding(ctx, *binding); err != nil {
		t.Fatal(err)
	}
	unknown := f.response("entryUUID:auto-provision-disabled", "Unknown", f.prefix+"-unknown@example.test", "")
	if _, err := provider.CompleteOAuth(ctx, unknown); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled auto-provision error=%v, want ErrInvalidCredentials", err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); err != nil {
		t.Fatalf("disabled auto-provision rejected existing identity: %v", err)
	}
	var unknownUsers int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email = $1`, unknown.Email).Scan(&unknownUsers); err != nil {
		t.Fatal(err)
	}
	if unknownUsers != 0 {
		t.Fatalf("disabled auto-provision created %d users", unknownUsers)
	}

	if _, err := f.pool.Exec(ctx, `
		DELETE FROM plugin_auth_bindings
		WHERE plugin_installation_id = $1 AND capability_id = $2`, f.installationID, f.capabilityID); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("deleted binding error=%v, want ErrInvalidCredentials", err)
	}
}

func TestPluginAuthenticationBindingDisableSerializesWithLoginDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	user, key := f.createIdentityUser(ctx, managedRoleUser, nil, nil, "entryUUID:concurrent-binding-disable")
	provider := f.provider(false)

	disable, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = disable.Rollback(context.Background()) }()
	if _, err := disable.Exec(ctx, `
		UPDATE plugin_auth_bindings
		SET enabled = false
		WHERE plugin_installation_id = $1 AND capability_id = $2`, f.installationID, f.capabilityID); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, loginErr := provider.CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, ""))
		result <- loginErr
	}()

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err := f.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND application_name = $1
			  AND wait_event_type = 'Lock'
			  AND query ILIKE '%FROM plugin_auth_bindings%'
			  AND query ILIKE '%FOR SHARE%'`, f.prefix).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 1 {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("login did not wait for the concurrent binding disable")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := disable.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("login after concurrent disable error=%v, want ErrInvalidCredentials", err)
	}
}

func TestPluginManagedRoleAuthorityFollowsInstalledDescriptorWithoutReconstructionDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx := context.Background()
	user, key := f.createIdentityUser(ctx, managedRoleUser, nil, nil, "entryUUID:dynamic-descriptor")
	provider := f.provider(true)
	response := f.response(key.ExternalSubject, user.Username, user.Email, managedRoleAdmin)
	withoutRole := f.response(key.ExternalSubject, user.Username, user.Email, "")

	if _, err := f.pool.Exec(ctx, `
		UPDATE plugin_capabilities
		SET metadata = '{"auth_provider":{"managed_roles":{"supported_roles":["NOT_A_ROLE"]}}}'::jsonb
		WHERE plugin_installation_id = $1 AND capability_type = 'auth_provider.v1' AND capability_id = $2`,
		f.installationID, f.capabilityID); err != nil {
		t.Fatal(err)
	}
	ordinary := f.response("entryUUID:malformed-descriptor-ordinary", "Ordinary", f.prefix+"-ordinary@example.test", "")
	provisioned, err := provider.CompleteOAuth(ctx, ordinary)
	if err != nil {
		t.Fatalf("malformed managed-role descriptor blocked ordinary provisioning: %v", err)
	}
	if provisioned.Role != managedRoleUser {
		t.Fatalf("ordinary provisioned role=%q, want user", provisioned.Role)
	}
	if _, err := provider.CompleteOAuth(ctx, withoutRole); err != nil {
		t.Fatalf("malformed managed-role descriptor blocked ordinary authentication: %v", err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); err == nil {
		t.Fatal("malformed installed descriptor authorized a managed role")
	}

	if _, err := f.pool.Exec(ctx, `
		UPDATE plugin_capabilities
		SET metadata = '{}'::jsonb
		WHERE plugin_installation_id = $1 AND capability_type = 'auth_provider.v1' AND capability_id = $2`,
		f.installationID, f.capabilityID); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, response); err == nil {
		t.Fatal("provider accepted a managed role after the installed descriptor was removed")
	}
	unchanged, err := NewUserRepository(f.pool).GetByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Role != managedRoleUser {
		t.Fatalf("removed descriptor changed role to %q", unchanged.Role)
	}
	if _, err := f.pool.Exec(ctx, `
		DELETE FROM plugin_capabilities
		WHERE plugin_installation_id = $1 AND capability_type = 'auth_provider.v1' AND capability_id = $2`,
		f.installationID, f.capabilityID); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.CompleteOAuth(ctx, withoutRole); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("removed auth capability error=%v, want ErrInvalidCredentials", err)
	}

	if _, err := f.pool.Exec(ctx, `
		INSERT INTO plugin_capabilities (plugin_installation_id, capability_type, capability_id, metadata)
		VALUES ($1, 'auth_provider.v1', $2, '{"auth_provider":{"managed_roles":{"supported_roles":["MANAGED_SILO_ROLE_USER","MANAGED_SILO_ROLE_ADMIN"]}}}'::jsonb)`,
		f.installationID, f.capabilityID); err != nil {
		t.Fatal(err)
	}
	promoted, err := provider.CompleteOAuth(ctx, response)
	if err != nil {
		t.Fatalf("same provider did not observe added managed-role descriptor: %v", err)
	}
	if promoted.Role != managedRoleAdmin {
		t.Fatalf("added descriptor role=%q, want admin", promoted.Role)
	}
}

func TestPluginProvisioningConcurrentFirstLoginDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	provider := f.provider(false)
	subject := "entryUUID:concurrent-subject"

	blocker, err := f.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	if _, err := blocker.Exec(ctx, `LOCK TABLE plugin_auth_identities IN SHARE MODE`); err != nil {
		t.Fatalf("lock identity table: %v", err)
	}

	responses := []*pluginv1.AuthenticateResponse{
		f.response(subject, "Concurrent Alice", f.prefix+"-alice@example.test", ""),
		f.response(subject, "Concurrent Bob", f.prefix+"-bob@example.test", ""),
	}
	start := make(chan struct{})
	type result struct {
		user *models.User
		err  error
	}
	results := make(chan result, len(responses))
	var ready sync.WaitGroup
	ready.Add(len(responses))
	for _, response := range responses {
		go func(response *pluginv1.AuthenticateResponse) {
			ready.Done()
			<-start
			user, err := provider.CompleteOAuth(ctx, response)
			results <- result{user: user, err: err}
		}(response)
	}
	ready.Wait()
	close(start)

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		if err := f.pool.QueryRow(ctx, `
			SELECT count(*)
			FROM pg_stat_activity
			WHERE datname = current_database()
			  AND application_name = $1
			  AND wait_event_type = 'Lock'
			  AND query ILIKE '%INSERT INTO plugin_auth_identities%'`, f.prefix).Scan(&waiting); err != nil {
			t.Fatalf("observe blocked identity claims: %v", err)
		}
		if waiting == len(responses) {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("observed %d blocked identity claims, want %d", waiting, len(responses))
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("release identity table lock: %v", err)
	}

	var users []*models.User
	for range responses {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent provisioning: %v", result.err)
		}
		users = append(users, result.user)
	}
	if users[0].ID != users[1].ID {
		t.Fatalf("concurrent callers resolved to users %d and %d", users[0].ID, users[1].ID)
	}
	var identityCount, userCount int
	var identityUserID int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*), min(user_id)
		FROM plugin_auth_identities
		WHERE plugin_installation_id = $1 AND capability_id = $2 AND external_subject = $3`,
		f.installationID, f.capabilityID, subject).Scan(&identityCount, &identityUserID); err != nil {
		t.Fatalf("count external identities: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE email IN ($1, $2)`,
		responses[0].Email, responses[1].Email).Scan(&userCount); err != nil {
		t.Fatalf("count provisioned users: %v", err)
	}
	if identityCount != 1 || userCount != 1 || identityUserID != users[0].ID {
		t.Fatalf("identity count=%d user count=%d identity owner=%d caller user=%d; want 1, 1, same owner",
			identityCount, userCount, identityUserID, users[0].ID)
	}
}

func TestPluginManagedRoleSnapshotLifecycleDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx := context.Background()
	customGroupID := f.createGroup(ctx, "custom")
	customPermissions := []string{string(PermissionMetadataCuration)}
	user, key := f.createIdentityUser(ctx, "user", customPermissions, &customGroupID, "entryUUID:managed-user")
	sessions := NewSessionRepository(f.pool)
	sessionID := uuid.NewString()
	if err := sessions.Create(ctx, models.AuthSession{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create admin session: %v", err)
	}
	provider := f.provider(true)

	promoted, err := provider.CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, "admin"))
	if err != nil {
		t.Fatalf("promote managed user: %v", err)
	}
	if promoted.Role != "admin" || promoted.AccessGroupID != nil {
		t.Fatalf("promoted role=%q group=%v; want admin, nil", promoted.Role, promoted.AccessGroupID)
	}
	identity, err := NewPluginIdentityRepository(f.pool).Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.SnapshotPresent || !slices.Equal(identity.SnapshotPermissions, customPermissions) ||
		identity.SnapshotAccessGroupID == nil || *identity.SnapshotAccessGroupID != customGroupID {
		t.Fatalf("promotion snapshot = %+v; want permissions %v and group %d", identity, customPermissions, customGroupID)
	}

	if _, err := provider.CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, "admin")); err != nil {
		t.Fatalf("repeat managed admin login: %v", err)
	}
	repeated, err := NewPluginIdentityRepository(f.pool).Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !repeated.SnapshotPresent || !slices.Equal(repeated.SnapshotPermissions, customPermissions) ||
		repeated.SnapshotAccessGroupID == nil || *repeated.SnapshotAccessGroupID != customGroupID {
		t.Fatalf("repeat login corrupted snapshot: %+v", repeated)
	}
	manualGroupID := f.createGroup(ctx, "manual-admin-change")
	manualPermissions := []string{}
	if err := NewUserRepository(f.pool).Update(ctx, user.ID, models.UpdateUserInput{
		Permissions:      &manualPermissions,
		AccessGroupIDSet: true,
		AccessGroupID:    &manualGroupID,
	}); err != nil {
		t.Fatalf("change authorization while managed admin: %v", err)
	}

	demoted, err := provider.CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, "user"))
	if err != nil {
		t.Fatalf("demote managed admin: %v", err)
	}
	if demoted.Role != "user" || !slices.Equal(demoted.Permissions, customPermissions) ||
		demoted.AccessGroupID == nil || *demoted.AccessGroupID != customGroupID {
		t.Fatalf("demoted user role=%q permissions=%v group=%v", demoted.Role, demoted.Permissions, demoted.AccessGroupID)
	}
	identity, err = NewPluginIdentityRepository(f.pool).Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if identity.SnapshotPresent || identity.SnapshotPermissions != nil || identity.SnapshotAccessGroupID != nil {
		t.Fatalf("demotion did not clear snapshot: %+v", identity)
	}
	valid, err := sessions.IsValid(ctx, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("pre-demotion administrator session remained valid")
	}
}

func TestPluginManagedRoleDemotionWithoutSnapshotUsesFallbackDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx := context.Background()
	user, key := f.createIdentityUser(ctx, "admin", nil, nil, "entryUUID:legacy-admin")
	sessions := NewSessionRepository(f.pool)
	sessionID := uuid.NewString()
	if err := sessions.Create(ctx, models.AuthSession{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	demoted, err := f.provider(true).CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, "user"))
	if err != nil {
		t.Fatalf("demote legacy managed admin: %v", err)
	}
	defaultGroupID, err := access.NewGroupStore(f.pool).DefaultID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if demoted.Role != "user" || !slices.Equal(demoted.Permissions, DefaultUserPermissions()) ||
		!equalOptionalInt64(demoted.AccessGroupID, defaultGroupID) {
		t.Fatalf("fallback role=%q permissions=%v group=%v; want user, %v, %v",
			demoted.Role, demoted.Permissions, demoted.AccessGroupID, DefaultUserPermissions(), defaultGroupID)
	}
	valid, err := sessions.IsValid(ctx, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("legacy administrator session remained valid after demotion")
	}
}

func TestPluginManagedRoleSnapshotEdgeStatesDB(t *testing.T) {
	t.Run("snapshot present with NULL permissions restores no permissions", func(t *testing.T) {
		f := newPluginProviderDBFixture(t)
		ctx := context.Background()
		user, key := f.createIdentityUser(ctx, managedRoleAdmin, []string{string(PermissionMetadataCuration)}, nil, "entryUUID:null-permissions")
		if _, err := f.pool.Exec(ctx, `
			UPDATE plugin_auth_identities
			SET managed_role_snapshot_present = true,
			    managed_role_snapshot_permissions = NULL,
			    managed_role_snapshot_access_group_id = NULL,
			    managed_role_snapshot_access_group_present = false
			WHERE plugin_installation_id = $1 AND capability_id = $2 AND external_subject = $3`,
			key.InstallationID, key.CapabilityID, key.ExternalSubject); err != nil {
			t.Fatal(err)
		}
		demoted, err := f.provider(true).CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, managedRoleUser))
		if err != nil {
			t.Fatal(err)
		}
		if demoted.Role != managedRoleUser || len(demoted.Permissions) != 0 || demoted.AccessGroupID != nil {
			t.Fatalf("NULL-permission snapshot restored %+v; want user, empty permissions, nil group", demoted)
		}
	})

	t.Run("snapshot present with NULL access group restores ungrouped state", func(t *testing.T) {
		f := newPluginProviderDBFixture(t)
		ctx := context.Background()
		snapshotPermissions := []string{string(PermissionMetadataCuration)}
		user, key := f.createIdentityUser(ctx, managedRoleAdmin, nil, nil, "entryUUID:null-access-group")
		if _, err := f.pool.Exec(ctx, `
			UPDATE plugin_auth_identities
			SET managed_role_snapshot_present = true,
			    managed_role_snapshot_permissions = $4,
			    managed_role_snapshot_access_group_id = NULL,
			    managed_role_snapshot_access_group_present = false
			WHERE plugin_installation_id = $1 AND capability_id = $2 AND external_subject = $3`,
			key.InstallationID, key.CapabilityID, key.ExternalSubject, snapshotPermissions); err != nil {
			t.Fatal(err)
		}
		demoted, err := f.provider(true).CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, managedRoleUser))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(demoted.Permissions, snapshotPermissions) || demoted.AccessGroupID != nil {
			t.Fatalf("ungrouped snapshot restored permissions=%v group=%v", demoted.Permissions, demoted.AccessGroupID)
		}
	})

	t.Run("deleted snapshotted access group falls back to current default", func(t *testing.T) {
		f := newPluginProviderDBFixture(t)
		ctx := context.Background()
		deletedGroupID := f.createGroup(ctx, "deleted-snapshot")
		snapshotPermissions := []string{string(PermissionMetadataCuration)}
		user, key := f.createIdentityUser(ctx, managedRoleAdmin, nil, nil, "entryUUID:deleted-access-group")
		if _, err := f.pool.Exec(ctx, `
			UPDATE plugin_auth_identities
			SET managed_role_snapshot_present = true,
			    managed_role_snapshot_permissions = $4,
			    managed_role_snapshot_access_group_id = $5,
			    managed_role_snapshot_access_group_present = true
			WHERE plugin_installation_id = $1 AND capability_id = $2 AND external_subject = $3`,
			key.InstallationID, key.CapabilityID, key.ExternalSubject, snapshotPermissions, deletedGroupID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.pool.Exec(ctx, `DELETE FROM access_groups WHERE id = $1`, deletedGroupID); err != nil {
			t.Fatal(err)
		}
		defaultGroupID, err := access.NewGroupStore(f.pool).DefaultID(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if defaultGroupID == nil {
			t.Fatal("security fixture requires a default access group")
		}
		demoted, err := f.provider(true).CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, managedRoleUser))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(demoted.Permissions, snapshotPermissions) || !equalOptionalInt64(demoted.AccessGroupID, defaultGroupID) {
			t.Fatalf("deleted-group snapshot restored permissions=%v group=%v; want %v, %v",
				demoted.Permissions, demoted.AccessGroupID, snapshotPermissions, defaultGroupID)
		}
	})

	t.Run("empty permissions snapshot remains empty", func(t *testing.T) {
		f := newPluginProviderDBFixture(t)
		ctx := context.Background()
		user, key := f.createIdentityUser(ctx, managedRoleAdmin, []string{string(PermissionMetadataCuration)}, nil, "entryUUID:empty-permissions")
		if _, err := f.pool.Exec(ctx, `
			UPDATE plugin_auth_identities
			SET managed_role_snapshot_present = true,
			    managed_role_snapshot_permissions = ARRAY[]::text[],
			    managed_role_snapshot_access_group_id = NULL,
			    managed_role_snapshot_access_group_present = false
			WHERE plugin_installation_id = $1 AND capability_id = $2 AND external_subject = $3`,
			key.InstallationID, key.CapabilityID, key.ExternalSubject); err != nil {
			t.Fatal(err)
		}
		demoted, err := f.provider(true).CompleteOAuth(ctx, f.response(key.ExternalSubject, user.Username, user.Email, managedRoleUser))
		if err != nil {
			t.Fatal(err)
		}
		if demoted.Permissions == nil || len(demoted.Permissions) != 0 {
			t.Fatalf("empty snapshot permissions=%v; want a persisted empty set", demoted.Permissions)
		}
	})
}

func TestPluginManagedRoleDemotionWithoutSnapshotOrDefaultGroupDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx := context.Background()
	user, key := f.createIdentityUser(ctx, managedRoleAdmin, nil, nil, "entryUUID:no-default-group")
	sessionID := uuid.NewString()
	if err := NewSessionRepository(f.pool).Create(ctx, models.AuthSession{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `UPDATE access_groups SET is_default = false WHERE is_default`); err != nil {
		t.Fatal(err)
	}
	identity, err := NewPluginIdentityRepository(f.pool).GetTx(ctx, tx, key, true)
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewUserRepository(f.pool).GetByIDTx(ctx, tx, user.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	demoted, transition, err := f.provider(true).applyManagedRoleTx(ctx, tx, identity, current, managedRoleUser)
	if err != nil {
		t.Fatal(err)
	}
	if !transition.changed || demoted.Role != managedRoleUser ||
		!slices.Equal(demoted.Permissions, DefaultUserPermissions()) || demoted.AccessGroupID != nil {
		t.Fatalf("no-default fallback user=%+v transition=%+v; want default permissions and nil group", demoted, transition)
	}
	var revoked bool
	if err := tx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE id = $1`, sessionID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("no-default fallback did not transactionally revoke the main session")
	}
}

func TestPluginMalformedManagedRoleDoesNotModifyDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx := context.Background()
	customGroupID := f.createGroup(ctx, "malformed")
	permissions := []string{string(PermissionMetadataCuration)}
	user, key := f.createIdentityUser(ctx, "user", permissions, &customGroupID, "entryUUID:malformed-role")
	response := f.response(key.ExternalSubject, user.Username, user.Email, "")
	response.ManagedSiloRole = &pluginv1.ManagedSiloRoleAssertion{Role: pluginv1.ManagedSiloRole(99)}

	if _, err := f.provider(true).CompleteOAuth(ctx, response); err == nil {
		t.Fatal("malformed managed-role claims unexpectedly succeeded")
	}
	got, err := NewUserRepository(f.pool).GetByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != "user" || !slices.Equal(got.Permissions, permissions) ||
		got.AccessGroupID == nil || *got.AccessGroupID != customGroupID {
		t.Fatalf("malformed claims modified user: %+v", got)
	}
	identity, err := NewPluginIdentityRepository(f.pool).Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if identity.SnapshotPresent {
		t.Fatal("malformed claims created a role snapshot")
	}
}

func TestPluginCapabilityNamespacesDoNotRepointIdentityDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx := context.Background()
	first, firstKey := f.createIdentityUser(ctx, "user", nil, nil, "shared-subject")
	secondCapability := "ldap-secondary"
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO plugin_auth_bindings (plugin_installation_id, capability_id, enabled, auto_provision)
		VALUES ($1, $2, true, true)`, f.installationID, secondCapability); err != nil {
		t.Fatal(err)
	}
	second, err := NewUserRepository(f.pool).Create(ctx, models.CreateUserInput{
		Email:    f.prefix + "-second-owner@example.test",
		Username: f.prefix + "-second-owner",
		Password: "test-only-password",
		Role:     "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	secondKey := PluginIdentityKey{
		InstallationID:  f.installationID,
		CapabilityID:    secondCapability,
		ExternalSubject: "shared-subject",
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := NewPluginIdentityRepository(f.pool).ClaimTx(ctx, tx, secondKey, second.ID)
	if err != nil || !claimed {
		_ = tx.Rollback(ctx)
		t.Fatalf("claim second namespace = %v, %v", claimed, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	conflictTx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err = NewPluginIdentityRepository(f.pool).ClaimTx(ctx, conflictTx, firstKey, second.ID)
	if err != nil {
		_ = conflictTx.Rollback(ctx)
		t.Fatal(err)
	}
	if claimed {
		_ = conflictTx.Rollback(ctx)
		t.Fatal("existing identity ownership was repointed")
	}
	if err := conflictTx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	identity, err := NewPluginIdentityRepository(f.pool).Get(ctx, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserID != first.ID {
		t.Fatalf("identity owner=%d, want original user %d", identity.UserID, first.ID)
	}
}

func TestPluginProvisioningDuplicatePolicyDB(t *testing.T) {
	t.Run("username collision retries with stable suffix", func(t *testing.T) {
		f := newPluginProviderDBFixture(t)
		ctx := context.Background()
		existing, err := NewUserRepository(f.pool).Create(ctx, models.CreateUserInput{
			Email:    f.prefix + "-local@example.test",
			Username: "collision-name",
			Password: "test-only-password",
			Role:     "user",
		})
		if err != nil {
			t.Fatal(err)
		}
		response := f.response(
			"entryUUID:username-collision",
			"Collision Name",
			f.prefix+"-plugin@example.test",
			"",
		)
		provisioned, err := f.provider(false).CompleteOAuth(ctx, response)
		if err != nil {
			t.Fatalf("provision after username collision: %v", err)
		}
		if provisioned.ID == existing.ID || provisioned.Username == existing.Username ||
			provisioned.Email != response.Email {
			t.Fatalf("provisioned user=%+v existing=%+v", provisioned, existing)
		}
	})

	t.Run("email collision fails without orphan", func(t *testing.T) {
		f := newPluginProviderDBFixture(t)
		ctx := context.Background()
		collisionEmail := f.prefix + "-claimed@example.test"
		if _, err := NewUserRepository(f.pool).Create(ctx, models.CreateUserInput{
			Email:    collisionEmail,
			Username: f.prefix + "-local",
			Password: "test-only-password",
			Role:     "user",
		}); err != nil {
			t.Fatal(err)
		}
		var before int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		response := f.response("entryUUID:email-collision", "Different Username", collisionEmail, "")
		_, err := f.provider(false).CompleteOAuth(ctx, response)
		if !errors.Is(err, ErrPluginEmailConflict) {
			t.Fatalf("email collision error=%v, want ErrPluginEmailConflict", err)
		}
		var after, identities int
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if err := f.pool.QueryRow(ctx, `
			SELECT count(*) FROM plugin_auth_identities
			WHERE plugin_installation_id = $1 AND capability_id = $2 AND external_subject = $3`,
			f.installationID, f.capabilityID, response.ExternalSubject).Scan(&identities); err != nil {
			t.Fatal(err)
		}
		if after != before || identities != 0 {
			t.Fatalf("email collision left users before=%d after=%d identities=%d", before, after, identities)
		}
	})
}

func equalOptionalInt64(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
