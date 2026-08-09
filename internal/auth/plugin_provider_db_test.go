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
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/access"
	"github.com/Silo-Server/silo-server/internal/models"
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
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name = 'plugin_auth_identities'
			  AND column_name = 'capability_id'
		)`).Scan(&hardened); err != nil {
		pool.Close()
		t.Fatalf("check plugin identity migration: %v", err)
	}
	if !hardened {
		pool.Close()
		if os.Getenv("SILO_REQUIRE_AUTH_DB_TESTS") == "1" {
			t.Fatal("SILO_REQUIRE_AUTH_DB_TESTS=1 requires plugin auth hardening migrations")
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
		INSERT INTO plugin_auth_bindings (
			plugin_installation_id, capability_id, enabled, auto_provision
		) VALUES ($1, $2, true, true)`, installationID, capabilityID); err != nil {
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

func (f *pluginProviderDBFixture) provider(managed bool) *PluginProvider {
	contract := ""
	if managed {
		contract = ManagedRoleContractV1
	}
	return NewPluginProviderWithClientFactory(
		PluginProviderConfig{
			InstallationID:      f.installationID,
			CapabilityID:        f.capabilityID,
			DisplayName:         "LDAP",
			AutoProvision:       true,
			ManagedRoleContract: contract,
		},
		NewSessionRepository(f.pool),
		NewUserRepository(f.pool),
		f.pool,
		nil,
	)
}

func (f *pluginProviderDBFixture) response(subject, displayName, email, role string) *pluginv1.AuthenticateResponse {
	response := &pluginv1.AuthenticateResponse{
		ExternalSubject: subject,
		DisplayName:     displayName,
		Email:           email,
	}
	if role != "" {
		claims, err := structpb.NewStruct(managedRoleClaims(role))
		if err != nil {
			f.t.Fatalf("build managed-role claims: %v", err)
		}
		response.Claims = claims
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

func TestPluginMalformedManagedRoleDoesNotModifyDB(t *testing.T) {
	f := newPluginProviderDBFixture(t)
	ctx := context.Background()
	customGroupID := f.createGroup(ctx, "malformed")
	permissions := []string{string(PermissionMetadataCuration)}
	user, key := f.createIdentityUser(ctx, "user", permissions, &customGroupID, "entryUUID:malformed-role")
	response := f.response(key.ExternalSubject, user.Username, user.Email, "")
	claims, err := structpb.NewStruct(map[string]any{
		managedRoleMarkerClaimKey:   true,
		managedRoleContractClaimKey: "silo.auth.managed-role.v2",
		managedRoleClaimKey:         "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	response.Claims = claims

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
