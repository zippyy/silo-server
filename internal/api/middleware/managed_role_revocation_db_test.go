package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"github.com/Silo-Server/silo-server/internal/audiobooks"
	"github.com/Silo-Server/silo-server/internal/audiobooks/abs"
	"github.com/Silo-Server/silo-server/internal/auth"
	"github.com/Silo-Server/silo-server/internal/jellycompat"
	"github.com/Silo-Server/silo-server/internal/models"
	"github.com/Silo-Server/silo-server/internal/plugins"
	"github.com/Silo-Server/silo-server/internal/secret"
)

func TestManagedRoleDemotionRejectsExistingAdminTokenDB(t *testing.T) {
	dsn := os.Getenv("SILO_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("SILO_REQUIRE_AUTH_DB_TESTS") == "1" {
			t.Fatal("SILO_REQUIRE_AUTH_DB_TESTS=1 requires SILO_TEST_DATABASE_URL")
		}
		t.Skip("SILO_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var hardened bool
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) = 2
			FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name = 'plugin_auth_identities'
			  AND column_name IN ('capability_id', 'managed_role_snapshot_access_group_present')`).Scan(&hardened); err != nil {
		t.Fatal(err)
	}
	if !hardened {
		if os.Getenv("SILO_REQUIRE_AUTH_DB_TESTS") == "1" {
			t.Fatal("SILO_REQUIRE_AUTH_DB_TESTS=1 requires all plugin auth hardening migrations")
		}
		t.Skip("plugin auth identity hardening migration is not applied")
	}

	prefix := "managed-role-http-" + uuid.NewString()
	var installationID int
	if err := pool.QueryRow(ctx, `
		INSERT INTO plugin_installations (plugin_id, version, install_path)
		VALUES ($1, 'test', $2)
		RETURNING id`, prefix, "/tmp/"+prefix).Scan(&installationID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM plugin_installations WHERE id = $1`, installationID); err != nil {
			t.Errorf("delete plugin installation: %v", err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, prefix+"@example.test"); err != nil {
			t.Errorf("delete user: %v", err)
		}
	})
	if _, err := pool.Exec(ctx, `
		INSERT INTO plugin_capabilities (
			plugin_installation_id, capability_type, capability_id, metadata
		) VALUES ($1, 'auth_provider.v1', 'ldap', '{"auth_provider":{"managed_roles":{"supported_roles":["MANAGED_SILO_ROLE_USER","MANAGED_SILO_ROLE_ADMIN"]}}}'::jsonb)`, installationID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO plugin_auth_bindings (
			plugin_installation_id, capability_id, enabled, auto_provision, managed_roles_enabled
		)
		VALUES ($1, 'ldap', true, true, true)`, installationID); err != nil {
		t.Fatal(err)
	}
	userRepo := auth.NewUserRepository(pool)
	user, err := userRepo.Create(ctx, models.CreateUserInput{
		Email:    prefix + "@example.test",
		Username: prefix,
		Password: "test-only-password",
		Role:     "user",
	})
	if err != nil {
		t.Fatal(err)
	}
	key := auth.PluginIdentityKey{
		InstallationID:  installationID,
		CapabilityID:    "ldap",
		ExternalSubject: "entryUUID:http-admin",
	}
	identityRepo := auth.NewPluginIdentityRepository(pool)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := identityRepo.ClaimTx(ctx, tx, key, user.ID)
	if err != nil || !claimed {
		_ = tx.Rollback(ctx)
		t.Fatalf("claim identity=%v, %v", claimed, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	sessions := auth.NewSessionRepository(pool)
	provider := auth.NewPluginProviderWithClientFactory(
		auth.PluginProviderConfig{
			InstallationID: installationID,
			CapabilityID:   "ldap",
		},
		sessions,
		userRepo,
		pool,
		nil,
		auth.WithAuthProviderAuthorityStore(plugins.NewRuntimeConfigStore(pool)),
	)
	response := managedRoleResponse(t, key.ExternalSubject, "admin")
	promoted, err := provider.CompleteOAuth(ctx, response)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Role != "admin" {
		t.Fatalf("promoted role=%q, want admin", promoted.Role)
	}

	sessionID := uuid.NewString()
	if err := sessions.Create(ctx, models.AuthSession{
		ID:        sessionID,
		UserID:    promoted.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	jwtService := auth.NewJWTService("managed-role-revocation-test-secret", time.Hour, time.Hour)
	token, err := jwtService.GenerateAccessToken(promoted.ID, "admin", sessionID)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAuthMiddleware(jwtService, sessions, nil, nil).RequireAuth(
		RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})),
	)
	request := func() int {
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code
	}
	if status := request(); status != http.StatusNoContent {
		t.Fatalf("admin token before demotion status=%d, want %d", status, http.StatusNoContent)
	}

	cipher, err := secret.New([]byte("managed-role-compat-session-test-key"))
	if err != nil {
		t.Fatal(err)
	}
	jellyStore := jellycompat.NewPersistentSessionStore(
		time.Hour,
		time.Now,
		jellycompat.NewSessionRepository(pool, cipher),
	)
	jellyTokens := []string{uuid.NewString(), uuid.NewString()}
	for _, jellyToken := range jellyTokens {
		if err := jellyStore.Put(jellycompat.Session{
			Token:                 jellyToken,
			Username:              promoted.Username,
			AccountUsername:       promoted.Username,
			ProfileID:             uuid.NewString(),
			ProfileName:           promoted.Username,
			PseudoUserID:          uuid.New(),
			StreamAppUserID:       promoted.ID,
			StreamAppAccessToken:  "compat-access",
			StreamAppRefreshToken: "compat-refresh",
			StreamAppTokenExpiry:  time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	absStore := &audiobooks.ABSSessionStore{Pool: pool}
	absTokens := []string{uuid.NewString(), uuid.NewString()}
	for index, jti := range absTokens {
		tokenType := "access"
		if index == 1 {
			tokenType = "refresh"
		}
		if err := absStore.InsertToken(ctx, abs.ABSToken{
			UserID:    strconv.Itoa(promoted.ID),
			ProfileID: uuid.NewString(),
			JTI:       jti,
			Type:      tokenType,
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, jellyToken := range jellyTokens {
		if _, ok := jellyStore.Get(jellyToken); !ok {
			t.Fatal("Jellyfin compatibility session did not resolve before demotion")
		}
	}
	for _, jti := range absTokens {
		token, err := absStore.GetTokenByJTI(ctx, jti)
		if err != nil || token.RevokedAt != nil {
			t.Fatalf("ABS token before demotion = %+v, %v", token, err)
		}
	}

	revokeCompat := func(ctx context.Context, userID int) error {
		var revokeErrors []error
		if err := jellyStore.RevokeByUserID(ctx, userID); err != nil {
			revokeErrors = append(revokeErrors, err)
		}
		if err := absStore.RevokeTokensByUserID(ctx, userID); err != nil {
			revokeErrors = append(revokeErrors, err)
		}
		return errors.Join(revokeErrors...)
	}
	provider = auth.NewPluginProviderWithClientFactory(
		auth.PluginProviderConfig{
			InstallationID: installationID,
			CapabilityID:   "ldap",
		},
		sessions,
		userRepo,
		pool,
		nil,
		auth.WithAuthProviderAuthorityStore(plugins.NewRuntimeConfigStore(pool)),
		auth.WithUserSessionRevoker(revokeCompat),
	)
	failingProvider := auth.NewPluginProviderWithClientFactory(
		auth.PluginProviderConfig{
			InstallationID: installationID,
			CapabilityID:   "ldap",
		},
		nil,
		userRepo,
		pool,
		nil,
		auth.WithAuthProviderAuthorityStore(plugins.NewRuntimeConfigStore(pool)),
		auth.WithUserSessionRevoker(revokeCompat),
	)
	if _, err := failingProvider.CompleteOAuth(ctx, managedRoleResponse(t, key.ExternalSubject, "user")); err == nil {
		t.Fatal("demotion without the transactional session repository unexpectedly succeeded")
	}
	if status := request(); status != http.StatusNoContent {
		t.Fatalf("failed demotion revoked main session: status=%d", status)
	}
	for _, jellyToken := range jellyTokens {
		if _, ok := jellyStore.Get(jellyToken); !ok {
			t.Fatal("failed demotion revoked Jellyfin compatibility session")
		}
	}
	for _, jti := range absTokens {
		token, err := absStore.GetTokenByJTI(ctx, jti)
		if err != nil || token.RevokedAt != nil {
			t.Fatalf("failed demotion changed ABS token = %+v, %v", token, err)
		}
	}

	if _, err := provider.CompleteOAuth(ctx, managedRoleResponse(t, key.ExternalSubject, "user")); err != nil {
		t.Fatal(err)
	}
	if status := request(); status != http.StatusUnauthorized {
		t.Fatalf("same admin token after demotion status=%d, want %d", status, http.StatusUnauthorized)
	}
	for _, jellyToken := range jellyTokens {
		if _, ok := jellyStore.Get(jellyToken); ok {
			t.Fatal("Jellyfin compatibility session survived successful demotion")
		}
	}
	for _, jti := range absTokens {
		token, err := absStore.GetTokenByJTI(ctx, jti)
		if err != nil {
			t.Fatal(err)
		}
		if token.RevokedAt == nil {
			t.Fatalf("ABS %s token survived successful demotion", token.Type)
		}
	}
}

func managedRoleResponse(t *testing.T, subject, role string) *pluginv1.AuthenticateResponse {
	t.Helper()
	var sdkRole pluginv1.ManagedSiloRole
	switch role {
	case "user":
		sdkRole = pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_USER
	case "admin":
		sdkRole = pluginv1.ManagedSiloRole_MANAGED_SILO_ROLE_ADMIN
	default:
		t.Fatalf("unsupported managed role %q", role)
	}
	return &pluginv1.AuthenticateResponse{
		ExternalSubject: subject,
		ManagedSiloRole: &pluginv1.ManagedSiloRoleAssertion{Role: sdkRole},
	}
}
