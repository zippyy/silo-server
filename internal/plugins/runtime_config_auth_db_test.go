package plugins

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAuthBindingManagedRolesAuthorizationDB(t *testing.T) {
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
	prefix := "managed-role-binding-" + uuid.NewString()
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
	})

	store := NewRuntimeConfigStore(pool)
	if err := store.UpsertAuthBinding(ctx, AuthBinding{
		InstallationID: installationID,
		CapabilityID:   "ldap",
		Enabled:        true,
		AutoProvision:  true,
	}); err != nil {
		t.Fatal(err)
	}
	binding, err := store.GetAuthBinding(ctx, installationID, "ldap")
	if err != nil {
		t.Fatal(err)
	}
	if binding.ManagedRolesEnabled {
		t.Fatal("new auth binding enabled managed roles without operator opt-in")
	}

	binding.ManagedRolesEnabled = true
	if err := store.UpsertAuthBinding(ctx, *binding); err != nil {
		t.Fatal(err)
	}
	reloaded, err := store.GetAuthBinding(ctx, installationID, "ldap")
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.ManagedRolesEnabled {
		t.Fatal("operator managed-role authorization was not persisted")
	}
}
