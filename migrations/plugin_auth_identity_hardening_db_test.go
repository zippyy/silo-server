package migrations

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const requireAuthDBTestsEnv = "SILO_REQUIRE_AUTH_DB_TESTS"

func TestPluginAuthIdentityHardeningMigrationDB(t *testing.T) {
	t.Run("one auth capability preserves every owner", func(t *testing.T) {
		conn := newLegacyPluginIdentityDB(t)
		seedLegacyPluginIdentity(t, conn, 10, []string{"ldap"}, map[string]int{
			"entryUUID:alice": 100,
			"entryUUID:bob":   101,
		})

		applyMigrationSection(t, conn, "sql/20260809153621_harden_plugin_auth_identities.sql", true)

		rows, err := conn.Query(context.Background(), `
			SELECT capability_id, external_subject, user_id
			FROM public.plugin_auth_identities
			ORDER BY external_subject`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		want := []struct {
			capability string
			subject    string
			userID     int
		}{
			{"ldap", "entryUUID:alice", 100},
			{"ldap", "entryUUID:bob", 101},
		}
		rowCount := 0
		for rows.Next() {
			i := rowCount
			if i >= len(want) {
				t.Fatal("migration manufactured an extra identity")
			}
			var got struct {
				capability string
				subject    string
				userID     int
			}
			if err := rows.Scan(&got.capability, &got.subject, &got.userID); err != nil {
				t.Fatal(err)
			}
			if got != want[i] {
				t.Fatalf("identity %d = %#v, want %#v", i, got, want[i])
			}
			rowCount++
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if rowCount != len(want) {
			t.Fatalf("migration returned %d identities, want %d", rowCount, len(want))
		}
	})

	for _, test := range []struct {
		name         string
		capabilities []string
		wantCount    string
	}{
		{name: "zero auth capabilities fails closed", wantCount: "found 0"},
		{name: "multiple auth capabilities fails closed", capabilities: []string{"ldap", "oidc"}, wantCount: "found 2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := newLegacyPluginIdentityDB(t)
			seedLegacyPluginIdentity(t, conn, 20, test.capabilities, map[string]int{"subject-1234": 100})

			err := executeMigrationSection(conn, "sql/20260809153621_harden_plugin_auth_identities.sql", true)
			if err == nil || !strings.Contains(err.Error(), "expected exactly one matching auth capability binding") || !strings.Contains(err.Error(), test.wantCount) {
				t.Fatalf("migration error = %v, want actionable ambiguity failure containing %q", err, test.wantCount)
			}

			var capabilityColumnCount int
			if err := conn.QueryRow(context.Background(), `
				SELECT count(*)
				FROM information_schema.columns
				WHERE table_schema = 'public'
				  AND table_name = 'plugin_auth_identities'
				  AND column_name = 'capability_id'`).Scan(&capabilityColumnCount); err != nil {
				t.Fatal(err)
			}
			if capabilityColumnCount != 0 {
				t.Fatal("failed migration left a partially capability-scoped identity table")
			}
			var userID, identityCount int
			if err := conn.QueryRow(context.Background(), `
				SELECT min(user_id), count(*)
				FROM public.plugin_auth_identities
				WHERE plugin_installation_id = 20 AND external_subject = 'subject-1234'`).Scan(&userID, &identityCount); err != nil {
				t.Fatal(err)
			}
			if userID != 100 || identityCount != 1 {
				t.Fatalf("legacy ownership changed after failed migration: user=%d rows=%d", userID, identityCount)
			}
		})
	}

	t.Run("independent capabilities may own the same subject without repointing", func(t *testing.T) {
		conn := newLegacyPluginIdentityDB(t)
		seedLegacyPluginIdentity(t, conn, 30, []string{"ldap"}, map[string]int{"1234": 100})
		applyMigrationSection(t, conn, "sql/20260809153621_harden_plugin_auth_identities.sql", true)

		if _, err := conn.Exec(context.Background(), `
			INSERT INTO public.users (id) VALUES (101);
			INSERT INTO public.plugin_capabilities (
				plugin_installation_id, capability_type, capability_id
			) VALUES (30, 'auth_provider.v1', 'oidc');
			INSERT INTO public.plugin_auth_bindings (plugin_installation_id, capability_id)
			VALUES (30, 'oidc');
			INSERT INTO public.plugin_auth_identities (
				plugin_installation_id, capability_id, external_subject, user_id
			) VALUES (30, 'oidc', '1234', 101);`); err != nil {
			t.Fatal(err)
		}
		rows, err := conn.Query(context.Background(), `
			SELECT capability_id, user_id
			FROM public.plugin_auth_identities
			WHERE plugin_installation_id = 30 AND external_subject = '1234'
			ORDER BY capability_id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		owners := map[string]int{}
		for rows.Next() {
			var capability string
			var userID int
			if err := rows.Scan(&capability, &userID); err != nil {
				t.Fatal(err)
			}
			owners[capability] = userID
		}
		if owners["ldap"] != 100 || owners["oidc"] != 101 || len(owners) != 2 {
			t.Fatalf("capability ownership = %#v, want ldap:100 and oidc:101", owners)
		}

		err = executeMigrationSection(conn, "sql/20260809153621_harden_plugin_auth_identities.sql", false)
		if err == nil || !strings.Contains(err.Error(), "different owners") {
			t.Fatalf("downgrade error = %v, want refusal to collapse different owners", err)
		}
		var rowsAfterFailedDown int
		if err := conn.QueryRow(context.Background(), `
			SELECT count(*) FROM public.plugin_auth_identities
			WHERE plugin_installation_id = 30 AND external_subject = '1234'`).Scan(&rowsAfterFailedDown); err != nil {
			t.Fatal(err)
		}
		if rowsAfterFailedDown != 2 {
			t.Fatalf("failed downgrade changed identity rows: got %d, want 2", rowsAfterFailedDown)
		}
	})
}

func TestManagedRolesAuthorizationMigrationDefaultsExistingBindingsOffDB(t *testing.T) {
	conn := newLegacyPluginIdentityDB(t)
	seedLegacyPluginIdentity(t, conn, 40, []string{"ldap"}, nil)

	applyMigrationSection(t, conn, "sql/20260809170000_authorize_managed_plugin_roles.sql", true)

	var enabled bool
	if err := conn.QueryRow(context.Background(), `
		SELECT managed_roles_enabled
		FROM public.plugin_auth_bindings
		WHERE plugin_installation_id = 40 AND capability_id = 'ldap'`).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("migration enabled managed-role authority for an existing binding")
	}

	applyMigrationSection(t, conn, "sql/20260809170000_authorize_managed_plugin_roles.sql", false)
	var columnCount int
	if err := conn.QueryRow(context.Background(), `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema = 'public'
		  AND table_name = 'plugin_auth_bindings'
		  AND column_name = 'managed_roles_enabled'`).Scan(&columnCount); err != nil {
		t.Fatal(err)
	}
	if columnCount != 0 {
		t.Fatal("managed-role authorization migration did not downgrade cleanly")
	}
}

func newLegacyPluginIdentityDB(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("SILO_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv(requireAuthDBTestsEnv) == "1" {
			t.Fatalf("%s=1 requires SILO_TEST_DATABASE_URL", requireAuthDBTestsEnv)
		}
		t.Skip("SILO_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect database admin: %v", err)
	}
	databaseName := "silo_auth_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{databaseName}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier); err != nil {
		admin.Close(ctx)
		t.Fatalf("create migration test database: %v", err)
	}

	testConfig := adminConfig.Copy()
	testConfig.Database = databaseName
	testConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(ctx, testConfig)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP DATABASE "+identifier+" WITH (FORCE)")
		admin.Close(ctx)
		t.Fatalf("connect migration test database: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close(ctx)
		if _, err := admin.Exec(ctx, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
			t.Errorf("drop migration test database: %v", err)
		}
		_ = admin.Close(ctx)
	})

	if _, err := conn.Exec(ctx, `
		CREATE TABLE public.users (id INTEGER PRIMARY KEY);
		CREATE TABLE public.access_groups (id BIGINT PRIMARY KEY);
		CREATE TABLE public.plugin_installations (id BIGINT PRIMARY KEY);
		CREATE TABLE public.plugin_capabilities (
			id BIGSERIAL PRIMARY KEY,
			plugin_installation_id BIGINT NOT NULL REFERENCES public.plugin_installations(id) ON DELETE CASCADE,
			capability_type TEXT NOT NULL,
			capability_id TEXT NOT NULL
		);
		CREATE TABLE public.plugin_auth_bindings (
			id BIGSERIAL PRIMARY KEY,
			plugin_installation_id BIGINT NOT NULL REFERENCES public.plugin_installations(id) ON DELETE CASCADE,
			capability_id TEXT NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT true,
			display_order INTEGER NOT NULL DEFAULT 0,
			auto_provision BOOLEAN NOT NULL DEFAULT false,
			default_login BOOLEAN NOT NULL DEFAULT false,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE UNIQUE INDEX idx_plugin_auth_bindings_installation_capability
			ON public.plugin_auth_bindings (plugin_installation_id, capability_id);
		CREATE TABLE public.plugin_auth_identities (
			id BIGSERIAL PRIMARY KEY,
			plugin_installation_id BIGINT NOT NULL REFERENCES public.plugin_installations(id) ON DELETE CASCADE,
			external_subject TEXT NOT NULL,
			user_id INTEGER NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE UNIQUE INDEX idx_plugin_auth_identities_installation_subject
			ON public.plugin_auth_identities (plugin_installation_id, external_subject);`); err != nil {
		t.Fatalf("create legacy plugin auth schema: %v", err)
	}
	return conn
}

func seedLegacyPluginIdentity(
	t *testing.T,
	conn *pgx.Conn,
	installationID int,
	capabilities []string,
	identities map[string]int,
) {
	t.Helper()
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `INSERT INTO public.plugin_installations (id) VALUES ($1)`, installationID); err != nil {
		t.Fatal(err)
	}
	for _, capability := range capabilities {
		if _, err := conn.Exec(ctx, `
			INSERT INTO public.plugin_capabilities (
				plugin_installation_id, capability_type, capability_id
			) VALUES ($1, 'auth_provider.v1', $2)`, installationID, capability); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `
			INSERT INTO public.plugin_auth_bindings (plugin_installation_id, capability_id)
			VALUES ($1, $2)`, installationID, capability); err != nil {
			t.Fatal(err)
		}
	}
	for subject, userID := range identities {
		if _, err := conn.Exec(ctx, `INSERT INTO public.users (id) VALUES ($1) ON CONFLICT DO NOTHING`, userID); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `
			INSERT INTO public.plugin_auth_identities (plugin_installation_id, external_subject, user_id)
			VALUES ($1, $2, $3)`, installationID, subject, userID); err != nil {
			t.Fatal(err)
		}
	}
}

func applyMigrationSection(t *testing.T, conn *pgx.Conn, path string, up bool) {
	t.Helper()
	if err := executeMigrationSection(conn, path, up); err != nil {
		t.Fatalf("apply migration %s up=%v: %v", path, up, err)
	}
}

func executeMigrationSection(conn *pgx.Conn, path string, up bool) error {
	migrationBytes, err := FS.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	parts := strings.SplitN(string(migrationBytes), "-- +goose Down", 2)
	if len(parts) != 2 {
		return fmt.Errorf("migration %s has no down section", path)
	}
	section := parts[0]
	if !up {
		section = parts[1]
	}
	ctx := context.Background()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, section); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
