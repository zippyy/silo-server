package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PluginIdentityKey struct {
	InstallationID  int
	CapabilityID    string
	ExternalSubject string
}

type PluginAuthIdentity struct {
	ID                    int64
	UserID                int
	SnapshotPresent       bool
	SnapshotPermissions   []string
	SnapshotAccessGroupID *int64
	// SnapshotAccessGroupPresent distinguishes a deliberately ungrouped
	// snapshot from a group reference cleared by ON DELETE SET NULL.
	SnapshotAccessGroupPresent bool
}

type pluginIdentityQueryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type PluginIdentityRepository struct {
	pool *pgxpool.Pool
}

func NewPluginIdentityRepository(pool *pgxpool.Pool) *PluginIdentityRepository {
	return &PluginIdentityRepository{pool: pool}
}

func (r *PluginIdentityRepository) Begin(ctx context.Context) (pgx.Tx, error) {
	return r.pool.BeginTx(ctx, pgx.TxOptions{})
}

func (r *PluginIdentityRepository) Get(ctx context.Context, key PluginIdentityKey) (*PluginAuthIdentity, error) {
	return r.get(ctx, r.pool, key, false)
}

func (r *PluginIdentityRepository) GetTx(
	ctx context.Context,
	tx pgx.Tx,
	key PluginIdentityKey,
	forUpdate bool,
) (*PluginAuthIdentity, error) {
	return r.get(ctx, tx, key, forUpdate)
}

func (r *PluginIdentityRepository) get(
	ctx context.Context,
	db pluginIdentityQueryRower,
	key PluginIdentityKey,
	forUpdate bool,
) (*PluginAuthIdentity, error) {
	query := `
		SELECT id, user_id, managed_role_snapshot_present,
		       managed_role_snapshot_permissions, managed_role_snapshot_access_group_id,
		       managed_role_snapshot_access_group_present
		FROM plugin_auth_identities
		WHERE plugin_installation_id = $1
		  AND capability_id = $2
		  AND external_subject = $3`
	if forUpdate {
		query += " FOR UPDATE"
	}
	var identity PluginAuthIdentity
	err := db.QueryRow(ctx, query, key.InstallationID, key.CapabilityID, key.ExternalSubject).Scan(
		&identity.ID,
		&identity.UserID,
		&identity.SnapshotPresent,
		&identity.SnapshotPermissions,
		&identity.SnapshotAccessGroupID,
		&identity.SnapshotAccessGroupPresent,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup plugin auth identity: %w", err)
	}
	return &identity, nil
}

func (r *PluginIdentityRepository) ClaimTx(
	ctx context.Context,
	tx pgx.Tx,
	key PluginIdentityKey,
	userID int,
) (bool, error) {
	var id int64
	err := tx.QueryRow(ctx, `
		INSERT INTO plugin_auth_identities (
			plugin_installation_id, capability_id, external_subject, user_id
		)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (plugin_installation_id, capability_id, external_subject) DO NOTHING
		RETURNING id`,
		key.InstallationID,
		key.CapabilityID,
		key.ExternalSubject,
		userID,
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim plugin auth identity: %w", err)
	}
	return true, nil
}

func (r *PluginIdentityRepository) SaveManagedRoleSnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	identityID int64,
	permissions []string,
	accessGroupID *int64,
) error {
	tag, err := tx.Exec(ctx, `
		UPDATE plugin_auth_identities
		SET managed_role_snapshot_present = true,
		    managed_role_snapshot_permissions = $2,
		    managed_role_snapshot_access_group_id = $3,
		    managed_role_snapshot_access_group_present = $4,
		    updated_at = NOW()
		WHERE id = $1
		  AND NOT managed_role_snapshot_present`,
		identityID,
		permissions,
		accessGroupID,
		accessGroupID != nil,
	)
	if err != nil {
		return fmt.Errorf("save managed-role authorization snapshot: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("save managed-role authorization snapshot: identity not found or snapshot already exists")
	}
	return nil
}

func (r *PluginIdentityRepository) ClearManagedRoleSnapshotTx(ctx context.Context, tx pgx.Tx, identityID int64) error {
	tag, err := tx.Exec(ctx, `
		UPDATE plugin_auth_identities
		SET managed_role_snapshot_present = false,
		    managed_role_snapshot_permissions = NULL,
		    managed_role_snapshot_access_group_id = NULL,
		    managed_role_snapshot_access_group_present = false,
		    updated_at = NOW()
		WHERE id = $1`, identityID)
	if err != nil {
		return fmt.Errorf("clear managed-role authorization snapshot: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
