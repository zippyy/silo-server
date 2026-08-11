-- +goose Up
ALTER TABLE public.plugin_auth_identities
    ADD COLUMN managed_role_snapshot_access_group_present BOOLEAN NOT NULL DEFAULT false;

UPDATE public.plugin_auth_identities
SET managed_role_snapshot_access_group_present = true
WHERE managed_role_snapshot_present
  AND managed_role_snapshot_access_group_id IS NOT NULL;

-- +goose Down
ALTER TABLE public.plugin_auth_identities
    DROP COLUMN managed_role_snapshot_access_group_present;
