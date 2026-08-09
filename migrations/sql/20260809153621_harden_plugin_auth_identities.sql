-- +goose Up
ALTER TABLE public.plugin_auth_identities
    ADD COLUMN capability_id TEXT,
    ADD COLUMN managed_role_snapshot_present BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN managed_role_snapshot_permissions TEXT[],
    ADD COLUMN managed_role_snapshot_access_group_id BIGINT
        REFERENCES public.access_groups(id) ON DELETE SET NULL;

UPDATE public.plugin_auth_identities AS identity
SET capability_id = (
    SELECT capability_id
    FROM public.plugin_auth_bindings
    WHERE plugin_installation_id = identity.plugin_installation_id
    ORDER BY capability_id
    LIMIT 1
);

UPDATE public.plugin_auth_identities
SET capability_id = '__legacy__'
WHERE capability_id IS NULL;

DROP INDEX public.idx_plugin_auth_identities_installation_subject;

INSERT INTO public.plugin_auth_identities (
    plugin_installation_id,
    capability_id,
    external_subject,
    user_id,
    created_at,
    updated_at
)
SELECT
    identity.plugin_installation_id,
    binding.capability_id,
    identity.external_subject,
    identity.user_id,
    identity.created_at,
    identity.updated_at
FROM public.plugin_auth_identities AS identity
JOIN public.plugin_auth_bindings AS binding
  ON binding.plugin_installation_id = identity.plugin_installation_id
WHERE binding.capability_id <> identity.capability_id;

ALTER TABLE public.plugin_auth_identities
    ALTER COLUMN capability_id SET NOT NULL;

CREATE UNIQUE INDEX idx_plugin_auth_identities_installation_capability_subject
    ON public.plugin_auth_identities (plugin_installation_id, capability_id, external_subject);

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM public.plugin_auth_identities
        WHERE managed_role_snapshot_present
    ) THEN
        RAISE EXCEPTION 'cannot roll back plugin auth hardening while managed-role snapshots exist';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM public.plugin_auth_identities
        GROUP BY plugin_installation_id, external_subject
        HAVING COUNT(DISTINCT user_id) > 1
    ) THEN
        RAISE EXCEPTION 'cannot collapse capability-scoped plugin identities with different owners';
    END IF;
END
$$;
-- +goose StatementEnd

DROP INDEX public.idx_plugin_auth_identities_installation_capability_subject;

DELETE FROM public.plugin_auth_identities AS duplicate
USING public.plugin_auth_identities AS keeper
WHERE duplicate.plugin_installation_id = keeper.plugin_installation_id
  AND duplicate.external_subject = keeper.external_subject
  AND duplicate.id > keeper.id;

ALTER TABLE public.plugin_auth_identities
    DROP COLUMN managed_role_snapshot_access_group_id,
    DROP COLUMN managed_role_snapshot_permissions,
    DROP COLUMN managed_role_snapshot_present,
    DROP COLUMN capability_id;

CREATE UNIQUE INDEX idx_plugin_auth_identities_installation_subject
    ON public.plugin_auth_identities (plugin_installation_id, external_subject);
