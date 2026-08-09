-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    unresolved RECORD;
BEGIN
    SELECT identities.plugin_installation_id, COUNT(capabilities.id) AS binding_count
      INTO unresolved
    FROM (
        SELECT DISTINCT plugin_installation_id
        FROM public.plugin_auth_identities
    ) AS identities
    LEFT JOIN public.plugin_auth_bindings AS bindings
      ON bindings.plugin_installation_id = identities.plugin_installation_id
    LEFT JOIN public.plugin_capabilities AS capabilities
      ON capabilities.plugin_installation_id = bindings.plugin_installation_id
     AND capabilities.capability_type = 'auth_provider.v1'
     AND capabilities.capability_id = bindings.capability_id
    GROUP BY identities.plugin_installation_id
    HAVING COUNT(capabilities.id) <> 1
    ORDER BY identities.plugin_installation_id
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION
            'cannot scope legacy plugin auth identities for installation %: expected exactly one matching auth capability binding, found %; resolve plugin_capabilities/plugin_auth_bindings before retrying',
            unresolved.plugin_installation_id,
            unresolved.binding_count;
    END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE public.plugin_auth_identities
    ADD COLUMN capability_id TEXT,
    ADD COLUMN managed_role_snapshot_present BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN managed_role_snapshot_permissions TEXT[],
    ADD COLUMN managed_role_snapshot_access_group_id BIGINT
        REFERENCES public.access_groups(id) ON DELETE SET NULL;

UPDATE public.plugin_auth_identities AS identity
SET capability_id = binding.capability_id
FROM public.plugin_auth_bindings AS binding
JOIN public.plugin_capabilities AS capability
  ON capability.plugin_installation_id = binding.plugin_installation_id
 AND capability.capability_type = 'auth_provider.v1'
 AND capability.capability_id = binding.capability_id
WHERE binding.plugin_installation_id = identity.plugin_installation_id;

DROP INDEX public.idx_plugin_auth_identities_installation_subject;

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
