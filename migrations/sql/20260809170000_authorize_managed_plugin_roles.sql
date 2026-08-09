-- +goose Up
ALTER TABLE public.plugin_auth_bindings
    ADD COLUMN managed_roles_enabled BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE public.plugin_auth_bindings
    DROP COLUMN managed_roles_enabled;
