-- +goose NO TRANSACTION

-- +goose Up
-- Drop the claim/lease columns and index added experimentally and later
-- removed from the codebase. New code uses AlreadySubmitted + UPSERT
-- instead of advisory-lock claims.
DROP INDEX CONCURRENTLY IF EXISTS public.marker_contributions_provider_hash_active_uidx;
ALTER TABLE public.marker_contributions
    DROP COLUMN IF EXISTS claim_active,
    DROP COLUMN IF EXISTS claim_token;

-- +goose Down
-- Columns and index are intentionally not restored. The claim/lease
-- system was removed in favor of a simpler deduplication approach, and
-- restoring these columns would create orphaned schema without matching
-- application code.