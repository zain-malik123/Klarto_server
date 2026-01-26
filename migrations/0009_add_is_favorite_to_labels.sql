-- Migration 0009: add is_favorite column to labels
BEGIN;

ALTER TABLE IF EXISTS labels ADD COLUMN IF NOT EXISTS is_favorite boolean NOT NULL DEFAULT false;

COMMIT;
