-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE content_publications
ADD COLUMN strong_deadline_at INTEGER NULL;

ALTER TABLE content_publications
ADD COLUMN strong_fallback_mode INTEGER NOT NULL DEFAULT 1
CHECK (strong_fallback_mode BETWEEN 1 AND 3);

ALTER TABLE content_publications
ADD COLUMN acknowledgement_outcome INTEGER NOT NULL DEFAULT 1
CHECK (acknowledgement_outcome IN (1, 2));

ALTER TABLE content_stripe_shards
ADD COLUMN eventual_fallback_required INTEGER NOT NULL DEFAULT 1
CHECK (eventual_fallback_required IN (0, 1));
