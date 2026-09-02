-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE content_stripe_shards
ADD COLUMN required_for_commit INTEGER NOT NULL DEFAULT 1
CHECK (required_for_commit IN (0, 1));
