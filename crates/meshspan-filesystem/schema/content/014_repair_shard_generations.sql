-- SPDX-License-Identifier: GPL-2.0-only

-- Existing effects used the same physical generation at both ends. Preserve those receipts;
-- subsequent replacements can advance their physical fence without changing immutable bytes.
ALTER TABLE content_shard_repair_effects ADD COLUMN replacement_shard_generation INTEGER NOT NULL DEFAULT 1
    CHECK (replacement_shard_generation BETWEEN 1 AND 4294967295);
UPDATE content_shard_repair_effects SET replacement_shard_generation = shard_generation;
