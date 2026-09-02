-- SPDX-License-Identifier: GPL-2.0-only

-- Scrub evidence names immutable shard roots rather than local publication operations. Manifest
-- roots include the unique manifest identity, so a committed root has exactly one local owner.
CREATE UNIQUE INDEX committed_content_by_root_digest
ON content_publications(root_digest)
WHERE state = 2;
