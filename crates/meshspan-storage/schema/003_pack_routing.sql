-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE pack_segments (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    assigned_bytes INTEGER NOT NULL CHECK (assigned_bytes >= 0),
    assigned_records INTEGER NOT NULL CHECK (assigned_records >= 0)
) STRICT;

CREATE TABLE pack_routes (
    shard_identity BLOB PRIMARY KEY CHECK (length(shard_identity) = 46),
    pack_sequence INTEGER NOT NULL REFERENCES pack_segments(sequence),
    expected_length INTEGER NOT NULL CHECK (expected_length > 0),
    expected_digest BLOB NOT NULL CHECK (length(expected_digest) = 32)
) STRICT;

CREATE INDEX pack_routes_by_segment ON pack_routes(pack_sequence, shard_identity);

INSERT INTO pack_segments VALUES (1, 0, 0);
INSERT OR IGNORE INTO pack_segments
SELECT pack_sequence, 0, 0 FROM inventory;

INSERT INTO pack_routes
SELECT shard_identity, pack_sequence, stored_length, stored_digest FROM inventory;

-- Before routing existed, incomplete puts could only have reached pack 1.
-- DISTINCT coalesces exact retries; contradictory identities fail the primary key.
INSERT INTO pack_routes
SELECT DISTINCT op.shard_identity, 1, op.expected_length, op.expected_digest
FROM provider_operations AS op
WHERE op.operation_kind = 1
  AND NOT EXISTS (SELECT 1 FROM inventory AS inv WHERE inv.shard_identity = op.shard_identity);

UPDATE pack_segments SET
    assigned_bytes = (SELECT COALESCE(sum(expected_length), 0) FROM pack_routes
                      WHERE pack_sequence = pack_segments.sequence),
    assigned_records = (SELECT count(*) FROM pack_routes
                        WHERE pack_sequence = pack_segments.sequence);
