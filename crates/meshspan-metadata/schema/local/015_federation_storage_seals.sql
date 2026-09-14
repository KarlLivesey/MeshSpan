-- SPDX-License-Identifier: GPL-2.0-only

-- A seal stops new admission without cancelling already admitted IO. Its ceiling
-- covers committed bytes and every unresolved reservation, not just visible files.
CREATE TABLE local_federation_storage_seals (
    allocation_id BLOB PRIMARY KEY
        REFERENCES local_federation_storage_usage(allocation_id) ON DELETE RESTRICT,
    ceiling_bytes INTEGER NOT NULL CHECK (ceiling_bytes >= 0),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    sealed_at INTEGER NOT NULL CHECK (sealed_at > 0)
) STRICT;

CREATE TRIGGER local_federation_storage_seals_validate_insert
BEFORE INSERT ON local_federation_storage_seals
WHEN NEW.sequence != 1 OR NEW.ceiling_bytes != (
    SELECT committed_bytes + reserved_bytes FROM local_federation_storage_usage
    WHERE allocation_id = NEW.allocation_id
)
BEGIN
    SELECT RAISE(ABORT, 'storage seal must cover all outstanding charges');
END;

CREATE TRIGGER local_federation_storage_seals_validate_update
BEFORE UPDATE ON local_federation_storage_seals
WHEN NEW.allocation_id != OLD.allocation_id
    OR NEW.ceiling_bytes >= OLD.ceiling_bytes
    OR NEW.sequence != OLD.sequence + 1
    OR NEW.ceiling_bytes != (
        SELECT committed_bytes + reserved_bytes FROM local_federation_storage_usage
        WHERE allocation_id = OLD.allocation_id
    )
BEGIN
    SELECT RAISE(ABORT, 'storage seal may only narrow to verified accounting');
END;

CREATE TRIGGER local_federation_storage_seals_reject_delete
BEFORE DELETE ON local_federation_storage_seals
BEGIN
    SELECT RAISE(ABORT, 'storage admission seal is permanent');
END;

CREATE TRIGGER local_federation_storage_usage_enforce_seal
BEFORE UPDATE OF committed_bytes, reserved_bytes ON local_federation_storage_usage
WHEN EXISTS (
    SELECT 1 FROM local_federation_storage_seals WHERE allocation_id = OLD.allocation_id
) AND NEW.committed_bytes + NEW.reserved_bytes > OLD.committed_bytes + OLD.reserved_bytes
BEGIN
    SELECT RAISE(ABORT, 'sealed storage allocation cannot increase its charge');
END;
