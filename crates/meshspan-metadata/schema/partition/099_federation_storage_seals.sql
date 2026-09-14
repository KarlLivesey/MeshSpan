-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE federation_storage_seals (
    allocation_id BLOB PRIMARY KEY REFERENCES federation_storage_allocations(allocation_id),
    provider_node_id BLOB NOT NULL,
    node_incarnation INTEGER NOT NULL CHECK (node_incarnation > 0),
    key_generation INTEGER NOT NULL CHECK (key_generation > 0),
    ceiling_bytes INTEGER NOT NULL CHECK (ceiling_bytes >= 0),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    sealed_at INTEGER NOT NULL CHECK (sealed_at > 0),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    revision INTEGER NOT NULL CHECK (revision > 0),
    FOREIGN KEY (provider_node_id, key_generation)
        REFERENCES cleanup_attestation_keys(node_id, generation)
) STRICT;

CREATE TRIGGER federation_storage_seals_validate_insert
BEFORE INSERT ON federation_storage_seals
WHEN NOT EXISTS (SELECT 1 FROM federation_storage_allocations
    WHERE allocation_id=NEW.allocation_id AND provider_node_id=NEW.provider_node_id
    AND NEW.ceiling_bytes <= maximum_bytes)
BEGIN
    SELECT RAISE(ABORT, 'storage seal must match its immutable allocation');
END;

CREATE TRIGGER federation_storage_seals_validate_update
BEFORE UPDATE ON federation_storage_seals
WHEN NEW.allocation_id != OLD.allocation_id OR NEW.provider_node_id != OLD.provider_node_id
    OR NEW.ceiling_bytes >= OLD.ceiling_bytes OR NEW.sequence <= OLD.sequence
    OR NEW.revision <= OLD.revision
BEGIN
    SELECT RAISE(ABORT, 'storage seal must monotonically narrow');
END;

CREATE TRIGGER federation_storage_seals_reject_delete
BEFORE DELETE ON federation_storage_seals
BEGIN
    SELECT RAISE(ABORT, 'storage seal evidence must be retained');
END;
