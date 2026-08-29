-- SPDX-License-Identifier: GPL-2.0-only

-- The accepting swarm's signature binds the exact grant-use evidence and
-- immutable payload digest. A digest alone is not treated as provenance.
CREATE TABLE federation_quarantine_acknowledgements (
    quarantine_id BLOB PRIMARY KEY
        REFERENCES federation_quarantine(quarantine_id) ON DELETE RESTRICT,
    signer_mesh_id BLOB NOT NULL CHECK (length(signer_mesh_id) = 16),
    signer_generation INTEGER NOT NULL CHECK (signer_generation > 0),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    required_rights INTEGER NOT NULL CHECK (required_rights BETWEEN 0 AND 8191),
    storage_bytes INTEGER NOT NULL CHECK (storage_bytes >= 0),
    resource_kind INTEGER NOT NULL CHECK (resource_kind BETWEEN 1 AND 4),
    authority_mesh_id BLOB NOT NULL CHECK (length(authority_mesh_id) = 16),
    volume_id BLOB CHECK (volume_id IS NULL OR length(volume_id) = 16),
    object_id BLOB CHECK (object_id IS NULL OR length(object_id) = 16),
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (resource_kind = 1 AND volume_id IS NOT NULL AND object_id IS NULL)
        OR (resource_kind IN (2, 3) AND volume_id IS NOT NULL AND object_id IS NOT NULL)
        OR (resource_kind = 4 AND volume_id IS NULL AND object_id IS NULL)
    ),
    CHECK (
        (resource_kind = 4 AND required_rights = 0 AND storage_bytes > 0)
        OR (resource_kind BETWEEN 1 AND 3 AND required_rights > 0 AND storage_bytes = 0)
    )
) STRICT;

CREATE TRIGGER federation_quarantine_acknowledgements_reject_update
BEFORE UPDATE ON federation_quarantine_acknowledgements
BEGIN
    SELECT RAISE(ABORT, 'federation quarantine acknowledgement is immutable');
END;

CREATE TRIGGER federation_quarantine_acknowledgements_reject_delete
BEFORE DELETE ON federation_quarantine_acknowledgements
BEGIN
    SELECT RAISE(ABORT, 'federation quarantine acknowledgement is immutable');
END;

CREATE TABLE federation_quarantine_events (
    quarantine_id BLOB NOT NULL
        REFERENCES federation_quarantine(quarantine_id) ON DELETE RESTRICT,
    event_sequence INTEGER NOT NULL CHECK (event_sequence BETWEEN 1 AND 3),
    event_kind INTEGER NOT NULL CHECK (event_kind BETWEEN 1 AND 5),
    prior_state INTEGER CHECK (prior_state IS NULL OR prior_state BETWEEN 1 AND 4),
    resulting_state INTEGER NOT NULL CHECK (resulting_state BETWEEN 1 AND 4),
    reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 1024),
    changed_by BLOB NOT NULL CHECK (length(changed_by) = 16),
    changed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (quarantine_id, event_sequence),
    CHECK (
        (event_kind IN (1, 2) AND reason IS NULL)
        OR (event_kind BETWEEN 3 AND 5 AND reason IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER federation_quarantine_events_reject_update
BEFORE UPDATE ON federation_quarantine_events
BEGIN
    SELECT RAISE(ABORT, 'federation quarantine events are immutable');
END;

CREATE TRIGGER federation_quarantine_events_reject_delete
BEFORE DELETE ON federation_quarantine_events
BEGIN
    SELECT RAISE(ABORT, 'federation quarantine events are immutable');
END;
