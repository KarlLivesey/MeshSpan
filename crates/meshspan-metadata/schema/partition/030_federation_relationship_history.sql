-- SPDX-License-Identifier: GPL-2.0-only

-- Current relationship rows are replaceable projections. This immutable ledger
-- preserves every authority fence and explains why it changed.
CREATE TABLE federation_relationship_events (
    relationship_id BLOB NOT NULL
        REFERENCES federation_relationships(relationship_id) ON DELETE RESTRICT,
    authority_epoch INTEGER NOT NULL CHECK (authority_epoch > 0),
    event_sequence INTEGER NOT NULL CHECK (event_sequence > 0),
    event_kind INTEGER NOT NULL CHECK (event_kind BETWEEN 1 AND 6),
    prior_state INTEGER CHECK (prior_state IS NULL OR prior_state BETWEEN 1 AND 5),
    resulting_state INTEGER NOT NULL CHECK (resulting_state BETWEEN 1 AND 5),
    reason TEXT CHECK (
        reason IS NULL OR (
            length(reason) BETWEEN 1 AND 512
            AND length(CAST(reason AS BLOB)) BETWEEN 1 AND 512
        )
    ),
    changed_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    changed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (relationship_id, authority_epoch, event_sequence),
    CHECK (
        (event_kind = 1 AND prior_state IS NULL AND resulting_state = 1 AND reason IS NULL)
        OR (event_kind = 2 AND prior_state = 1 AND resulting_state = 2 AND reason IS NULL)
        OR (event_kind = 3 AND prior_state IN (2, 3) AND resulting_state = 3
            AND reason IS NOT NULL)
        OR (event_kind = 4 AND prior_state = 3 AND resulting_state = 2
            AND reason IS NOT NULL)
        OR (event_kind = 5 AND prior_state IN (1, 2, 3) AND resulting_state = 4
            AND reason IS NOT NULL)
        OR (event_kind = 6 AND prior_state = 4 AND resulting_state = 5
            AND reason IS NOT NULL)
    )
) STRICT;

CREATE INDEX federation_relationship_events_by_revision
ON federation_relationship_events(revision, relationship_id);

CREATE TRIGGER federation_relationship_events_reject_update
BEFORE UPDATE ON federation_relationship_events
BEGIN
    SELECT RAISE(ABORT, 'federation relationship events are immutable');
END;

CREATE TRIGGER federation_relationship_events_reject_delete
BEFORE DELETE ON federation_relationship_events
BEGIN
    SELECT RAISE(ABORT, 'federation relationship events are immutable');
END;
