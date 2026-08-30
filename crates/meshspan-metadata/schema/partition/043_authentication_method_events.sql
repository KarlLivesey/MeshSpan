-- SPDX-License-Identifier: GPL-2.0-only

-- event_kind: 1 created, 2 revoked.
CREATE TABLE authentication_method_events (
    method_id BLOB NOT NULL
        REFERENCES authentication_methods(method_id) ON DELETE RESTRICT,
    event_sequence INTEGER NOT NULL CHECK (event_sequence BETWEEN 1 AND 2),
    event_kind INTEGER NOT NULL CHECK (event_kind BETWEEN 1 AND 2),
    prior_state INTEGER CHECK (prior_state IS NULL OR prior_state BETWEEN 1 AND 3),
    resulting_state INTEGER NOT NULL CHECK (resulting_state BETWEEN 1 AND 3),
    reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 1024),
    changed_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    changed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (method_id, event_sequence),
    CHECK (
        (event_sequence = 1 AND event_kind = 1 AND prior_state IS NULL
            AND resulting_state = 1 AND reason IS NULL)
        OR (event_sequence = 2 AND event_kind = 2 AND prior_state IN (1, 2)
            AND resulting_state = 3 AND reason IS NOT NULL)
    )
) STRICT;

INSERT INTO authentication_method_events(
    method_id, event_sequence, event_kind, prior_state, resulting_state,
    reason, changed_by, changed_at, revision
)
SELECT method_id, 1, 1, NULL, 1, NULL, user_principal_id, created_at, revision
FROM authentication_methods;

CREATE TRIGGER authentication_method_events_reject_update
BEFORE UPDATE ON authentication_method_events
BEGIN
    SELECT RAISE(ABORT, 'authentication method lifecycle events are immutable');
END;

CREATE TRIGGER authentication_method_events_reject_delete
BEFORE DELETE ON authentication_method_events
BEGIN
    SELECT RAISE(ABORT, 'authentication method lifecycle events are immutable');
END;
