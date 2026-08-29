-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE principal_lifecycle_events (
    principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    event_kind INTEGER NOT NULL CHECK (event_kind BETWEEN 1 AND 4),
    prior_state INTEGER CHECK (prior_state IS NULL OR prior_state BETWEEN 1 AND 2),
    resulting_state INTEGER NOT NULL CHECK (resulting_state BETWEEN 1 AND 3),
    reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 512),
    changed_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    changed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (principal_id, revision),
    CHECK (
        (event_kind = 1 AND prior_state IS NULL AND reason IS NULL)
        OR (event_kind = 2 AND prior_state = 1 AND resulting_state = 2
            AND reason IS NOT NULL)
        OR (event_kind = 3 AND prior_state = 2 AND resulting_state = 1
            AND reason IS NOT NULL)
        OR (event_kind = 4 AND prior_state IN (1, 2) AND resulting_state = 3
            AND reason IS NOT NULL)
    ),
    CHECK (reason IS NULL OR length(CAST(reason AS BLOB)) BETWEEN 1 AND 512)
) STRICT;

INSERT INTO principal_lifecycle_events(
    principal_id, event_kind, prior_state, resulting_state, reason,
    changed_by, changed_at, revision
)
SELECT principal_id, 1, NULL, state, NULL, principal_id, created_at, revision
FROM principals;

CREATE INDEX principal_lifecycle_events_by_revision
ON principal_lifecycle_events(revision, principal_id);

CREATE UNIQUE INDEX one_principal_lifecycle_baseline
ON principal_lifecycle_events(principal_id) WHERE event_kind = 1;

CREATE TRIGGER principal_lifecycle_events_reject_update
BEFORE UPDATE ON principal_lifecycle_events
BEGIN
    SELECT RAISE(ABORT, 'principal lifecycle events are immutable');
END;

CREATE TRIGGER principal_lifecycle_events_reject_delete
BEFORE DELETE ON principal_lifecycle_events
BEGIN
    SELECT RAISE(ABORT, 'principal lifecycle events are immutable');
END;

CREATE TRIGGER principals_validate_lifecycle_insert
BEFORE INSERT ON principals
WHEN NOT (
    (NEW.state IN (1, 2) AND NEW.retired_at IS NULL)
    OR (NEW.state = 3 AND NEW.retired_at IS NOT NULL
        AND NEW.retired_at >= NEW.created_at)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid principal lifecycle state');
END;

CREATE TRIGGER principals_validate_lifecycle_update
BEFORE UPDATE OF state, retired_at ON principals
WHEN NOT (
    (NEW.state IN (1, 2) AND NEW.retired_at IS NULL)
    OR (NEW.state = 3 AND NEW.retired_at IS NOT NULL
        AND NEW.retired_at >= NEW.created_at)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid principal lifecycle state');
END;
