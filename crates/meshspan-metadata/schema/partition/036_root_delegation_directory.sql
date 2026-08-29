-- SPDX-License-Identifier: GPL-2.0-only

-- The permanent root group owns this directory even after the represented
-- operation-family/key-range scope moves to another consensus group.
CREATE TABLE root_delegated_scopes (
    scope_id BLOB PRIMARY KEY
        REFERENCES partition_scopes(scope_id) ON DELETE RESTRICT,
    root_partition_id BLOB NOT NULL
        REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT,
    directory_role INTEGER NOT NULL CHECK (directory_role BETWEEN 1 AND 2),
    operation_family INTEGER NOT NULL CHECK (operation_family BETWEEN 2 AND 8),
    initial_routing_epoch INTEGER NOT NULL CHECK (initial_routing_epoch > 0),
    key_range_kind INTEGER NOT NULL CHECK (key_range_kind BETWEEN 1 AND 2),
    start_inclusive BLOB CHECK (start_inclusive IS NULL OR length(start_inclusive) = 16),
    end_exclusive BLOB CHECK (end_exclusive IS NULL OR length(end_exclusive) = 16),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (key_range_kind = 1 AND start_inclusive IS NULL AND end_exclusive IS NULL)
        OR (key_range_kind = 2 AND start_inclusive IS NOT NULL AND end_exclusive IS NOT NULL
            AND start_inclusive < end_exclusive)
    )
) STRICT;

CREATE INDEX root_delegated_scopes_by_family_range
ON root_delegated_scopes(
    directory_role, operation_family, key_range_kind, start_inclusive, end_exclusive, scope_id
);

CREATE TRIGGER root_delegated_scopes_reject_overlap
BEFORE INSERT ON root_delegated_scopes
WHEN EXISTS (
    SELECT 1 FROM root_delegated_scopes existing
    WHERE existing.operation_family = NEW.operation_family
      AND (
          existing.key_range_kind = 1
          OR NEW.key_range_kind = 1
          OR (NEW.start_inclusive < existing.end_exclusive
              AND existing.start_inclusive < NEW.end_exclusive)
      )
)
BEGIN
    SELECT RAISE(ABORT, 'delegated metadata scopes overlap');
END;

CREATE TRIGGER root_delegated_scopes_reject_update
BEFORE UPDATE ON root_delegated_scopes
BEGIN
    SELECT RAISE(ABORT, 'root delegation scope identity is immutable');
END;

CREATE TRIGGER root_delegated_scopes_reject_delete
BEFORE DELETE ON root_delegated_scopes
BEGIN
    SELECT RAISE(ABORT, 'root delegation scope identity is immutable');
END;

-- One immutable admission accompanies each attempted route epoch. Aborted
-- epochs remain evidence; another attempt must use a newer routing epoch.
CREATE TABLE root_delegation_admissions (
    scope_id BLOB NOT NULL
        REFERENCES root_delegated_scopes(scope_id) ON DELETE RESTRICT,
    routing_epoch INTEGER NOT NULL CHECK (routing_epoch > 0),
    source_partition_id BLOB NOT NULL
        REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT,
    destination_partition_id BLOB NOT NULL
        REFERENCES metadata_partitions(partition_id) ON DELETE RESTRICT,
    eligible_member_count INTEGER NOT NULL CHECK (eligible_member_count > 0),
    planned_voter_count INTEGER NOT NULL CHECK (planned_voter_count BETWEEN 1 AND 9),
    quorum_plan_digest BLOB NOT NULL CHECK (length(quorum_plan_digest) = 32),
    load_evidence_digest BLOB NOT NULL CHECK (length(load_evidence_digest) = 32),
    measured_at INTEGER NOT NULL,
    admitted_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (scope_id, routing_epoch),
    CHECK (source_partition_id <> destination_partition_id),
    CHECK (eligible_member_count >= planned_voter_count),
    CHECK (quorum_plan_digest <> zeroblob(32)),
    CHECK (load_evidence_digest <> zeroblob(32))
) STRICT;

CREATE INDEX root_delegation_admissions_by_destination
ON root_delegation_admissions(destination_partition_id, routing_epoch, scope_id);

CREATE TRIGGER root_delegation_admissions_reject_update
BEFORE UPDATE ON root_delegation_admissions
BEGIN
    SELECT RAISE(ABORT, 'root delegation admission is immutable');
END;

CREATE TRIGGER root_delegation_admissions_reject_delete
BEFORE DELETE ON root_delegation_admissions
BEGIN
    SELECT RAISE(ABORT, 'root delegation admission is immutable');
END;

CREATE TRIGGER partition_routes_reject_update
BEFORE UPDATE ON partition_routes
BEGIN
    SELECT RAISE(ABORT, 'partition route history is immutable');
END;

CREATE TRIGGER partition_routes_reject_delete
BEFORE DELETE ON partition_routes
BEGIN
    SELECT RAISE(ABORT, 'partition route history is immutable');
END;
