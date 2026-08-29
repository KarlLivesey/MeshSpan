-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE group_memberships
ADD COLUMN state INTEGER NOT NULL DEFAULT 1 CHECK (state IN (1, 2));

ALTER TABLE group_memberships
ADD COLUMN removed_at INTEGER;

ALTER TABLE group_memberships
ADD COLUMN removed_by BLOB REFERENCES principals(principal_id) ON DELETE RESTRICT;

ALTER TABLE group_memberships
ADD COLUMN removal_reason TEXT CHECK (removal_reason IS NULL OR length(removal_reason) BETWEEN 1 AND 512);

ALTER TABLE permission_grants
ADD COLUMN revoked_at INTEGER;

ALTER TABLE permission_grants
ADD COLUMN revoked_by BLOB REFERENCES principals(principal_id) ON DELETE RESTRICT;

ALTER TABLE permission_grants
ADD COLUMN revocation_reason TEXT CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 512);

ALTER TABLE access_activations
ADD COLUMN revoked_by BLOB REFERENCES principals(principal_id) ON DELETE RESTRICT;

ALTER TABLE access_activations
ADD COLUMN revocation_reason TEXT CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 512);

CREATE TABLE group_membership_events (
    containing_group_id BLOB NOT NULL REFERENCES groups(principal_id) ON DELETE RESTRICT,
    member_principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    event_kind INTEGER NOT NULL CHECK (event_kind IN (1, 2)),
    reason TEXT CHECK (reason IS NULL OR length(reason) BETWEEN 1 AND 512),
    actor_principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    occurred_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (containing_group_id, member_principal_id, revision),
    CHECK ((event_kind = 1 AND reason IS NULL)
        OR (event_kind = 2 AND reason IS NOT NULL
            AND length(CAST(reason AS BLOB)) BETWEEN 1 AND 512))
) STRICT;

INSERT INTO group_membership_events(
    containing_group_id, member_principal_id, event_kind, reason,
    actor_principal_id, occurred_at, revision
)
SELECT containing_group_id, member_principal_id, 1, NULL,
       created_by, created_at, revision
FROM group_memberships;

CREATE INDEX group_memberships_active_by_member
ON group_memberships(member_principal_id, containing_group_id) WHERE state = 1;

CREATE INDEX group_membership_events_by_revision
ON group_membership_events(revision, containing_group_id, member_principal_id);

CREATE TRIGGER group_memberships_validate_removal_insert
BEFORE INSERT ON group_memberships
WHEN NOT (
    (NEW.state = 1 AND NEW.removed_at IS NULL
        AND NEW.removed_by IS NULL AND NEW.removal_reason IS NULL)
    OR (NEW.state = 2 AND NEW.removed_at IS NOT NULL
        AND NEW.removed_at >= NEW.created_at AND NEW.removed_by IS NOT NULL
        AND NEW.removal_reason IS NOT NULL
        AND length(CAST(NEW.removal_reason AS BLOB)) BETWEEN 1 AND 512)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid group membership removal evidence');
END;

CREATE TRIGGER group_memberships_validate_removal_update
BEFORE UPDATE OF state, removed_at, removed_by, removal_reason ON group_memberships
WHEN NOT (
    (NEW.state = 1 AND NEW.removed_at IS NULL
        AND NEW.removed_by IS NULL AND NEW.removal_reason IS NULL)
    OR (NEW.state = 2 AND NEW.removed_at IS NOT NULL
        AND NEW.removed_at >= NEW.created_at AND NEW.removed_by IS NOT NULL
        AND NEW.removal_reason IS NOT NULL
        AND length(CAST(NEW.removal_reason AS BLOB)) BETWEEN 1 AND 512)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid group membership removal evidence');
END;

CREATE TRIGGER permission_grants_validate_revocation_insert
BEFORE INSERT ON permission_grants
WHEN NOT (
    (NEW.state <> 2 AND NEW.revoked_at IS NULL
        AND NEW.revoked_by IS NULL AND NEW.revocation_reason IS NULL)
    OR (NEW.state = 2 AND NEW.revoked_at IS NOT NULL
        AND NEW.revoked_at >= NEW.created_at AND NEW.revoked_by IS NOT NULL
        AND NEW.revocation_reason IS NOT NULL
        AND length(CAST(NEW.revocation_reason AS BLOB)) BETWEEN 1 AND 512)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid permission grant revocation evidence');
END;

CREATE TRIGGER permission_grants_validate_revocation_update
BEFORE UPDATE OF state, revoked_at, revoked_by, revocation_reason ON permission_grants
WHEN NOT (
    (NEW.state <> 2 AND NEW.revoked_at IS NULL
        AND NEW.revoked_by IS NULL AND NEW.revocation_reason IS NULL)
    OR (NEW.state = 2 AND NEW.revoked_at IS NOT NULL
        AND NEW.revoked_at >= NEW.created_at AND NEW.revoked_by IS NOT NULL
        AND NEW.revocation_reason IS NOT NULL
        AND length(CAST(NEW.revocation_reason AS BLOB)) BETWEEN 1 AND 512)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid permission grant revocation evidence');
END;

CREATE TRIGGER access_activations_validate_revocation_insert
BEFORE INSERT ON access_activations
WHEN NOT (
    (NEW.revoked_at IS NULL AND NEW.revoked_by IS NULL
        AND NEW.revocation_reason IS NULL)
    OR (NEW.revoked_at IS NOT NULL AND NEW.revoked_at >= NEW.activated_at
        AND NEW.revoked_by IS NOT NULL AND NEW.revocation_reason IS NOT NULL
        AND length(CAST(NEW.revocation_reason AS BLOB)) BETWEEN 1 AND 512)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid access activation revocation evidence');
END;

CREATE TRIGGER access_activations_validate_revocation_update
BEFORE UPDATE OF revoked_at, revoked_by, revocation_reason ON access_activations
WHEN NOT (
    (NEW.revoked_at IS NULL AND NEW.revoked_by IS NULL
        AND NEW.revocation_reason IS NULL)
    OR (NEW.revoked_at IS NOT NULL AND NEW.revoked_at >= NEW.activated_at
        AND NEW.revoked_by IS NOT NULL AND NEW.revocation_reason IS NOT NULL
        AND length(CAST(NEW.revocation_reason AS BLOB)) BETWEEN 1 AND 512)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid access activation revocation evidence');
END;
