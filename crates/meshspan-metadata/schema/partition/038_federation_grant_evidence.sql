-- SPDX-License-Identifier: GPL-2.0-only

-- Grant authority is retained permanently. A termination records whether the
-- grant ended directly or through an exact successor; migrated direct
-- revocations explicitly preserve that their discarded reason is unknown.
CREATE TABLE federation_grant_terminations (
    grant_id BLOB PRIMARY KEY
        REFERENCES federation_grants(grant_id) ON DELETE RESTRICT,
    termination_kind INTEGER NOT NULL CHECK (termination_kind BETWEEN 1 AND 4),
    reason TEXT,
    terminated_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (termination_kind BETWEEN 1 AND 3 AND reason IS NOT NULL
            AND length(reason) BETWEEN 1 AND 512
            AND length(CAST(reason AS BLOB)) BETWEEN 1 AND 512)
        OR (termination_kind = 4 AND reason IS NULL)
    )
) STRICT;

-- Exact reasons already retained by replacement history remain exact.
INSERT INTO federation_grant_terminations(
    grant_id, termination_kind, reason, terminated_at, revision
)
SELECT predecessor_grant_id,
       CASE succession_kind WHEN 1 THEN 2 ELSE 3 END,
       reason, succeeded_at, revision
FROM federation_grant_successions;

-- Older direct revocations discarded their reason. Preserve that fact rather
-- than fabricating evidence during migration.
INSERT INTO federation_grant_terminations(
    grant_id, termination_kind, reason, terminated_at, revision
)
SELECT grant_id, 4, NULL, revoked_at, revision
FROM federation_grants AS grant
WHERE state = 3
  AND NOT EXISTS (
      SELECT 1 FROM federation_grant_successions AS succession
      WHERE succession.predecessor_grant_id = grant.grant_id
  );

CREATE TRIGGER federation_grant_terminations_reject_new_legacy_unknown
BEFORE INSERT ON federation_grant_terminations
WHEN NEW.termination_kind = 4
BEGIN
    SELECT RAISE(ABORT, 'legacy grant termination evidence is migration-only');
END;

CREATE TRIGGER federation_grants_reject_delete
BEFORE DELETE ON federation_grants
BEGIN
    SELECT RAISE(ABORT, 'federation grant authority is retained');
END;

CREATE TRIGGER federation_grant_terminations_reject_update
BEFORE UPDATE ON federation_grant_terminations
BEGIN
    SELECT RAISE(ABORT, 'federation grant termination evidence is immutable');
END;

CREATE TRIGGER federation_grant_terminations_reject_delete
BEFORE DELETE ON federation_grant_terminations
BEGIN
    SELECT RAISE(ABORT, 'federation grant termination evidence is retained');
END;
