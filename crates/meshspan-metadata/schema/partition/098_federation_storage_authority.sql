-- SPDX-License-Identifier: GPL-2.0-only

-- Allocation identity and original capacity remain immutable. This projection carries
-- only renewable authority; replacing a grant never creates another allocation budget.
CREATE TABLE federation_storage_authority (
    allocation_id BLOB PRIMARY KEY REFERENCES federation_storage_allocations(allocation_id),
    grant_id BLOB NOT NULL REFERENCES federation_grants(grant_id),
    valid_from INTEGER NOT NULL CHECK (valid_from > 0),
    valid_until INTEGER NOT NULL CHECK (valid_until > valid_from),
    write_limit_bytes INTEGER NOT NULL CHECK (write_limit_bytes >= 0),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE INDEX federation_storage_authority_by_grant
ON federation_storage_authority(grant_id, allocation_id);

CREATE INDEX federation_storage_authority_discovery
ON federation_storage_authority(grant_id, valid_from, valid_until, allocation_id);

-- Follow only explicit immutable succession. UNION bounds even a corrupt cycle;
-- a cycle has no terminal member and is rejected by the completeness check below.
WITH RECURSIVE lineage(allocation_id, grant_id) AS (
    SELECT allocation_id, grant_id FROM federation_storage_allocations
    UNION
    SELECT l.allocation_id, s.successor_grant_id FROM lineage l
    JOIN federation_grant_successions s ON s.predecessor_grant_id = l.grant_id
), terminal AS (
    SELECT l.allocation_id, l.grant_id FROM lineage l
    WHERE NOT EXISTS (SELECT 1 FROM federation_grant_successions s
                      WHERE s.predecessor_grant_id = l.grant_id)
), budgets AS (
    SELECT t.allocation_id, t.grant_id, a.maximum_bytes,
           COALESCE(SUM(a.maximum_bytes) OVER (PARTITION BY t.grant_id
               ORDER BY t.allocation_id ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING), 0) AS prior_bytes,
           (SELECT MIN(r.maximum_storage_bytes) FROM federation_grant_restrictions r
            WHERE r.grant_id = t.grant_id AND r.policy_kind = 2) AS quota
    FROM terminal t JOIN federation_storage_allocations a USING(allocation_id)
)
INSERT INTO federation_storage_authority
SELECT b.allocation_id, b.grant_id, a.valid_from,
       CASE WHEN a.valid_until = origin.valid_until
            THEN COALESCE(g.valid_until, 9223372036854775807)
            ELSE a.valid_until END,
       MAX(0, MIN(b.maximum_bytes, b.quota - b.prior_bytes)), MAX(a.revision, g.revision)
FROM budgets b JOIN federation_storage_allocations a USING(allocation_id)
JOIN federation_grants g ON g.grant_id = b.grant_id
JOIN federation_grants origin ON origin.grant_id = a.grant_id;

CREATE TEMP TABLE storage_authority_migration_check (valid INTEGER CHECK (valid = 1));
INSERT INTO storage_authority_migration_check
SELECT (SELECT count(*) FROM federation_storage_authority) =
       (SELECT count(*) FROM federation_storage_allocations);
DROP TABLE storage_authority_migration_check;

CREATE TRIGGER federation_storage_authority_reject_unrelated_successor
BEFORE UPDATE ON federation_storage_authority
WHEN NEW.allocation_id <> OLD.allocation_id OR NEW.valid_from <> OLD.valid_from
  OR NOT EXISTS (SELECT 1 FROM federation_grant_successions s
                 WHERE s.predecessor_grant_id = OLD.grant_id
                   AND s.successor_grant_id = NEW.grant_id AND s.revision = NEW.revision)
  OR NEW.write_limit_bytes > (SELECT maximum_bytes FROM federation_storage_allocations
                              WHERE allocation_id = OLD.allocation_id)
BEGIN
    SELECT RAISE(ABORT, 'storage authority requires explicit grant succession');
END;

CREATE TRIGGER federation_storage_authority_reject_delete
BEFORE DELETE ON federation_storage_authority
BEGIN
    SELECT RAISE(ABORT, 'storage allocation accounting authority must be retained');
END;
