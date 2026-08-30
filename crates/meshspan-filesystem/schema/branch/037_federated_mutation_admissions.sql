-- SPDX-License-Identifier: GPL-2.0-only

-- Owner-side admission is distinct from the remote swarm's signed acknowledgement.  Imported
-- federated history is never eligible for namespace replay until one immutable decision exists.
CREATE TABLE federated_namespace_mutation_admissions (
    namespace_commit_id BLOB PRIMARY KEY
        REFERENCES federated_namespace_mutation_acknowledgements(namespace_commit_id)
        CHECK (length(namespace_commit_id) = 16),
    admission_kind INTEGER NOT NULL CHECK (admission_kind IN (1, 2)),
    quarantine_reason INTEGER CHECK (
        (admission_kind = 1 AND quarantine_reason IS NULL)
        OR (admission_kind = 2 AND quarantine_reason BETWEEN 1 AND 6)
    ),
    classified_at INTEGER NOT NULL,
    decision_digest BLOB NOT NULL CHECK (length(decision_digest) = 32)
) STRICT;

CREATE TRIGGER federated_namespace_mutation_admissions_reject_update
BEFORE UPDATE ON federated_namespace_mutation_admissions
BEGIN
    SELECT RAISE(ABORT, 'federated mutation admissions are immutable');
END;

CREATE TRIGGER federated_namespace_mutation_admissions_reject_delete
BEFORE DELETE ON federated_namespace_mutation_admissions
BEGIN
    SELECT RAISE(ABORT, 'federated mutation admissions are immutable');
END;

-- A completed receive receipt is bound to the exact ordered decision set.  Local-history receive
-- sessions retain NULL so the existing version-1 receipt remains byte-for-byte distinguishable.
ALTER TABLE namespace_history_imports ADD COLUMN admission_digest BLOB
    CHECK (admission_digest IS NULL OR length(admission_digest) = 32);
