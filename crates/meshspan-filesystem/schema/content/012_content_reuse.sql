-- SPDX-License-Identifier: GPL-2.0-only

-- Upload intent remains distinct from the original encrypted-layout operation.
CREATE TABLE content_reuse (
    operation_id BLOB PRIMARY KEY REFERENCES content_publications(operation_id),
    source_operation_id BLOB NOT NULL REFERENCES content_publications(operation_id),
    manifest_root_digest BLOB NOT NULL CHECK (length(manifest_root_digest) = 32),
    acknowledgement_class INTEGER NOT NULL CHECK (acknowledgement_class IN (1, 2)),
    acknowledgement_scope INTEGER NOT NULL CHECK (acknowledgement_scope BETWEEN 1 AND 3),
    verified_receipts INTEGER NOT NULL CHECK (verified_receipts > 0),
    policy_digest BLOB NOT NULL CHECK (length(policy_digest) = 32),
    achieved_digest BLOB NOT NULL CHECK (length(achieved_digest) = 32),
    debt_digest BLOB NOT NULL CHECK (length(debt_digest) = 32),
    CHECK (operation_id != source_operation_id)
) STRICT;
