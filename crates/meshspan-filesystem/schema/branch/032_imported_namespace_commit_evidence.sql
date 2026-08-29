-- SPDX-License-Identifier: GPL-2.0-only

-- Imported branch commits are immutable causal evidence, not locally executed operations.  Keep
-- their canonical request and intent binding separate from local connector operation receipts.
CREATE TABLE imported_namespace_commit_evidence (
    namespace_commit_id BLOB PRIMARY KEY REFERENCES namespace_commits(namespace_commit_id)
        CHECK (length(namespace_commit_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    intent_digest BLOB NOT NULL CHECK (length(intent_digest) = 32),
    evidence_digest BLOB NOT NULL CHECK (length(evidence_digest) = 32)
) STRICT;
