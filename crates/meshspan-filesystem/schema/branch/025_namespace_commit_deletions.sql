-- SPDX-License-Identifier: GPL-2.0-only

-- Existing intent columns retain the exact removed object, revision, version, path and generation.
-- This marker changes that otherwise-compatible leaf record from an upsert into a removal without
-- rewriting the stable v5 intent table or any pre-existing rows.
CREATE TABLE namespace_commit_deletions (
    namespace_commit_id BLOB PRIMARY KEY REFERENCES namespace_commit_intents(namespace_commit_id)
        CHECK (length(namespace_commit_id) = 16)
) STRICT;
