-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE namespace_commit_intent_ancestors (
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commit_intents(namespace_commit_id),
    ancestor_ordinal INTEGER NOT NULL CHECK (ancestor_ordinal BETWEEN 0 AND 1022),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    prior_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(prior_revision_id) = 16),
    resulting_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(resulting_revision_id) = 16),
    PRIMARY KEY (namespace_commit_id, ancestor_ordinal),
    UNIQUE (namespace_commit_id, object_id),
    CHECK (prior_revision_id != resulting_revision_id)
) STRICT;
