-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE namespace_commit_renames (
    namespace_commit_id BLOB PRIMARY KEY REFERENCES namespace_commit_intents(namespace_commit_id)
        CHECK (length(namespace_commit_id) = 16),
    source_path_depth INTEGER NOT NULL CHECK (source_path_depth BETWEEN 1 AND 1024),
    source_entry_generation INTEGER NOT NULL CHECK (source_entry_generation > 0),
    intermediate_root_object_revision_id BLOB NOT NULL
        REFERENCES object_revisions(object_revision_id)
        CHECK (length(intermediate_root_object_revision_id) = 16)
) STRICT;

CREATE TABLE namespace_commit_rename_source_components (
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commit_renames(namespace_commit_id),
    component_ordinal INTEGER NOT NULL CHECK (component_ordinal BETWEEN 0 AND 1023),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 16384),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 16384),
    PRIMARY KEY (namespace_commit_id, component_ordinal)
) STRICT;

CREATE TABLE namespace_commit_rename_source_ancestors (
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commit_renames(namespace_commit_id),
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
