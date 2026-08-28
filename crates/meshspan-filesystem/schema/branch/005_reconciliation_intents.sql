-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE namespace_commit_intents (
    namespace_commit_id BLOB PRIMARY KEY REFERENCES namespace_commits(namespace_commit_id)
        CHECK (length(namespace_commit_id) = 16),
    intent_kind INTEGER NOT NULL CHECK (intent_kind IN (1, 2)),
    object_id BLOB NOT NULL CHECK (length(object_id) = 16),
    object_revision_id BLOB NOT NULL REFERENCES object_revisions(object_revision_id)
        CHECK (length(object_revision_id) = 16),
    prior_object_revision_id BLOB NULL REFERENCES object_revisions(object_revision_id)
        CHECK (prior_object_revision_id IS NULL OR length(prior_object_revision_id) = 16),
    file_version_id BLOB NULL REFERENCES file_versions(version_id)
        CHECK (file_version_id IS NULL OR length(file_version_id) = 16),
    entry_generation INTEGER NOT NULL CHECK (entry_generation > 0),
    path_depth INTEGER NOT NULL CHECK (path_depth BETWEEN 1 AND 1024),
    intent_digest BLOB NOT NULL CHECK (length(intent_digest) = 32),
    CHECK (
        (intent_kind = 1 AND file_version_id IS NOT NULL)
        OR
        (intent_kind = 2 AND file_version_id IS NULL AND prior_object_revision_id IS NULL)
    )
) STRICT;

CREATE TABLE namespace_commit_path_components (
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commit_intents(namespace_commit_id),
    component_ordinal INTEGER NOT NULL CHECK (component_ordinal BETWEEN 0 AND 1023),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 16384),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 16384),
    PRIMARY KEY (namespace_commit_id, component_ordinal)
) STRICT;
