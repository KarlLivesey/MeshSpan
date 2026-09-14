-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE content_reuse_reservations (
    operation_id BLOB PRIMARY KEY CHECK (length(operation_id) = 16),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    version_id BLOB NOT NULL CHECK (length(version_id) = 16),
    manifest_id BLOB NOT NULL REFERENCES content_manifests(manifest_id),
    manifest_root_digest BLOB NOT NULL CHECK (length(manifest_root_digest) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3))
) STRICT;

CREATE INDEX content_reuse_by_live_manifest
ON content_reuse_reservations(manifest_root_digest, operation_id) WHERE state = 1;

CREATE INDEX content_reuse_by_live_volume
ON content_reuse_reservations(volume_id, operation_id) WHERE state = 1;

CREATE INDEX file_versions_by_publication_operation
ON file_versions(publication_operation_id);

CREATE INDEX content_manifests_by_plaintext
ON content_manifests(content_digest, logical_length, manifest_id);

CREATE INDEX file_versions_by_volume_manifest
ON file_versions(volume_id, manifest_id);
