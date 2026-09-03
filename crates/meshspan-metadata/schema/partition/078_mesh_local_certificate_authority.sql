-- SPDX-License-Identifier: GPL-2.0-only

-- One mesh has one initial local HTTPS trust anchor. Authority rotation will append a successor
-- generation without mutating this immutable root record in a later migration.
CREATE TABLE mesh_local_certificate_authorities (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    authority_id BLOB NOT NULL UNIQUE CHECK (length(authority_id) = 16),
    generation INTEGER NOT NULL CHECK (generation = 1),
    certificate_der BLOB NOT NULL CHECK (length(certificate_der) BETWEEN 1 AND 16384),
    certificate_digest BLOB NOT NULL CHECK (length(certificate_digest) = 32),
    key_secret_kind INTEGER NOT NULL DEFAULT 9 CHECK (key_secret_kind = 9),
    key_secret_id BLOB NOT NULL CHECK (length(key_secret_id) = 16),
    key_secret_generation INTEGER NOT NULL CHECK (key_secret_generation = generation),
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (not_after > not_before),
    CHECK (key_secret_id = authority_id),
    FOREIGN KEY (key_secret_kind, key_secret_id, key_secret_generation)
        REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER mesh_local_certificate_authorities_immutable
BEFORE UPDATE ON mesh_local_certificate_authorities
BEGIN
    SELECT RAISE(ABORT, 'mesh-local certificate authority is immutable');
END;

CREATE TRIGGER mesh_local_certificate_authorities_not_deletable
BEFORE DELETE ON mesh_local_certificate_authorities
BEGIN
    SELECT RAISE(ABORT, 'mesh-local certificate authority cannot be deleted');
END;
