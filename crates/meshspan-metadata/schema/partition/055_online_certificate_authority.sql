-- SPDX-License-Identifier: GPL-2.0-only

-- Root-signed online authorities are public certificate generations. Their private keys are
-- stored only in independently encrypted secret generations.
CREATE TABLE online_certificate_authorities (
    mesh_id BLOB NOT NULL REFERENCES meshes(mesh_id) ON DELETE RESTRICT
        CHECK (length(mesh_id) = 16),
    generation INTEGER NOT NULL CHECK (generation > 0),
    certificate_der BLOB NOT NULL CHECK (length(certificate_der) BETWEEN 1 AND 8192),
    certificate_digest BLOB NOT NULL CHECK (length(certificate_digest) = 32),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_at INTEGER NOT NULL,
    retired_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (mesh_id, generation),
    CHECK (state != 3 OR retired_at IS NOT NULL)
) STRICT;

CREATE UNIQUE INDEX online_certificate_authorities_one_current
ON online_certificate_authorities(mesh_id)
WHERE state = 1 AND retired_at IS NULL;

CREATE TRIGGER online_certificate_authorities_immutable
BEFORE UPDATE OF mesh_id, generation, certificate_der, certificate_digest, created_at
ON online_certificate_authorities
BEGIN
    SELECT RAISE(ABORT, 'online certificate authority identity is immutable');
END;

CREATE TRIGGER online_certificate_authorities_not_deletable
BEFORE DELETE ON online_certificate_authorities
BEGIN
    SELECT RAISE(ABORT, 'online certificate authority generations cannot be deleted');
END;
