-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE node_certificate_rotations (
    node_id BLOB NOT NULL,
    generation INTEGER NOT NULL CHECK (generation > 1),
    previous_generation INTEGER NOT NULL CHECK (previous_generation > 0 AND previous_generation < generation),
    incarnation INTEGER NOT NULL CHECK (incarnation > 0),
    issuer_generation INTEGER NOT NULL CHECK (issuer_generation > 0),
    issuer_certificate_der BLOB NOT NULL CHECK (length(issuer_certificate_der) BETWEEN 1 AND 8192),
    staged_revision INTEGER NOT NULL CHECK (staged_revision > 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 4),
    installed_at INTEGER,
    installed_revision INTEGER,
    retire_after INTEGER,
    installation_signature BLOB,
    PRIMARY KEY (node_id, generation),
    FOREIGN KEY (node_id, generation) REFERENCES node_certificates(node_id, generation),
    FOREIGN KEY (node_id, previous_generation) REFERENCES node_certificates(node_id, generation),
    CHECK ((state IN (1, 4) AND installed_at IS NULL AND installed_revision IS NULL
            AND retire_after IS NULL AND installation_signature IS NULL)
        OR (state IN (2, 3) AND installed_at IS NOT NULL AND installed_revision > staged_revision
            AND retire_after > installed_at AND length(installation_signature) BETWEEN 1 AND 72))
) STRICT;

CREATE UNIQUE INDEX node_certificate_rotations_one_pending
ON node_certificate_rotations(node_id) WHERE state IN (1, 2);

CREATE TRIGGER node_certificate_rotations_immutable
BEFORE UPDATE OF node_id, generation, previous_generation, incarnation, issuer_generation,
    issuer_certificate_der, staged_revision ON node_certificate_rotations
BEGIN
    SELECT RAISE(ABORT, 'node certificate generation identity is immutable');
END;
