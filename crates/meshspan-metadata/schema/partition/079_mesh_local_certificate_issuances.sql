-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE mesh_local_certificate_issuances (
    issuance_id BLOB PRIMARY KEY CHECK (length(issuance_id) = 16),
    authority_id BLOB NOT NULL REFERENCES mesh_local_certificate_authorities(authority_id)
        ON DELETE RESTRICT,
    authority_generation INTEGER NOT NULL CHECK (authority_generation > 0),
    authority_certificate_digest BLOB NOT NULL CHECK (length(authority_certificate_digest) = 32),
    certificate_id BLOB NOT NULL UNIQUE CHECK (length(certificate_id) = 16),
    generation INTEGER NOT NULL UNIQUE CHECK (generation > 0),
    certificate_secret_kind INTEGER NOT NULL DEFAULT 7 CHECK (certificate_secret_kind = 7),
    certificate_secret_id BLOB NOT NULL CHECK (length(certificate_secret_id) = 16),
    certificate_secret_generation INTEGER NOT NULL CHECK (certificate_secret_generation > 0),
    bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
    public_key_fingerprint BLOB NOT NULL CHECK (length(public_key_fingerprint) = 32),
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (not_after > not_before),
    CHECK (certificate_secret_id = certificate_id),
    CHECK (certificate_secret_generation = generation),
    FOREIGN KEY (certificate_secret_kind, certificate_secret_id, certificate_secret_generation)
        REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE TABLE mesh_local_certificate_issuance_names (
    issuance_id BLOB NOT NULL REFERENCES mesh_local_certificate_issuances(issuance_id)
        ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 255),
    dns_name TEXT NOT NULL CHECK (length(dns_name) BETWEEN 1 AND 253),
    PRIMARY KEY (issuance_id, ordinal),
    UNIQUE (issuance_id, dns_name)
) WITHOUT ROWID, STRICT;

CREATE TABLE mesh_local_certificate_installations (
    issuance_id BLOB NOT NULL REFERENCES mesh_local_certificate_issuances(issuance_id)
        ON DELETE RESTRICT,
    gateway_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    gateway_incarnation INTEGER NOT NULL CHECK (gateway_incarnation > 0),
    certificate_secret_kind INTEGER NOT NULL DEFAULT 7 CHECK (certificate_secret_kind = 7),
    certificate_secret_id BLOB NOT NULL CHECK (length(certificate_secret_id) = 16),
    certificate_secret_generation INTEGER NOT NULL CHECK (certificate_secret_generation > 0),
    bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
    installed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (issuance_id, gateway_node_id),
    FOREIGN KEY (certificate_secret_kind, certificate_secret_id, certificate_secret_generation)
        REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE INDEX mesh_local_certificate_issuances_newest
ON mesh_local_certificate_issuances(created_at DESC, issuance_id DESC);

CREATE TRIGGER mesh_local_certificate_issuances_immutable
BEFORE UPDATE ON mesh_local_certificate_issuances BEGIN
    SELECT RAISE(ABORT, 'mesh-local certificate issuances are immutable');
END;
CREATE TRIGGER mesh_local_certificate_issuances_not_deletable
BEFORE DELETE ON mesh_local_certificate_issuances BEGIN
    SELECT RAISE(ABORT, 'mesh-local certificate issuances cannot be deleted');
END;
CREATE TRIGGER mesh_local_certificate_issuance_names_immutable
BEFORE UPDATE ON mesh_local_certificate_issuance_names BEGIN
    SELECT RAISE(ABORT, 'mesh-local certificate issuance names are immutable');
END;
CREATE TRIGGER mesh_local_certificate_issuance_names_not_deletable
BEFORE DELETE ON mesh_local_certificate_issuance_names BEGIN
    SELECT RAISE(ABORT, 'mesh-local certificate issuance names cannot be deleted');
END;
CREATE TRIGGER mesh_local_certificate_installations_immutable
BEFORE UPDATE ON mesh_local_certificate_installations BEGIN
    SELECT RAISE(ABORT, 'mesh-local certificate installations are immutable');
END;
CREATE TRIGGER mesh_local_certificate_installations_not_deletable
BEFORE DELETE ON mesh_local_certificate_installations BEGIN
    SELECT RAISE(ABORT, 'mesh-local certificate installations cannot be deleted');
END;
