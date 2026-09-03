-- SPDX-License-Identifier: GPL-2.0-only

-- Automated external issuers publish one already-validated certificate generation. External
-- publications remain separate from ACME orders: they have no challenge, retry or worker claim.
CREATE TABLE external_certificate_publications (
    publication_id BLOB PRIMARY KEY CHECK (length(publication_id) = 16),
    certificate_id BLOB NOT NULL UNIQUE CHECK (length(certificate_id) = 16),
    generation INTEGER NOT NULL UNIQUE CHECK (generation > 0),
    publisher_principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    certificate_secret_kind INTEGER NOT NULL DEFAULT 7 CHECK (certificate_secret_kind = 7),
    certificate_secret_id BLOB NOT NULL CHECK (length(certificate_secret_id) = 16),
    certificate_secret_generation INTEGER NOT NULL CHECK (certificate_secret_generation > 0),
    bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
    chain_digest BLOB NOT NULL CHECK (length(chain_digest) = 32),
    public_key_fingerprint BLOB NOT NULL CHECK (length(public_key_fingerprint) = 32),
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (not_after > not_before),
    CHECK (certificate_secret_id = certificate_id),
    CHECK (certificate_secret_generation = generation),
    FOREIGN KEY (
        certificate_secret_kind, certificate_secret_id, certificate_secret_generation
    ) REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE TABLE external_certificate_publication_names (
    publication_id BLOB NOT NULL
        REFERENCES external_certificate_publications(publication_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 255),
    dns_name TEXT NOT NULL CHECK (length(dns_name) BETWEEN 1 AND 253),
    PRIMARY KEY (publication_id, ordinal),
    UNIQUE (publication_id, dns_name)
) WITHOUT ROWID, STRICT;

CREATE TABLE external_public_certificate_installations (
    publication_id BLOB NOT NULL
        REFERENCES external_certificate_publications(publication_id) ON DELETE RESTRICT,
    gateway_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    gateway_incarnation INTEGER NOT NULL CHECK (gateway_incarnation > 0),
    certificate_secret_kind INTEGER NOT NULL DEFAULT 7 CHECK (certificate_secret_kind = 7),
    certificate_secret_id BLOB NOT NULL CHECK (length(certificate_secret_id) = 16),
    certificate_secret_generation INTEGER NOT NULL CHECK (certificate_secret_generation > 0),
    bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
    installed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (publication_id, gateway_node_id),
    FOREIGN KEY (
        certificate_secret_kind, certificate_secret_id, certificate_secret_generation
    ) REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE INDEX external_certificate_publications_newest
ON external_certificate_publications(created_at DESC, publication_id DESC);

CREATE INDEX external_public_certificate_installations_by_gateway
ON external_public_certificate_installations(gateway_node_id, installed_at, publication_id);

CREATE TRIGGER external_certificate_publications_immutable
BEFORE UPDATE ON external_certificate_publications
BEGIN
    SELECT RAISE(ABORT, 'external certificate publications are immutable');
END;

CREATE TRIGGER external_certificate_publications_not_deletable
BEFORE DELETE ON external_certificate_publications
BEGIN
    SELECT RAISE(ABORT, 'external certificate publications cannot be deleted');
END;

CREATE TRIGGER external_certificate_publication_names_immutable
BEFORE UPDATE ON external_certificate_publication_names
BEGIN
    SELECT RAISE(ABORT, 'external certificate publication names are immutable');
END;

CREATE TRIGGER external_certificate_publication_names_not_deletable
BEFORE DELETE ON external_certificate_publication_names
BEGIN
    SELECT RAISE(ABORT, 'external certificate publication names cannot be deleted');
END;

CREATE TRIGGER external_public_certificate_installations_immutable
BEFORE UPDATE ON external_public_certificate_installations
BEGIN
    SELECT RAISE(ABORT, 'external public certificate installations are immutable');
END;

CREATE TRIGGER external_public_certificate_installations_not_deletable
BEFORE DELETE ON external_public_certificate_installations
BEGIN
    SELECT RAISE(ABORT, 'external public certificate installations cannot be deleted');
END;
