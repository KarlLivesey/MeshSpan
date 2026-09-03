-- SPDX-License-Identifier: GPL-2.0-only

-- Certificate identity and encrypted delivery generation are deliberately separate. A recipient
-- change re-encrypts the same certificate bundle as a later secret generation without issuing a
-- new certificate. Every gateway acknowledgement is therefore retained per delivery generation.
CREATE TABLE public_certificate_delivery_installations (
    source_kind INTEGER NOT NULL CHECK (source_kind BETWEEN 1 AND 3),
    source_id BLOB NOT NULL CHECK (length(source_id) = 16),
    gateway_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    gateway_incarnation INTEGER NOT NULL CHECK (gateway_incarnation > 0),
    certificate_secret_kind INTEGER NOT NULL DEFAULT 7 CHECK (certificate_secret_kind = 7),
    certificate_secret_id BLOB NOT NULL CHECK (length(certificate_secret_id) = 16),
    certificate_secret_generation INTEGER NOT NULL CHECK (certificate_secret_generation > 0),
    bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
    installed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (
        source_kind, source_id, gateway_node_id, certificate_secret_generation
    ),
    FOREIGN KEY (
        certificate_secret_kind, certificate_secret_id, certificate_secret_generation
    ) REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE INDEX public_certificate_delivery_installations_by_gateway
ON public_certificate_delivery_installations(
    gateway_node_id, installed_at, source_kind, source_id, certificate_secret_generation
);

-- Preserve every pre-delivery-generation acknowledgement while the old source-specific tables
-- remain immutable compatibility evidence.
INSERT INTO public_certificate_delivery_installations(
    source_kind, source_id, gateway_node_id, gateway_incarnation, certificate_secret_kind,
    certificate_secret_id, certificate_secret_generation, bundle_digest, installed_at, revision
)
SELECT 1, order_id, gateway_node_id, gateway_incarnation, certificate_secret_kind,
       certificate_secret_id, certificate_secret_generation, bundle_digest, installed_at, revision
FROM public_certificate_installations;

INSERT INTO public_certificate_delivery_installations(
    source_kind, source_id, gateway_node_id, gateway_incarnation, certificate_secret_kind,
    certificate_secret_id, certificate_secret_generation, bundle_digest, installed_at, revision
)
SELECT 2, publication_id, gateway_node_id, gateway_incarnation, certificate_secret_kind,
       certificate_secret_id, certificate_secret_generation, bundle_digest, installed_at, revision
FROM external_public_certificate_installations;

INSERT INTO public_certificate_delivery_installations(
    source_kind, source_id, gateway_node_id, gateway_incarnation, certificate_secret_kind,
    certificate_secret_id, certificate_secret_generation, bundle_digest, installed_at, revision
)
SELECT 3, issuance_id, gateway_node_id, gateway_incarnation, certificate_secret_kind,
       certificate_secret_id, certificate_secret_generation, bundle_digest, installed_at, revision
FROM mesh_local_certificate_installations;

CREATE TRIGGER public_certificate_delivery_installations_immutable
BEFORE UPDATE ON public_certificate_delivery_installations BEGIN
    SELECT RAISE(ABORT, 'public certificate delivery installations are immutable');
END;

CREATE TRIGGER public_certificate_delivery_installations_not_deletable
BEFORE DELETE ON public_certificate_delivery_installations BEGIN
    SELECT RAISE(ABORT, 'public certificate delivery installations cannot be deleted');
END;
