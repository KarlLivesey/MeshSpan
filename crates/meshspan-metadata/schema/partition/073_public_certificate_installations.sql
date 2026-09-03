-- SPDX-License-Identifier: GPL-2.0-only

-- A gateway acknowledges only after its live resolver selects the exact decrypted bundle. The
-- order and recipient foreign keys bind the claim to a generation actually issued to that node.
CREATE TABLE public_certificate_installations (
    order_id BLOB NOT NULL REFERENCES certificate_orders(order_id) ON DELETE RESTRICT,
    gateway_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT,
    gateway_incarnation INTEGER NOT NULL CHECK (gateway_incarnation > 0),
    certificate_secret_kind INTEGER NOT NULL DEFAULT 7 CHECK (certificate_secret_kind = 7),
    certificate_secret_id BLOB NOT NULL CHECK (length(certificate_secret_id) = 16),
    certificate_secret_generation INTEGER NOT NULL CHECK (certificate_secret_generation > 0),
    bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
    installed_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (order_id, gateway_node_id),
    FOREIGN KEY (
        certificate_secret_kind, certificate_secret_id, certificate_secret_generation
    )
        REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE INDEX public_certificate_installations_by_gateway
ON public_certificate_installations(gateway_node_id, installed_at, order_id);

CREATE TRIGGER public_certificate_installations_immutable
BEFORE UPDATE ON public_certificate_installations
BEGIN
    SELECT RAISE(ABORT, 'public certificate installations are immutable');
END;

CREATE TRIGGER public_certificate_installations_not_deletable
BEFORE DELETE ON public_certificate_installations
BEGIN
    SELECT RAISE(ABORT, 'public certificate installations cannot be deleted');
END;
