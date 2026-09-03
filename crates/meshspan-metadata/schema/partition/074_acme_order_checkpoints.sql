-- SPDX-License-Identifier: GPL-2.0-only

-- One compact validated restart point follows an order across expired worker claims. The leaf key
-- is an ordinary encrypted secret generation; only its non-secret reference appears here.
CREATE TABLE certificate_order_checkpoints (
    order_id BLOB PRIMARY KEY REFERENCES certificate_orders(order_id) ON DELETE RESTRICT
        CHECK (length(order_id) = 16),
    claim_generation INTEGER NOT NULL CHECK (claim_generation > 0),
    worker_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(worker_node_id) = 16),
    worker_incarnation INTEGER NOT NULL CHECK (worker_incarnation > 0),
    fence INTEGER NOT NULL CHECK (fence > 0),
    certificate_key_secret_kind INTEGER NOT NULL CHECK (certificate_key_secret_kind = 8),
    certificate_key_secret_id BLOB NOT NULL CHECK (length(certificate_key_secret_id) = 16),
    certificate_key_secret_generation INTEGER NOT NULL
        CHECK (certificate_key_secret_generation = 1),
    checkpoint BLOB NOT NULL CHECK (length(checkpoint) BETWEEN 1 AND 921600),
    checkpoint_digest BLOB NOT NULL CHECK (length(checkpoint_digest) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    FOREIGN KEY (order_id, claim_generation)
        REFERENCES certificate_order_claims(order_id, claim_generation) ON DELETE RESTRICT,
    FOREIGN KEY (
        certificate_key_secret_kind,
        certificate_key_secret_id,
        certificate_key_secret_generation
    ) REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;
