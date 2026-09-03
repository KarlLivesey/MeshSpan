-- SPDX-License-Identifier: GPL-2.0-only

-- Public-certificate configuration is immutable. Reconfiguration creates another identity, so an
-- in-flight order can never observe provider or account settings that changed underneath it.
CREATE TABLE acme_configurations (
    config_id BLOB PRIMARY KEY CHECK (length(config_id) = 16),
    directory_url TEXT NOT NULL CHECK (
        length(directory_url) BETWEEN 9 AND 2048
        AND substr(directory_url, 1, 8) = 'https://'
    ),
    account_key_secret_id BLOB NOT NULL CHECK (length(account_key_secret_id) = 16),
    account_key_secret_generation INTEGER NOT NULL
        CHECK (account_key_secret_generation > 0),
    challenge_kind INTEGER NOT NULL CHECK (challenge_kind IN (1, 2)),
    challenge_settings_secret_id BLOB CHECK (
        challenge_settings_secret_id IS NULL OR length(challenge_settings_secret_id) = 16
    ),
    challenge_settings_secret_generation INTEGER CHECK (
        challenge_settings_secret_generation IS NULL
        OR challenge_settings_secret_generation > 0
    ),
    created_by BLOB NOT NULL REFERENCES principals(principal_id),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (challenge_settings_secret_id IS NULL)
        = (challenge_settings_secret_generation IS NULL)
    )
) STRICT;

CREATE TABLE acme_configuration_names (
    config_id BLOB NOT NULL REFERENCES acme_configurations(config_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 255),
    dns_name TEXT NOT NULL CHECK (length(dns_name) BETWEEN 1 AND 253),
    PRIMARY KEY (config_id, ordinal),
    UNIQUE (config_id, dns_name)
) WITHOUT ROWID, STRICT;

CREATE TABLE certificate_orders (
    order_id BLOB PRIMARY KEY CHECK (length(order_id) = 16),
    config_id BLOB NOT NULL REFERENCES acme_configurations(config_id) ON DELETE RESTRICT,
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    next_attempt_at INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    certificate_secret_id BLOB CHECK (
        certificate_secret_id IS NULL OR length(certificate_secret_id) = 16
    ),
    certificate_secret_generation INTEGER CHECK (
        certificate_secret_generation IS NULL OR certificate_secret_generation > 0
    ),
    certificate_not_before INTEGER,
    certificate_not_after INTEGER,
    completed_at INTEGER,
    result_digest BLOB CHECK (result_digest IS NULL OR length(result_digest) = 32),
    created_by BLOB NOT NULL REFERENCES principals(principal_id),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (state = 3)
        = (certificate_secret_id IS NOT NULL
           AND certificate_secret_generation IS NOT NULL
           AND certificate_not_before IS NOT NULL
           AND certificate_not_after IS NOT NULL
           AND completed_at IS NOT NULL
           AND result_digest IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX one_actionable_certificate_order_per_configuration
ON certificate_orders(config_id)
WHERE state IN (1, 2);

CREATE INDEX certificate_orders_ready
ON certificate_orders(state, next_attempt_at, created_at, order_id);

CREATE TABLE certificate_order_claims (
    order_id BLOB NOT NULL REFERENCES certificate_orders(order_id) ON DELETE RESTRICT,
    claim_generation INTEGER NOT NULL CHECK (claim_generation > 0),
    worker_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(worker_node_id) = 16),
    worker_incarnation INTEGER NOT NULL CHECK (worker_incarnation > 0),
    fence INTEGER NOT NULL CHECK (fence > 0),
    claimed_at INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    state INTEGER NOT NULL CHECK (state IN (1, 2, 3)),
    finished_at INTEGER,
    result_digest BLOB CHECK (result_digest IS NULL OR length(result_digest) = 32),
    retry_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (order_id, claim_generation),
    UNIQUE (order_id, fence),
    CHECK (lease_expires_at > claimed_at),
    CHECK ((state = 1) = (finished_at IS NULL AND result_digest IS NULL)),
    CHECK (retry_at IS NULL OR state = 2)
) STRICT;

CREATE UNIQUE INDEX one_active_certificate_order_claim
ON certificate_order_claims(order_id)
WHERE state = 1;

CREATE INDEX certificate_order_claims_by_worker
ON certificate_order_claims(worker_node_id, worker_incarnation, state, lease_expires_at, order_id);
