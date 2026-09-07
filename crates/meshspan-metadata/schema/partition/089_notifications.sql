-- SPDX-License-Identifier: GPL-2.0-only

-- Immutable, encrypted channel configurations and one deduplicated outbox row per event.
CREATE TABLE notification_channels (
    channel_id BLOB PRIMARY KEY CHECK (length(channel_id) = 16),
    active_sequence INTEGER NOT NULL CHECK (active_sequence > 0),
    created_revision INTEGER NOT NULL CHECK (created_revision > 0),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE notification_channel_configurations (
    channel_id BLOB NOT NULL REFERENCES notification_channels(channel_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    channel_kind INTEGER NOT NULL CHECK (channel_kind IN (1, 2)),
    settings_kind INTEGER NOT NULL DEFAULT 10 CHECK (settings_kind = 10),
    settings_id BLOB NOT NULL CHECK (length(settings_id) = 16),
    settings_generation INTEGER NOT NULL CHECK (settings_generation > 0),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    event_filter INTEGER NOT NULL CHECK (event_filter BETWEEN 1 AND 15),
    configured_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (channel_id, sequence),
    FOREIGN KEY (settings_kind, settings_id, settings_generation)
        REFERENCES secret_generations(secret_kind, secret_id, generation) ON DELETE RESTRICT
) STRICT;

CREATE TABLE notification_deliveries (
    delivery_id BLOB PRIMARY KEY CHECK (length(delivery_id) = 16),
    channel_id BLOB NOT NULL,
    channel_sequence INTEGER NOT NULL,
    event_id BLOB NOT NULL REFERENCES audit_events(event_id) ON DELETE RESTRICT,
    event_kind INTEGER NOT NULL CHECK (event_kind BETWEEN 1 AND 4),
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 5),
    next_attempt_at INTEGER NOT NULL CHECK (next_attempt_at >= 0),
    worker_node_id BLOB REFERENCES nodes(node_id) ON DELETE RESTRICT,
    worker_incarnation INTEGER CHECK (worker_incarnation > 0),
    claim_expires_at INTEGER CHECK (claim_expires_at >= 0),
    delivered_at INTEGER CHECK (delivered_at >= 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (channel_id, event_id),
    FOREIGN KEY (channel_id, channel_sequence)
        REFERENCES notification_channel_configurations(channel_id, sequence) ON DELETE RESTRICT,
    CHECK ((state = 2 AND worker_node_id IS NOT NULL AND worker_incarnation IS NOT NULL
            AND claim_expires_at IS NOT NULL AND attempt > 0)
        OR (state != 2 AND worker_node_id IS NULL AND worker_incarnation IS NULL
            AND claim_expires_at IS NULL)),
    CHECK ((state = 3 AND delivered_at IS NOT NULL) OR (state != 3 AND delivered_at IS NULL))
) STRICT;

CREATE INDEX notification_deliveries_due ON notification_deliveries(state, next_attempt_at, delivery_id);
CREATE INDEX notification_deliveries_channel_state ON notification_deliveries(channel_id, state);
CREATE INDEX audit_events_notification_source ON audit_events(event_kind, sequence, event_id);
