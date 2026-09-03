-- SPDX-License-Identifier: GPL-2.0-only

-- Operator-facing manual DNS work is authoritative and fence-bound. A replacement claim can
-- supersede an older task, preventing an administrator from acting on stale challenge material.
CREATE TABLE manual_dns_tasks (
    task_digest BLOB PRIMARY KEY CHECK (length(task_digest) = 32),
    order_id BLOB NOT NULL REFERENCES certificate_orders(order_id) ON DELETE RESTRICT
        CHECK (length(order_id) = 16),
    claim_generation INTEGER NOT NULL CHECK (claim_generation > 0),
    worker_node_id BLOB NOT NULL REFERENCES nodes(node_id) ON DELETE RESTRICT
        CHECK (length(worker_node_id) = 16),
    worker_incarnation INTEGER NOT NULL CHECK (worker_incarnation > 0),
    fence INTEGER NOT NULL CHECK (fence > 0),
    record_name TEXT NOT NULL CHECK (length(record_name) BETWEEN 1 AND 253),
    record_value BLOB NOT NULL CHECK (length(record_value) BETWEEN 1 AND 512),
    expires_at INTEGER NOT NULL,
    phase INTEGER NOT NULL CHECK (phase IN (1, 2, 3, 4, 5)),
    created_at INTEGER NOT NULL,
    transitioned_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    UNIQUE (order_id, fence, task_digest)
) STRICT;

CREATE INDEX manual_dns_tasks_operator_queue
ON manual_dns_tasks(phase, expires_at, created_at, task_digest);
