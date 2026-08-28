-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE version_cleanup_intents
ADD COLUMN terminal_operation_id BLOB
    REFERENCES operations(operation_id) DEFERRABLE INITIALLY DEFERRED
    CHECK (terminal_operation_id IS NULL OR length(terminal_operation_id) = 16);

ALTER TABLE version_cleanup_intents
ADD COLUMN terminal_revision INTEGER CHECK (
    terminal_revision IS NULL OR terminal_revision > revision
);

ALTER TABLE version_cleanup_intents
ADD COLUMN cancelled_at INTEGER;

ALTER TABLE version_cleanup_intents
ADD COLUMN terminal_kind INTEGER CHECK (
    (terminal_kind IS NULL AND state = 1 AND terminal_operation_id IS NULL
        AND terminal_revision IS NULL AND cancelled_at IS NULL)
    OR
    (terminal_kind = 1 AND state = 2 AND terminal_operation_id IS NOT NULL
        AND terminal_revision IS NOT NULL AND completed_at IS NOT NULL
        AND cancelled_at IS NULL)
    OR
    (terminal_kind = 2 AND state = 3 AND terminal_operation_id IS NOT NULL
        AND terminal_revision IS NOT NULL AND completed_at IS NULL
        AND cancelled_at IS NOT NULL)
);

CREATE UNIQUE INDEX version_cleanup_intents_terminal_operation
ON version_cleanup_intents(terminal_operation_id)
WHERE terminal_operation_id IS NOT NULL;
