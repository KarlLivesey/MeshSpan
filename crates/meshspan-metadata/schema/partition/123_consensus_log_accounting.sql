-- SPDX-License-Identifier: GPL-2.0-only

-- One migration scan establishes exact payload accounting for all retained history.
-- Later writes update these counters in their existing consensus transaction.
CREATE TABLE consensus_log_accounting (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version INTEGER NOT NULL CHECK (format_version = 1),
    entry_count INTEGER NOT NULL CHECK (entry_count >= 0),
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes >= 0),
    revision INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;

INSERT INTO consensus_log_accounting(singleton, format_version, entry_count, payload_bytes, revision)
SELECT 1, 1, count(*), coalesce(sum(length(payload)), 0), 0 FROM consensus_log;
