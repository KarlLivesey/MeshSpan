-- SPDX-License-Identifier: GPL-2.0-only

-- Node attestations only: never a replacement for certificates or service admission.
CREATE TABLE partition_recovery_key_installations (
    node_id BLOB PRIMARY KEY CHECK (length(node_id) = 16),
    preparation INTEGER NOT NULL REFERENCES partition_recovery_credential_fence(singleton)
        ON DELETE RESTRICT CHECK (preparation = 1),
    bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
    signature BLOB NOT NULL CHECK (length(signature) BETWEEN 8 AND 72),
    recorded_at INTEGER NOT NULL
) STRICT;

CREATE TRIGGER partition_recovery_key_installations_immutable
BEFORE UPDATE ON partition_recovery_key_installations
BEGIN SELECT RAISE(ABORT, 'recovery key installation is immutable'); END;

CREATE TRIGGER partition_recovery_key_installations_not_deletable
BEFORE DELETE ON partition_recovery_key_installations
BEGIN SELECT RAISE(ABORT, 'recovery key installation must be retained'); END;
