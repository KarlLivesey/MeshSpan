-- SPDX-License-Identifier: GPL-2.0-only

-- A disposable runtime candidate remains admission-fenced. The open state exists only
-- inside the transaction replacing its node/key projection, never as a committed phase.
CREATE TABLE partition_recovery_node_key_projection (
    singleton INTEGER PRIMARY KEY REFERENCES partition_recovery_preparation(singleton)
        CHECK (singleton = 1),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    reserved_revision INTEGER NOT NULL CHECK (reserved_revision > 0),
    projected_at INTEGER NOT NULL,
    completed INTEGER NOT NULL CHECK (completed IN (0, 1))
) STRICT;

CREATE TRIGGER recovery_node_key_projection_immutable
BEFORE UPDATE ON partition_recovery_node_key_projection
WHEN NOT (OLD.completed = 0 AND NEW.completed = 1
    AND NEW.singleton = OLD.singleton AND NEW.manifest_digest = OLD.manifest_digest
    AND NEW.reserved_revision = OLD.reserved_revision AND NEW.projected_at = OLD.projected_at)
BEGIN
    SELECT RAISE(ABORT, 'recovery projection identity is immutable');
END;

CREATE TRIGGER recovery_node_key_projection_not_deletable
BEFORE DELETE ON partition_recovery_node_key_projection
BEGIN
    SELECT RAISE(ABORT, 'recovery projection cannot be deleted');
END;

DROP TRIGGER node_wrapping_keys_immutable;
CREATE TRIGGER node_wrapping_keys_immutable
BEFORE UPDATE ON node_wrapping_keys
WHEN NOT (EXISTS (SELECT 1 FROM partition_recovery_node_key_projection p
    JOIN partition_recovery_credential_fence f ON f.singleton = p.singleton
    WHERE p.completed = 0 AND p.manifest_digest = f.manifest_digest
      AND p.reserved_revision = f.source_revision + 1
      AND NEW.revision = p.reserved_revision AND NEW.retired_at = p.projected_at)
    AND OLD.state IN (1, 2) AND NEW.state = 3 AND OLD.retired_at IS NULL
    AND NEW.retired_at >= OLD.registered_at
    AND NEW.node_id = OLD.node_id AND NEW.generation = OLD.generation
    AND NEW.public_key = OLD.public_key AND NEW.key_fingerprint = OLD.key_fingerprint
    AND NEW.registered_at = OLD.registered_at)
BEGIN
    SELECT RAISE(ABORT, 'node wrapping key generations are immutable');
END;

DROP TRIGGER secret_wrapping_recipients_immutable;
CREATE TRIGGER secret_wrapping_recipients_immutable
BEFORE UPDATE ON secret_wrapping_recipients
WHEN NOT (EXISTS (SELECT 1 FROM partition_recovery_node_key_projection p
    JOIN partition_recovery_credential_fence f ON f.singleton = p.singleton
    WHERE p.completed = 0 AND p.manifest_digest = f.manifest_digest
      AND p.reserved_revision = f.source_revision + 1
      AND NEW.revision = p.reserved_revision AND NEW.retired_at = p.projected_at)
    AND OLD.recipient_kind = 1 AND OLD.state IN (1, 2) AND NEW.state = 3
    AND OLD.retired_at IS NULL AND NEW.retired_at >= OLD.registered_at
    AND NEW.key_fingerprint = OLD.key_fingerprint AND NEW.recipient_kind = OLD.recipient_kind
    AND NEW.owner_id = OLD.owner_id AND NEW.generation = OLD.generation
    AND NEW.public_key = OLD.public_key AND NEW.registered_at = OLD.registered_at)
BEGIN
    SELECT RAISE(ABORT, 'secret wrapping recipient generations are immutable');
END;

-- Ciphertext generations remain immutable. Only their recipient envelopes are replaced
-- from the sealed recovery inventory, in the same atomic, admission-fenced projection.
DROP TRIGGER secret_recipient_envelopes_not_deletable;
CREATE TRIGGER secret_recipient_envelopes_not_deletable
BEFORE DELETE ON secret_recipient_envelopes
WHEN NOT EXISTS (SELECT 1 FROM partition_recovery_node_key_projection p
    JOIN partition_recovery_credential_fence f ON f.singleton = p.singleton
    WHERE p.completed = 0 AND p.manifest_digest = f.manifest_digest
      AND p.reserved_revision = f.source_revision + 1)
BEGIN
    SELECT RAISE(ABORT, 'secret recipient envelopes cannot be deleted');
END;
