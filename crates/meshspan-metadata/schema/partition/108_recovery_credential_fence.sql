-- SPDX-License-Identifier: GPL-2.0-only

-- Offline-root evidence, not a fabricated user action or a consensus revision.
-- Activations at/below source_revision are invalid, including federated assignments.
CREATE TABLE partition_recovery_credential_fence (
    singleton INTEGER PRIMARY KEY REFERENCES partition_recovery_replacement_plan(singleton)
        ON DELETE RESTRICT CHECK (singleton = 1),
    recovery_id BLOB NOT NULL CHECK (length(recovery_id) = 16),
    manifest_digest BLOB NOT NULL CHECK (length(manifest_digest) = 32),
    source_revision INTEGER NOT NULL CHECK (source_revision > 0),
    fenced_at INTEGER NOT NULL,
    online_generation INTEGER NOT NULL CHECK (online_generation > 1),
    permit_generation INTEGER NOT NULL CHECK (permit_generation > 1),
    sessions INTEGER NOT NULL CHECK (sessions >= 0),
    join_grants INTEGER NOT NULL CHECK (join_grants >= 0),
    activations INTEGER NOT NULL CHECK (activations >= 0),
    federation_activations INTEGER NOT NULL CHECK (federation_activations >= 0),
    node_certificates INTEGER NOT NULL CHECK (node_certificates >= 0),
    pairing_invitations INTEGER NOT NULL CHECK (pairing_invitations >= 0)
) STRICT;

CREATE TRIGGER partition_recovery_credential_fence_immutable
BEFORE UPDATE ON partition_recovery_credential_fence
BEGIN SELECT RAISE(ABORT, 'recovery credential fence is immutable'); END;

CREATE TRIGGER partition_recovery_credential_fence_not_deletable
BEFORE DELETE ON partition_recovery_credential_fence
BEGIN SELECT RAISE(ABORT, 'recovery credential fence must be retained'); END;
