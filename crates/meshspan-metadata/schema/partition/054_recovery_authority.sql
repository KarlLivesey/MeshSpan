-- SPDX-License-Identifier: GPL-2.0-only

-- Mesh creation atomically commits the public half of the offline authority and a commitment to
-- the exact encrypted bundle. Verification is an explicit later transition; no join or secret
-- provisioning path may treat a pending bundle as safely exported.
CREATE TABLE mesh_recovery_authorities (
    mesh_id BLOB PRIMARY KEY REFERENCES meshes(mesh_id) ON DELETE RESTRICT
        CHECK (length(mesh_id) = 16),
    recovery_key_fingerprint BLOB NOT NULL UNIQUE
        REFERENCES secret_wrapping_recipients(key_fingerprint) ON DELETE RESTRICT
        CHECK (length(recovery_key_fingerprint) = 32),
    root_certificate_der BLOB NOT NULL
        CHECK (length(root_certificate_der) BETWEEN 1 AND 8192),
    root_certificate_digest BLOB NOT NULL CHECK (length(root_certificate_digest) = 32),
    bundle_digest BLOB NOT NULL CHECK (length(bundle_digest) = 32),
    save_challenge_commitment BLOB NOT NULL
        CHECK (length(save_challenge_commitment) = 32),
    state INTEGER NOT NULL CHECK (state IN (1, 2)),
    created_at INTEGER NOT NULL,
    verified_by BLOB REFERENCES principals(principal_id) ON DELETE RESTRICT,
    verified_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (
        (state = 1 AND verified_by IS NULL AND verified_at IS NULL) OR
        (state = 2 AND verified_by IS NOT NULL AND verified_at IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER mesh_recovery_authority_identity_immutable
BEFORE UPDATE OF recovery_key_fingerprint, root_certificate_der, root_certificate_digest,
                 bundle_digest, save_challenge_commitment, created_at
ON mesh_recovery_authorities
BEGIN
    SELECT RAISE(ABORT, 'mesh recovery authority identity is immutable');
END;

CREATE TRIGGER mesh_recovery_authority_no_regression
BEFORE UPDATE OF state, verified_by, verified_at ON mesh_recovery_authorities
WHEN OLD.state != 1 OR NEW.state != 2
BEGIN
    SELECT RAISE(ABORT, 'mesh recovery authority state cannot regress');
END;

CREATE TRIGGER mesh_recovery_authority_not_deletable
BEFORE DELETE ON mesh_recovery_authorities
BEGIN
    SELECT RAISE(ABORT, 'mesh recovery authority cannot be deleted');
END;
