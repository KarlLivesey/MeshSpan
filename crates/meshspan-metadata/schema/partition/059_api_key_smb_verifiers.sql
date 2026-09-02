-- SPDX-License-Identifier: GPL-2.0-only

-- One optional, authenticated-encryption envelope derived from the same API key.
-- It is mandatory exactly when the common method is SMB-capable; the repository
-- validates that cross-row invariant before insertion and integrity checks.
ALTER TABLE api_keys ADD COLUMN smb_verifier_ciphertext BLOB
    CHECK (
        smb_verifier_ciphertext IS NULL
        OR length(smb_verifier_ciphertext) BETWEEN 65 AND 256
    );
