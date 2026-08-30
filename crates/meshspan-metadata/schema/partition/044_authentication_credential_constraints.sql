-- SPDX-License-Identifier: GPL-2.0-only

-- COSE algorithm identifiers used by WebAuthn are commonly negative (for
-- example ES256 is -7). Rebuild the pre-implementation table before admitting
-- passkeys, and make public API-key identities globally unambiguous.
DROP TRIGGER webauthn_credentials_require_passkey_method;
ALTER TABLE webauthn_credentials RENAME TO webauthn_credentials_old;

CREATE TABLE webauthn_credentials (
    method_id BLOB NOT NULL
        REFERENCES authentication_methods(method_id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 1024),
    public_key_algorithm INTEGER NOT NULL CHECK (
        public_key_algorithm BETWEEN -65535 AND 65535 AND public_key_algorithm <> 0
    ),
    public_key BLOB NOT NULL CHECK (length(public_key) BETWEEN 1 AND 4096),
    signature_counter INTEGER NOT NULL CHECK (signature_counter >= 0),
    authenticator_guid BLOB CHECK (
        authenticator_guid IS NULL OR length(authenticator_guid) = 16
    ),
    transports INTEGER NOT NULL CHECK (transports BETWEEN 0 AND 255),
    backup_eligible INTEGER NOT NULL CHECK (backup_eligible IN (0, 1)),
    backup_state INTEGER NOT NULL CHECK (backup_state IN (0, 1)),
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (method_id, credential_id),
    UNIQUE (credential_id),
    CHECK (backup_state = 0 OR backup_eligible = 1)
) STRICT;

INSERT INTO webauthn_credentials SELECT * FROM webauthn_credentials_old;
DROP TABLE webauthn_credentials_old;

CREATE TRIGGER webauthn_credentials_require_passkey_method
BEFORE INSERT ON webauthn_credentials
WHEN NOT EXISTS (
    SELECT 1 FROM authentication_methods
    WHERE method_id = NEW.method_id AND method_kind = 1
)
BEGIN
    SELECT RAISE(ABORT, 'credential subtype does not match authentication method');
END;

DROP TRIGGER api_keys_require_api_key_method;
ALTER TABLE api_keys RENAME TO api_keys_old;

CREATE TABLE api_keys (
    method_id BLOB NOT NULL
        REFERENCES authentication_methods(method_id) ON DELETE CASCADE,
    key_id BLOB NOT NULL UNIQUE CHECK (length(key_id) = 16),
    key_digest BLOB NOT NULL UNIQUE CHECK (length(key_digest) = 32),
    scopes INTEGER NOT NULL CHECK (scopes > 0),
    valid_from INTEGER NOT NULL,
    valid_until INTEGER,
    last_used_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (method_id, key_id),
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    CHECK (last_used_at IS NULL OR last_used_at >= valid_from),
    CHECK (last_used_at IS NULL OR valid_until IS NULL OR last_used_at < valid_until)
) STRICT;

INSERT INTO api_keys SELECT * FROM api_keys_old;
DROP TABLE api_keys_old;

CREATE TRIGGER api_keys_require_api_key_method
BEFORE INSERT ON api_keys
WHEN NOT EXISTS (
    SELECT 1 FROM authentication_methods
    WHERE method_id = NEW.method_id AND method_kind = 4
)
BEGIN
    SELECT RAISE(ABORT, 'credential subtype does not match authentication method');
END;
