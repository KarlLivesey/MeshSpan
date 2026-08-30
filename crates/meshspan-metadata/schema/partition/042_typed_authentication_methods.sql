-- SPDX-License-Identifier: GPL-2.0-only

-- The pre-alpha generic protected-material row cannot be mapped safely to one
-- accepted typed method. Refuse an upgrade that contains one rather than guess
-- whether its bytes were a password, certificate or another obsolete shape.
CREATE TABLE authentication_method_migration_guard (
    legacy_row_count INTEGER NOT NULL CHECK (legacy_row_count = 0)
) STRICT;

INSERT INTO authentication_method_migration_guard
SELECT count(*) FROM authentication_methods;

DROP TABLE authentication_method_migration_guard;
DROP TABLE authentication_methods;

-- method_kind: 1 passkey, 2 TOTP, 3 recovery-code set, 4 API-key set.
-- service_scope is a non-empty bitset: 1 HTTPS, 2 headless API, 4 SMB.
-- state: 1 active, 2 suspended, 3 revoked.
CREATE TABLE authentication_methods (
    method_id BLOB PRIMARY KEY CHECK (length(method_id) = 16),
    user_principal_id BLOB NOT NULL REFERENCES users(principal_id) ON DELETE CASCADE,
    method_kind INTEGER NOT NULL CHECK (method_kind BETWEEN 1 AND 4),
    label TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 128),
    service_scope INTEGER NOT NULL CHECK (service_scope BETWEEN 1 AND 7),
    state INTEGER NOT NULL CHECK (state BETWEEN 1 AND 3),
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at INTEGER,
    credential_generation INTEGER NOT NULL CHECK (credential_generation > 0),
    revision INTEGER NOT NULL CHECK (revision > 0),
    CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (last_used_at IS NULL OR expires_at IS NULL OR last_used_at < expires_at)
) STRICT;

CREATE INDEX authentication_methods_by_user
ON authentication_methods(user_principal_id, state, method_kind, method_id);

CREATE TABLE webauthn_credentials (
    method_id BLOB NOT NULL
        REFERENCES authentication_methods(method_id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 1024),
    public_key_algorithm INTEGER NOT NULL CHECK (public_key_algorithm > 0),
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

-- TOTP material is an authenticated-encryption envelope, never plaintext.
CREATE TABLE totp_credentials (
    method_id BLOB PRIMARY KEY
        REFERENCES authentication_methods(method_id) ON DELETE CASCADE,
    secret_ciphertext BLOB NOT NULL CHECK (length(secret_ciphertext) BETWEEN 32 AND 4096),
    algorithm INTEGER NOT NULL CHECK (algorithm BETWEEN 1 AND 3),
    digits INTEGER NOT NULL CHECK (digits BETWEEN 6 AND 10),
    period_seconds INTEGER NOT NULL CHECK (period_seconds BETWEEN 15 AND 300),
    accepted_step_window INTEGER NOT NULL CHECK (accepted_step_window BETWEEN 0 AND 10),
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE recovery_codes (
    method_id BLOB NOT NULL
        REFERENCES authentication_methods(method_id) ON DELETE CASCADE,
    code_id BLOB NOT NULL CHECK (length(code_id) = 16),
    code_digest BLOB NOT NULL UNIQUE CHECK (length(code_digest) = 32),
    created_at INTEGER NOT NULL,
    used_at INTEGER,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (method_id, code_id),
    CHECK (used_at IS NULL OR used_at >= created_at)
) STRICT;

CREATE TABLE api_keys (
    method_id BLOB NOT NULL
        REFERENCES authentication_methods(method_id) ON DELETE CASCADE,
    key_id BLOB NOT NULL CHECK (length(key_id) = 16),
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

CREATE TRIGGER webauthn_credentials_require_passkey_method
BEFORE INSERT ON webauthn_credentials
WHEN NOT EXISTS (
    SELECT 1 FROM authentication_methods
    WHERE method_id = NEW.method_id AND method_kind = 1
)
BEGIN
    SELECT RAISE(ABORT, 'credential subtype does not match authentication method');
END;

CREATE TRIGGER totp_credentials_require_totp_method
BEFORE INSERT ON totp_credentials
WHEN NOT EXISTS (
    SELECT 1 FROM authentication_methods
    WHERE method_id = NEW.method_id AND method_kind = 2
)
BEGIN
    SELECT RAISE(ABORT, 'credential subtype does not match authentication method');
END;

CREATE TRIGGER recovery_codes_require_recovery_method
BEFORE INSERT ON recovery_codes
WHEN NOT EXISTS (
    SELECT 1 FROM authentication_methods
    WHERE method_id = NEW.method_id AND method_kind = 3
)
BEGIN
    SELECT RAISE(ABORT, 'credential subtype does not match authentication method');
END;

CREATE TRIGGER api_keys_require_api_key_method
BEFORE INSERT ON api_keys
WHEN NOT EXISTS (
    SELECT 1 FROM authentication_methods
    WHERE method_id = NEW.method_id AND method_kind = 4
)
BEGIN
    SELECT RAISE(ABORT, 'credential subtype does not match authentication method');
END;

CREATE TRIGGER authentication_method_kind_immutable
BEFORE UPDATE OF method_kind ON authentication_methods
WHEN NEW.method_kind <> OLD.method_kind
BEGIN
    SELECT RAISE(ABORT, 'authentication method kind is immutable');
END;
