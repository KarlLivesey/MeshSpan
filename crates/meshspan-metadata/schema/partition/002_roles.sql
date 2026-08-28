-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE roles (
    role_id BLOB PRIMARY KEY CHECK (length(role_id) = 16),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 128),
    canonical_name TEXT NOT NULL UNIQUE CHECK (length(canonical_name) BETWEEN 1 AND 128),
    system_rights INTEGER NOT NULL CHECK (system_rights > 0 AND (system_rights & ~255) = 0),
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0)
) STRICT;

CREATE TABLE role_grants (
    role_id BLOB NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    principal_id BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    valid_from INTEGER,
    valid_until INTEGER,
    activation_policy_id BLOB REFERENCES access_activation_policies(policy_id) ON DELETE RESTRICT,
    created_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (role_id, principal_id),
    CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from)
) STRICT;

CREATE INDEX role_grants_by_principal
ON role_grants(principal_id, valid_until, role_id);
