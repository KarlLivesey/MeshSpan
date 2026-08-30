-- SPDX-License-Identifier: GPL-2.0-only

-- Authentication policy is immutable history selected by a contiguous sequence
-- for one exact connector and operation family. Policy IDs identify revisions;
-- callers cannot overwrite or silently broaden an earlier decision.
CREATE TABLE authentication_policy_revisions (
    service INTEGER NOT NULL CHECK (service IN (1, 2, 4)),
    operation_class INTEGER NOT NULL CHECK (operation_class BETWEEN 1 AND 4),
    policy_sequence INTEGER NOT NULL CHECK (policy_sequence > 0),
    policy_id BLOB NOT NULL UNIQUE CHECK (length(policy_id) = 16),
    allowed_factor_classes INTEGER NOT NULL CHECK (
        allowed_factor_classes BETWEEN 1 AND 15
    ),
    minimum_factor_count INTEGER NOT NULL CHECK (
        minimum_factor_count BETWEEN 1 AND 8
    ),
    maximum_session_duration_micros INTEGER NOT NULL CHECK (
        maximum_session_duration_micros > 0
    ),
    maximum_step_up_age_micros INTEGER CHECK (
        maximum_step_up_age_micros IS NULL
        OR (
            maximum_step_up_age_micros > 0
            AND maximum_step_up_age_micros <= maximum_session_duration_micros
        )
    ),
    configured_by BLOB NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
    configured_at INTEGER NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    PRIMARY KEY (service, operation_class, policy_sequence)
) STRICT;

CREATE TRIGGER authentication_policy_sequence_is_contiguous
BEFORE INSERT ON authentication_policy_revisions
WHEN NEW.policy_sequence != COALESCE(
    (
        SELECT max(policy_sequence) + 1
        FROM authentication_policy_revisions
        WHERE service = NEW.service AND operation_class = NEW.operation_class
    ),
    1
)
BEGIN
    SELECT RAISE(ABORT, 'authentication policy sequence must be contiguous');
END;

CREATE TRIGGER authentication_policy_revisions_immutable
BEFORE UPDATE ON authentication_policy_revisions
BEGIN
    SELECT RAISE(ABORT, 'authentication policy revisions are immutable');
END;

CREATE TRIGGER authentication_policy_revisions_not_deletable
BEFORE DELETE ON authentication_policy_revisions
BEGIN
    SELECT RAISE(ABORT, 'authentication policy revisions cannot be deleted');
END;

-- Existing bootstrapped partitions receive the same conservative defaults that
-- bootstrap installs for a new mesh. Empty pre-bootstrap databases remain empty.
WITH authority(configured_by, configured_at, revision) AS (
    SELECT rg.principal_id, mesh.created_at, mesh.revision
    FROM meshes AS mesh
    JOIN role_grants AS rg
    JOIN roles AS role ON role.role_id = rg.role_id
    WHERE (role.system_rights & 1) = 1
    ORDER BY rg.created_at, rg.principal_id
    LIMIT 1
), defaults(
    service, operation_class, policy_id, minimum_factor_count,
    maximum_session_duration_micros, maximum_step_up_age_micros
) AS (
    VALUES
        (1, 1, X'A6000000000000000000000000000101', 1, 43200000000, NULL),
        (1, 2, X'A6000000000000000000000000000102', 1, 43200000000, NULL),
        (1, 3, X'A6000000000000000000000000000103', 2,  3600000000, 900000000),
        (1, 4, X'A6000000000000000000000000000104', 2,   900000000, 300000000),
        (2, 1, X'A6000000000000000000000000000201', 1,  3600000000, NULL),
        (2, 2, X'A6000000000000000000000000000202', 1,  3600000000, NULL),
        (2, 3, X'A6000000000000000000000000000203', 2,  3600000000, 900000000),
        (2, 4, X'A6000000000000000000000000000204', 2,   900000000, 300000000),
        (4, 1, X'A6000000000000000000000000000401', 1, 43200000000, NULL),
        (4, 2, X'A6000000000000000000000000000402', 1, 43200000000, NULL),
        (4, 3, X'A6000000000000000000000000000403', 2,  3600000000, 900000000),
        (4, 4, X'A6000000000000000000000000000404', 2,   900000000, 300000000)
)
INSERT INTO authentication_policy_revisions(
    service, operation_class, policy_sequence, policy_id,
    allowed_factor_classes, minimum_factor_count,
    maximum_session_duration_micros, maximum_step_up_age_micros,
    configured_by, configured_at, revision
)
SELECT defaults.service, defaults.operation_class, 1, defaults.policy_id,
       15, defaults.minimum_factor_count,
       defaults.maximum_session_duration_micros, defaults.maximum_step_up_age_micros,
       authority.configured_by, authority.configured_at, authority.revision
FROM authority CROSS JOIN defaults;
