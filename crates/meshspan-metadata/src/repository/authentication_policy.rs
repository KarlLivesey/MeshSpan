// SPDX-License-Identifier: GPL-2.0-only

//! Immutable mesh-wide authentication policy revisions and enforcement.

use meshspan_domain::{
    AssuranceLevel, AuthenticationFactorClasses, AuthenticationMethodKind,
    AuthenticationOperationClass, AuthenticationPolicyId, AuthenticationService, DurationMicros,
    PrincipalId, Revision, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::to_i64;
use super::{EntityKind, EntityReference, RepositoryError};
use crate::{CommandContext, ConfigureAuthenticationPolicy, PartitionDatabase};

const MAXIMUM_FACTORS: u8 = 8;

const DEFAULT_POLICIES: [DefaultPolicy; 12] = [
    DefaultPolicy::new(
        AuthenticationService::Https,
        AuthenticationOperationClass::SessionEstablishment,
        1,
        43_200_000_000,
        None,
    ),
    DefaultPolicy::new(
        AuthenticationService::Https,
        AuthenticationOperationClass::Ordinary,
        1,
        43_200_000_000,
        None,
    ),
    DefaultPolicy::new(
        AuthenticationService::Https,
        AuthenticationOperationClass::Privileged,
        2,
        3_600_000_000,
        Some(900_000_000),
    ),
    DefaultPolicy::new(
        AuthenticationService::Https,
        AuthenticationOperationClass::Recovery,
        2,
        900_000_000,
        Some(300_000_000),
    ),
    DefaultPolicy::new(
        AuthenticationService::HeadlessApi,
        AuthenticationOperationClass::SessionEstablishment,
        1,
        3_600_000_000,
        None,
    ),
    DefaultPolicy::new(
        AuthenticationService::HeadlessApi,
        AuthenticationOperationClass::Ordinary,
        1,
        3_600_000_000,
        None,
    ),
    DefaultPolicy::new(
        AuthenticationService::HeadlessApi,
        AuthenticationOperationClass::Privileged,
        2,
        3_600_000_000,
        Some(900_000_000),
    ),
    DefaultPolicy::new(
        AuthenticationService::HeadlessApi,
        AuthenticationOperationClass::Recovery,
        2,
        900_000_000,
        Some(300_000_000),
    ),
    DefaultPolicy::new(
        AuthenticationService::Smb,
        AuthenticationOperationClass::SessionEstablishment,
        1,
        43_200_000_000,
        None,
    ),
    DefaultPolicy::new(
        AuthenticationService::Smb,
        AuthenticationOperationClass::Ordinary,
        1,
        43_200_000_000,
        None,
    ),
    DefaultPolicy::new(
        AuthenticationService::Smb,
        AuthenticationOperationClass::Privileged,
        2,
        3_600_000_000,
        Some(900_000_000),
    ),
    DefaultPolicy::new(
        AuthenticationService::Smb,
        AuthenticationOperationClass::Recovery,
        2,
        900_000_000,
        Some(300_000_000),
    ),
];

/// Current independently validated policy for one service and operation family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationPolicy {
    /// Connector family governed by this policy.
    pub service: AuthenticationService,
    /// Operation family governed by this policy.
    pub operation_class: AuthenticationOperationClass,
    /// Monotonic immutable policy sequence.
    pub sequence: u64,
    /// Stable identity of this immutable revision.
    pub policy_id: AuthenticationPolicyId,
    /// Method classes which may contribute to authentication.
    pub allowed_factor_classes: AuthenticationFactorClasses,
    /// Minimum number of distinct methods required.
    pub minimum_factor_count: u8,
    /// Maximum age of a session used under this policy.
    pub maximum_session_duration: DurationMicros,
    /// Maximum age of a recent step-up factor, when required.
    pub maximum_step_up_age: Option<DurationMicros>,
    /// Principal that selected this revision.
    pub configured_by: PrincipalId,
    /// Authoritative configuration instant.
    pub configured_at: UnixMicros,
    /// Replicated state revision selecting this policy.
    pub revision: Revision,
}

#[derive(Clone, Copy)]
struct DefaultPolicy {
    service: AuthenticationService,
    operation_class: AuthenticationOperationClass,
    minimum_factor_count: u8,
    maximum_session_duration: u64,
    maximum_step_up_age: Option<u64>,
}

impl DefaultPolicy {
    const fn new(
        service: AuthenticationService,
        operation_class: AuthenticationOperationClass,
        minimum_factor_count: u8,
        maximum_session_duration: u64,
        maximum_step_up_age: Option<u64>,
    ) -> Self {
        Self {
            service,
            operation_class,
            minimum_factor_count,
            maximum_session_duration,
            maximum_step_up_age,
        }
    }
}

pub(super) fn bootstrap_defaults(
    transaction: &Transaction<'_>,
    configured_by: PrincipalId,
    configured_at: UnixMicros,
    revision: Revision,
) -> Result<(), RepositoryError> {
    for policy in DEFAULT_POLICIES {
        insert_policy(
            transaction,
            AuthenticationPolicy {
                service: policy.service,
                operation_class: policy.operation_class,
                sequence: 1,
                policy_id: default_policy_id(policy.service, policy.operation_class)?,
                allowed_factor_classes: AuthenticationFactorClasses::ALL,
                minimum_factor_count: policy.minimum_factor_count,
                maximum_session_duration: DurationMicros::new(policy.maximum_session_duration),
                maximum_step_up_age: policy.maximum_step_up_age.map(DurationMicros::new),
                configured_by,
                configured_at,
                revision,
            },
        )?;
    }
    Ok(())
}

pub(super) fn configure(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: ConfigureAuthenticationPolicy,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_policy_shape(
        command.operation_class,
        command.allowed_factor_classes,
        command.minimum_factor_count,
        command.maximum_session_duration,
        command.maximum_step_up_age,
    )?;
    let current = load_current_connection(transaction, command.service, command.operation_class)?;
    if current.sequence != command.expected_policy_sequence {
        return Err(RepositoryError::StaleAuthenticationPolicy);
    }
    let next = current
        .sequence
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)?;
    insert_policy(
        transaction,
        AuthenticationPolicy {
            service: command.service,
            operation_class: command.operation_class,
            sequence: next,
            policy_id: command.policy_id,
            allowed_factor_classes: command.allowed_factor_classes,
            minimum_factor_count: command.minimum_factor_count,
            maximum_session_duration: command.maximum_session_duration,
            maximum_step_up_age: command.maximum_step_up_age,
            configured_by: context.actor_principal_id,
            configured_at: context.occurred_at,
            revision,
        },
    )?;
    Ok(EntityReference {
        kind: EntityKind::AuthenticationPolicy,
        id: command.policy_id.as_bytes(),
    })
}

fn insert_policy(
    transaction: &Transaction<'_>,
    policy: AuthenticationPolicy,
) -> Result<(), RepositoryError> {
    validate_policy_shape(
        policy.operation_class,
        policy.allowed_factor_classes,
        policy.minimum_factor_count,
        policy.maximum_session_duration,
        policy.maximum_step_up_age,
    )?;
    transaction.execute(
        "INSERT INTO authentication_policy_revisions(
            service, operation_class, policy_sequence, policy_id,
            allowed_factor_classes, minimum_factor_count,
            maximum_session_duration_micros, maximum_step_up_age_micros,
            configured_by, configured_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            policy.service.scope_bit(),
            policy.operation_class.code(),
            to_i64(policy.sequence)?,
            policy.policy_id.as_bytes().as_slice(),
            policy.allowed_factor_classes.bits(),
            policy.minimum_factor_count,
            duration_i64(policy.maximum_session_duration)?,
            policy.maximum_step_up_age.map(duration_i64).transpose()?,
            policy.configured_by.as_bytes().as_slice(),
            policy.configured_at.get(),
            to_i64(policy.revision.get())?,
        ],
    )?;
    Ok(())
}

fn validate_policy_shape(
    operation_class: AuthenticationOperationClass,
    allowed: AuthenticationFactorClasses,
    minimum_factor_count: u8,
    maximum_session_duration: DurationMicros,
    maximum_step_up_age: Option<DurationMicros>,
) -> Result<(), RepositoryError> {
    let has_primary = allowed.contains(AuthenticationMethodKind::Passkey)
        || allowed.contains(AuthenticationMethodKind::ApiKey);
    let step_up_shape_is_valid = match operation_class {
        AuthenticationOperationClass::SessionEstablishment
        | AuthenticationOperationClass::Ordinary => maximum_step_up_age.is_none(),
        AuthenticationOperationClass::Privileged | AuthenticationOperationClass::Recovery => {
            maximum_step_up_age.is_some()
        }
    };
    if !has_primary
        || minimum_factor_count == 0
        || minimum_factor_count > MAXIMUM_FACTORS
        || maximum_session_duration.get() == 0
        || !step_up_shape_is_valid
        || maximum_step_up_age
            .is_some_and(|age| age.get() == 0 || age.get() > maximum_session_duration.get())
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

pub(super) fn validate_session_establishment(
    connection: &Connection,
    service: AuthenticationService,
    factor_kinds: impl IntoIterator<Item = AuthenticationMethodKind>,
    issued_at: UnixMicros,
    expires_at: UnixMicros,
) -> Result<(), RepositoryError> {
    let policy = load_current_connection(
        connection,
        service,
        AuthenticationOperationClass::SessionEstablishment,
    )?;
    let (classes, count) = collect_evidence(factor_kinds)?;
    let requested_duration = expires_at
        .get()
        .checked_sub(issued_at.get())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(RepositoryError::InvalidCommand)?;
    if count < policy.minimum_factor_count
        || classes & !policy.allowed_factor_classes.bits() != 0
        || requested_duration > policy.maximum_session_duration.get()
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(())
    }
}

pub(super) fn permits_operation(
    connection: &Connection,
    service: AuthenticationService,
    required_assurance: AssuranceLevel,
    evidence: SessionPolicyEvidence,
    now: UnixMicros,
) -> Result<bool, RepositoryError> {
    let operation_class = match required_assurance {
        AssuranceLevel::SingleFactor | AssuranceLevel::MultiFactor => {
            AuthenticationOperationClass::Ordinary
        }
        AssuranceLevel::RecentStepUp => AuthenticationOperationClass::Privileged,
    };
    let policy = load_current_connection(connection, service, operation_class)?;
    if evidence.factor_count < policy.minimum_factor_count
        || evidence.factor_classes & !policy.allowed_factor_classes.bits() != 0
        || !assurance_satisfies(evidence.assurance, required_assurance)
        || !within_duration(evidence.issued_at, now, policy.maximum_session_duration)
    {
        return Ok(false);
    }
    let Some(maximum_age) = policy.maximum_step_up_age else {
        return Ok(true);
    };
    Ok(evidence.assurance >= AssuranceLevel::MultiFactor
        && within_duration(evidence.latest_authenticated_at, now, maximum_age))
}

/// Current factor and session evidence consumed by policy enforcement.
#[derive(Clone, Copy)]
pub(super) struct SessionPolicyEvidence {
    pub(super) assurance: AssuranceLevel,
    pub(super) factor_classes: u8,
    pub(super) factor_count: u8,
    pub(super) issued_at: UnixMicros,
    pub(super) latest_authenticated_at: UnixMicros,
}

fn assurance_satisfies(actual: AssuranceLevel, required: AssuranceLevel) -> bool {
    match required {
        AssuranceLevel::SingleFactor => actual >= AssuranceLevel::SingleFactor,
        AssuranceLevel::MultiFactor | AssuranceLevel::RecentStepUp => {
            actual >= AssuranceLevel::MultiFactor
        }
    }
}

fn within_duration(start: UnixMicros, now: UnixMicros, maximum: DurationMicros) -> bool {
    now.get() >= start.get()
        && now
            .get()
            .checked_sub(start.get())
            .and_then(|value| u64::try_from(value).ok())
            .is_some_and(|age| age <= maximum.get())
}

fn collect_evidence(
    factor_kinds: impl IntoIterator<Item = AuthenticationMethodKind>,
) -> Result<(u8, u8), RepositoryError> {
    let mut classes = 0_u8;
    let mut count = 0_u8;
    for kind in factor_kinds {
        classes |= kind.class_bit();
        count = count
            .checked_add(1)
            .ok_or(RepositoryError::CapacityExceeded)?;
    }
    Ok((classes, count))
}

pub(super) fn load(
    database: &PartitionDatabase,
    service: AuthenticationService,
    operation_class: AuthenticationOperationClass,
) -> Result<AuthenticationPolicy, RepositoryError> {
    load_current_connection(database.connection(), service, operation_class)
}

fn load_current_connection(
    connection: &Connection,
    service: AuthenticationService,
    operation_class: AuthenticationOperationClass,
) -> Result<AuthenticationPolicy, RepositoryError> {
    let stored: Option<StoredPolicy> = connection
        .query_row(
            "SELECT policy_sequence, policy_id, allowed_factor_classes,
                    minimum_factor_count, maximum_session_duration_micros,
                    maximum_step_up_age_micros, configured_by, configured_at, revision
             FROM authentication_policy_revisions
             WHERE service = ?1 AND operation_class = ?2
             ORDER BY policy_sequence DESC LIMIT 1",
            params![service.scope_bit(), operation_class.code()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()?;
    let stored = stored.ok_or(RepositoryError::CorruptState)?;
    let policy = decode_policy(service, operation_class, stored)?;
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM authentication_policy_revisions
         WHERE service = ?1 AND operation_class = ?2",
        params![service.scope_bit(), operation_class.code()],
        |row| row.get(0),
    )?;
    if policy.sequence != positive(count)? {
        return Err(RepositoryError::CorruptState);
    }
    Ok(policy)
}

type StoredPolicy = (i64, Vec<u8>, i64, i64, i64, Option<i64>, Vec<u8>, i64, i64);

fn decode_policy(
    service: AuthenticationService,
    operation_class: AuthenticationOperationClass,
    stored: StoredPolicy,
) -> Result<AuthenticationPolicy, RepositoryError> {
    let allowed_bits = u8::try_from(stored.2).map_err(|_| RepositoryError::CorruptState)?;
    let allowed_factor_classes = AuthenticationFactorClasses::new(allowed_bits)
        .map_err(|_| RepositoryError::CorruptState)?;
    let policy = AuthenticationPolicy {
        service,
        operation_class,
        sequence: positive(stored.0)?,
        policy_id: identifier(stored.1)?,
        allowed_factor_classes,
        minimum_factor_count: u8::try_from(stored.3).map_err(|_| RepositoryError::CorruptState)?,
        maximum_session_duration: duration(stored.4)?,
        maximum_step_up_age: stored.5.map(duration).transpose()?,
        configured_by: principal(stored.6)?,
        configured_at: UnixMicros::new(stored.7),
        revision: Revision::new(positive(stored.8)?),
    };
    validate_policy_shape(
        policy.operation_class,
        policy.allowed_factor_classes,
        policy.minimum_factor_count,
        policy.maximum_session_duration,
        policy.maximum_step_up_age,
    )
    .map_err(|_| RepositoryError::CorruptState)?;
    Ok(policy)
}

fn default_policy_id(
    service: AuthenticationService,
    operation_class: AuthenticationOperationClass,
) -> Result<AuthenticationPolicyId, RepositoryError> {
    let mut bytes = [0_u8; 16];
    bytes[0] = 0xa6;
    bytes[14] = service.scope_bit();
    bytes[15] = operation_class.code();
    AuthenticationPolicyId::from_bytes(bytes).map_err(|_| RepositoryError::CorruptState)
}

fn identifier(bytes: Vec<u8>) -> Result<AuthenticationPolicyId, RepositoryError> {
    AuthenticationPolicyId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn principal(bytes: Vec<u8>) -> Result<PrincipalId, RepositoryError> {
    PrincipalId::from_bytes(
        bytes
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn duration_i64(value: DurationMicros) -> Result<i64, RepositoryError> {
    i64::try_from(value.get()).map_err(|_| RepositoryError::CapacityExceeded)
}

fn duration(value: i64) -> Result<DurationMicros, RepositoryError> {
    positive(value).map(DurationMicros::new)
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::CorruptState)
}
