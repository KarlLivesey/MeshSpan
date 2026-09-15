// SPDX-License-Identifier: GPL-2.0-only

//! One-use, digest-only invitation authority and atomic primary-method publication.

use meshspan_domain::{AuthenticationMethodId, OperationId, PrincipalId, Revision, UnixMicros};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::apply::{require_system_administrator, to_i64};
use super::{EntityKind, EntityReference, RepositoryError, authentication_method_creation};
use crate::{
    AuthoritativeCommand, CommandContext, IssueUserEnrollment, NewAuthenticationCredential,
    PartitionDatabase, RedeemUserEnrollment, RevokeUserEnrollment,
};

const MAXIMUM_INVITATION_LIFETIME_MICROS: i64 = 86_400_000_000;

/// Digest-bound evidence of one successful first-credential redemption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserEnrollmentRedemption {
    /// Recipient operation whose exact response may be recovered within capability lifetime.
    pub operation_id: OperationId,
    /// Complete canonical redemption command and context digest.
    pub request_digest: [u8; 32],
    /// Ordinary independently revocable primary method created in the transaction.
    pub method_id: AuthenticationMethodId,
    /// Original committed creation time, retained for exact replay.
    pub redeemed_at: UnixMicros,
}

/// Closed capability lifecycle; cancellation never erases a committed method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserEnrollmentState {
    /// No credential has been created from this invitation.
    Issued,
    /// Only the exact recorded redemption may recover its prior result.
    Redeemed(UserEnrollmentRedemption),
    /// No further capability use or secret retrieval is allowed.
    Revoked,
}

/// Validated public-owner facts; contains a token digest, never its plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserEnrollmentRecord {
    /// Invitation identity is the operation which issued its consent.
    pub issuance_operation_id: OperationId,
    /// Canonical original manager request digest.
    pub issuance_request_digest: [u8; 32],
    /// User for whom the first credential is permitted.
    pub principal_id: PrincipalId,
    /// Exact user revision to which the issuer consented.
    pub principal_revision: Revision,
    /// Manager responsible for this invitation.
    pub issued_by: PrincipalId,
    /// Capability verifier, never usable as a login secret.
    pub token_digest: [u8; 32],
    /// Original authority instant.
    pub issued_at: UnixMicros,
    /// Exclusive end of redemption and response-retrieval authority.
    pub expires_at: UnixMicros,
    /// Current closed lifecycle.
    pub state: UserEnrollmentState,
    /// Latest invitation revision for exact cancellation.
    pub revision: Revision,
}

pub(super) fn issue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &IssueUserEnrollment,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let lifetime = command
        .expires_at
        .get()
        .checked_sub(context.occurred_at.get())
        .ok_or(RepositoryError::InvalidCommand)?;
    if !(1..=MAXIMUM_INVITATION_LIFETIME_MICROS).contains(&lifetime)
        || command.token_digest == [0; 32]
    {
        return Err(RepositoryError::InvalidCommand);
    }
    require_recipient(
        transaction,
        command.principal_id,
        command.expected_principal_revision,
    )?;
    require_no_primary(transaction, command.principal_id)?;
    // An expired outstanding invitation cannot prevent the manager from issuing a new one.
    transaction.execute(
        "UPDATE user_enrollments SET state = 3, revision = ?1
         WHERE principal_id = ?2 AND state = 1 AND expires_at <= ?3",
        params![
            to_i64(revision.get())?,
            command.principal_id.as_bytes().as_slice(),
            context.occurred_at.get()
        ],
    )?;
    let existing: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM user_enrollments WHERE principal_id = ?1 AND state = 1)",
        [command.principal_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    if existing != 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO user_enrollments(issuance_operation_id, principal_id, principal_revision,
            issued_by, token_digest, issued_at, expires_at, state, revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
        params![
            context.operation_id.as_bytes().as_slice(),
            command.principal_id.as_bytes().as_slice(),
            to_i64(command.expected_principal_revision.get())?,
            context.actor_principal_id.as_bytes().as_slice(),
            command.token_digest.as_slice(),
            context.occurred_at.get(),
            command.expires_at.get(),
            to_i64(revision.get())?
        ],
    )?;
    Ok(invitation_entity(context.operation_id))
}

pub(super) fn revoke(
    transaction: &Transaction<'_>,
    _context: CommandContext,
    command: &RevokeUserEnrollment,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let changed = transaction.execute(
        "UPDATE user_enrollments SET state = 3, revision = ?1
         WHERE issuance_operation_id = ?2 AND revision = ?3 AND state IN (1, 2)",
        params![
            to_i64(revision.get())?,
            command.enrollment_operation_id.as_bytes().as_slice(),
            to_i64(command.expected_revision.get())?
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(invitation_entity(command.enrollment_operation_id))
}

pub(super) fn redeem(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &RedeemUserEnrollment,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let invitation = read_connection(transaction, command.enrollment_operation_id)?
        .ok_or(RepositoryError::InvalidCommand)?;
    if invitation.state != UserEnrollmentState::Issued
        || invitation.token_digest != command.token_digest
        || invitation.principal_id != command.method.principal_id
        || context.actor_principal_id != invitation.principal_id
        || context.occurred_at < invitation.issued_at
        || context.occurred_at >= invitation.expires_at
    {
        return Err(RepositoryError::InvalidCommand);
    }
    require_recipient(
        transaction,
        invitation.principal_id,
        invitation.principal_revision,
    )?;
    require_no_primary(transaction, invitation.principal_id)?;
    require_system_administrator(transaction, invitation.issued_by, context.occurred_at.get())?;
    require_primary(&command.method.credential, command.method.service_scope)?;
    let entity =
        authentication_method_creation::create(transaction, context, &command.method, revision)?;
    let digest =
        AuthoritativeCommand::RedeemUserEnrollment(command.clone()).request_digest(context);
    let changed = transaction.execute(
        "UPDATE user_enrollments SET state = 2, redeemed_operation_id = ?1,
            redeemed_request_digest = ?2, method_id = ?3, redeemed_at = ?4, revision = ?5
         WHERE issuance_operation_id = ?6 AND state = 1",
        params![
            context.operation_id.as_bytes().as_slice(),
            digest.as_slice(),
            command.method.method_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
            command.enrollment_operation_id.as_bytes().as_slice()
        ],
    )?;
    if changed != 1 {
        return Err(RepositoryError::InvalidCommand);
    }
    Ok(entity)
}

pub(super) fn read(
    database: &PartitionDatabase,
    operation: OperationId,
) -> Result<Option<UserEnrollmentRecord>, RepositoryError> {
    read_connection(database.connection(), operation)
}

fn invitation_entity(operation_id: OperationId) -> EntityReference {
    EntityReference {
        kind: EntityKind::UserEnrollment,
        id: operation_id.as_bytes(),
    }
}

fn require_recipient(
    transaction: &Transaction<'_>,
    principal: PrincipalId,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let valid: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM users u JOIN principals p ON p.principal_id = u.principal_id
         WHERE u.principal_id = ?1 AND p.state = 1 AND p.revision = ?2)",
        params![principal.as_bytes().as_slice(), to_i64(revision.get())?],
        |row| row.get(0),
    )?;
    if valid == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn require_no_primary(
    transaction: &Transaction<'_>,
    principal: PrincipalId,
) -> Result<(), RepositoryError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM authentication_methods WHERE user_principal_id = ?1 AND method_kind IN (1, 4))",
        [principal.as_bytes().as_slice()], |row| row.get(0),
    )?;
    if exists == 0 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn require_primary(
    credential: &NewAuthenticationCredential,
    service_scope: u8,
) -> Result<(), RepositoryError> {
    if service_scope == 0 || service_scope & !3 != 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    match credential {
        NewAuthenticationCredential::Passkey { .. }
        | NewAuthenticationCredential::ApiKey { .. } => Ok(()),
        NewAuthenticationCredential::Totp { .. }
        | NewAuthenticationCredential::RecoveryCodes { .. } => Err(RepositoryError::InvalidCommand),
    }
}

fn read_connection(
    connection: &Connection,
    operation: OperationId,
) -> Result<Option<UserEnrollmentRecord>, RepositoryError> {
    let row = connection
        .query_row(
            "SELECT e.principal_id, e.principal_revision, e.issued_by, e.token_digest,
            e.issued_at, e.expires_at, e.state, e.revision, o.request_digest,
            e.redeemed_operation_id, e.redeemed_request_digest, e.method_id, e.redeemed_at
         FROM user_enrollments e JOIN operations o ON o.operation_id = e.issuance_operation_id
         WHERE e.issuance_operation_id = ?1",
            [operation.as_bytes().as_slice()],
            StoredInvitation::read,
        )
        .optional()?;
    row.map(|row| row.validate(operation)).transpose()
}

struct StoredInvitation {
    principal: Vec<u8>,
    principal_revision: i64,
    issued_by: Vec<u8>,
    token_digest: Vec<u8>,
    issued_at: i64,
    expires_at: i64,
    state: i64,
    revision: i64,
    request_digest: Vec<u8>,
    redeemed_operation: Option<Vec<u8>>,
    redeemed_digest: Option<Vec<u8>>,
    method_id: Option<Vec<u8>>,
    redeemed_at: Option<i64>,
}
impl StoredInvitation {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            principal: row.get(0)?,
            principal_revision: row.get(1)?,
            issued_by: row.get(2)?,
            token_digest: row.get(3)?,
            issued_at: row.get(4)?,
            expires_at: row.get(5)?,
            state: row.get(6)?,
            revision: row.get(7)?,
            request_digest: row.get(8)?,
            redeemed_operation: row.get(9)?,
            redeemed_digest: row.get(10)?,
            method_id: row.get(11)?,
            redeemed_at: row.get(12)?,
        })
    }
    fn validate(self, operation: OperationId) -> Result<UserEnrollmentRecord, RepositoryError> {
        if self.expires_at <= self.issued_at || self.token_digest.iter().all(|byte| *byte == 0) {
            return Err(RepositoryError::CorruptState);
        }
        let state = self.parse_state()?;
        Ok(UserEnrollmentRecord {
            issuance_operation_id: operation,
            issuance_request_digest: fixed(&self.request_digest)?,
            principal_id: PrincipalId::from_bytes(fixed(&self.principal)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            principal_revision: positive_revision(self.principal_revision)?,
            issued_by: PrincipalId::from_bytes(fixed(&self.issued_by)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            token_digest: fixed(&self.token_digest)?,
            issued_at: UnixMicros::new(self.issued_at),
            expires_at: UnixMicros::new(self.expires_at),
            state,
            revision: positive_revision(self.revision)?,
        })
    }
    fn parse_state(&self) -> Result<UserEnrollmentState, RepositoryError> {
        match self.state {
            1 if self.redeemed_operation.is_none()
                && self.method_id.is_none()
                && self.redeemed_digest.is_none()
                && self.redeemed_at.is_none() =>
            {
                Ok(UserEnrollmentState::Issued)
            }
            2 => Ok(UserEnrollmentState::Redeemed(self.redemption()?)),
            3 => Ok(UserEnrollmentState::Revoked),
            _ => Err(RepositoryError::CorruptState),
        }
    }
    fn redemption(&self) -> Result<UserEnrollmentRedemption, RepositoryError> {
        let operation = self
            .redeemed_operation
            .as_deref()
            .ok_or(RepositoryError::CorruptState)?;
        let digest = self
            .redeemed_digest
            .as_deref()
            .ok_or(RepositoryError::CorruptState)?;
        let method = self
            .method_id
            .as_deref()
            .ok_or(RepositoryError::CorruptState)?;
        let redeemed_at = self.redeemed_at.ok_or(RepositoryError::CorruptState)?;
        if redeemed_at < self.issued_at || redeemed_at >= self.expires_at {
            return Err(RepositoryError::CorruptState);
        }
        Ok(UserEnrollmentRedemption {
            operation_id: OperationId::from_bytes(fixed(operation)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            request_digest: fixed(digest)?,
            method_id: AuthenticationMethodId::from_bytes(fixed(method)?)
                .map_err(|_| RepositoryError::CorruptState)?,
            redeemed_at: UnixMicros::new(redeemed_at),
        })
    }
}
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], RepositoryError> {
    bytes.try_into().map_err(|_| RepositoryError::CorruptState)
}
fn positive_revision(value: i64) -> Result<Revision, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        return Err(RepositoryError::CorruptState);
    }
    Ok(Revision::new(value))
}
