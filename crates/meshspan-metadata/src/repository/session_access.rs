// SPDX-License-Identifier: GPL-2.0-only

//! Bounded session and system-role authority for non-filesystem administration reads.

use meshspan_domain::{AssuranceLevel, NodeId, PrincipalId, Revision, SessionId, UnixMicros};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};

use super::RepositoryError;
use crate::PartitionDatabase;

const SYSTEM_MANAGE_RIGHT: i64 = 1;
const UNBOUNDED_EXPIRY: i64 = i64::MAX;

/// Authenticated gateway-bound context for an administration read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionAccessRequest {
    /// Digest of the presented bearer token; raw credentials remain outside metadata.
    pub token_digest: [u8; 32],
    /// Minimum authentication assurance required by the operation.
    pub required_assurance: AssuranceLevel,
    /// Gateway serving the request.
    pub gateway_node_id: NodeId,
    /// Exact live gateway process incarnation.
    pub gateway_incarnation: u64,
    /// Authoritative mesh instant for session and role windows.
    pub now: UnixMicros,
}

/// Browser-specific presentation requirements layered over common session evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserSessionProtection {
    /// Safe read requiring no CSRF presentation.
    Read,
    /// State change requiring the independently presented CSRF verifier digest.
    Mutation {
        /// Digest of the separately presented CSRF secret.
        csrf_digest: [u8; 32],
    },
}

/// Browser session request binding token identity and CSRF requirements before authorisation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserSessionAccessRequest {
    /// Session identity embedded in the presented bearer.
    pub expected_session_id: SessionId,
    /// Common current session and gateway requirements.
    pub session: SessionAccessRequest,
    /// Read or mutation-specific CSRF requirement.
    pub protection: BrowserSessionProtection,
}

/// Non-disclosing rejection of a session-level administration request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionAccessDenial {
    /// The credential or gateway incarnation is not currently usable.
    Unavailable,
    /// The session predates the current identity and role projection.
    StaleIdentity,
    /// The session does not meet the operation's assurance requirement.
    InsufficientAssurance,
}

/// Current session authority bound to the identity, gateway and system-role projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionAccessCapability {
    /// Exact committed session.
    pub session_id: SessionId,
    /// Authenticated user.
    pub principal_id: PrincipalId,
    /// Gateway to which this authority is fenced.
    pub gateway_node_id: NodeId,
    /// Exact live gateway process incarnation.
    pub gateway_incarnation: u64,
    /// Current identity and role revision.
    pub identity_revision: Revision,
    /// Current gateway record revision.
    pub gateway_revision: Revision,
    /// Exclusive session expiry.
    pub expires_at: UnixMicros,
    /// Whether replacement browser cookies may retain bounded persistence.
    pub persistent_cookie: bool,
    /// Exclusive system-management expiry, or none when the user is not a current manager.
    pub system_management_expires_at: Option<UnixMicros>,
    /// Canonical evidence digest for response validators and audit binding.
    pub capability_digest: [u8; 32],
}

impl SessionAccessCapability {
    /// Reports whether this session currently has the system-management role.
    #[must_use]
    pub const fn is_system_manager(self) -> bool {
        self.system_management_expires_at.is_some()
    }
}

/// Complete session-level authority outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionAccessDecision {
    /// The session and gateway are current.
    Granted(SessionAccessCapability),
    /// The request is intentionally rejected without exposing credential details.
    Denied(SessionAccessDenial),
}

type StoredSession = (Vec<u8>, Vec<u8>, i64, i64, i64, i64, i64, Option<i64>, i64);

pub(super) fn evaluate(
    database: &PartitionDatabase,
    request: SessionAccessRequest,
) -> Result<SessionAccessDecision, RepositoryError> {
    if request.token_digest == [0; 32] || request.gateway_incarnation == 0 {
        return Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::Unavailable,
        ));
    }
    let stored = load_stored_session(database, request)?;
    let Some(stored) = stored else {
        return Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::Unavailable,
        ));
    };
    evaluate_stored_session(database, request, &stored)
}

fn load_stored_session(
    database: &PartitionDatabase,
    request: SessionAccessRequest,
) -> Result<Option<StoredSession>, RepositoryError> {
    database
        .connection()
        .query_row(
            "SELECT s.session_id, s.user_principal_id, s.assurance, s.identity_revision,
                    s.expires_at, m.identity_revision, n.revision,
                    (SELECT MIN(COALESCE(rg.valid_until, ?1))
                     FROM role_grants rg JOIN roles r USING(role_id)
                     WHERE rg.principal_id = s.user_principal_id
                       AND (r.system_rights & ?2) = ?2
                       AND (rg.valid_from IS NULL OR rg.valid_from <= ?3)
                       AND (rg.valid_until IS NULL OR rg.valid_until > ?3)
                       AND rg.activation_policy_id IS NULL),
                    s.persistent_cookie
             FROM authentication_sessions s
             JOIN principals p ON p.principal_id = s.user_principal_id
             JOIN nodes n ON n.node_id = ?4 AND n.current_incarnation = ?5 AND n.state = 2
             CROSS JOIN meshes m
             WHERE s.token_digest = ?6 AND s.revoked_at IS NULL AND s.issued_at <= ?3
               AND s.expires_at > ?3 AND p.state = 1
               AND (SELECT COUNT(*) FROM meshes) = 1",
            params![
                UNBOUNDED_EXPIRY,
                SYSTEM_MANAGE_RIGHT,
                request.now.get(),
                request.gateway_node_id.as_bytes().as_slice(),
                to_i64(request.gateway_incarnation)?,
                request.token_digest.as_slice(),
            ],
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
        .optional()
        .map_err(RepositoryError::from)
}

fn evaluate_stored_session(
    database: &PartitionDatabase,
    request: SessionAccessRequest,
    stored: &StoredSession,
) -> Result<SessionAccessDecision, RepositoryError> {
    let assurance = assurance(stored.2)?;
    let Some(factors) =
        super::session::active_factor_state(database.connection(), &stored.0, request.now)?
    else {
        return Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::Unavailable,
        ));
    };
    if assurance != factors.assurance {
        return Err(RepositoryError::CorruptState);
    }
    let session_revision = revision(stored.3)?;
    let identity_revision = revision(stored.5)?;
    if session_revision != identity_revision {
        return Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::StaleIdentity,
        ));
    }
    if !super::session::meets_assurance(
        database.connection(),
        factors,
        request.required_assurance,
        request.now,
    )? {
        return Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::InsufficientAssurance,
        ));
    }
    let expires_at = UnixMicros::new(stored.4);
    let system_management_expires_at = stored
        .7
        .map(|value| UnixMicros::new(value.min(expires_at.get())));
    let capability = SessionAccessCapability {
        session_id: identifier(&stored.0, SessionId::from_bytes)?,
        principal_id: identifier(&stored.1, PrincipalId::from_bytes)?,
        gateway_node_id: request.gateway_node_id,
        gateway_incarnation: request.gateway_incarnation,
        identity_revision,
        gateway_revision: revision(stored.6)?,
        expires_at,
        persistent_cookie: boolean(stored.8)?,
        system_management_expires_at,
        capability_digest: [0; 32],
    };
    Ok(SessionAccessDecision::Granted(SessionAccessCapability {
        capability_digest: capability_digest(capability),
        ..capability
    }))
}

pub(super) fn evaluate_browser(
    database: &PartitionDatabase,
    request: BrowserSessionAccessRequest,
) -> Result<SessionAccessDecision, RepositoryError> {
    let decision = evaluate(database, request.session)?;
    let SessionAccessDecision::Granted(capability) = decision else {
        return Ok(decision);
    };
    if capability.session_id != request.expected_session_id {
        return Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::Unavailable,
        ));
    }
    let BrowserSessionProtection::Mutation { csrf_digest } = request.protection else {
        return Ok(SessionAccessDecision::Granted(capability));
    };
    if csrf_digest == [0; 32] {
        return Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::Unavailable,
        ));
    }
    let stored: Vec<u8> = database.connection().query_row(
        "SELECT csrf_digest FROM authentication_sessions WHERE session_id = ?1",
        [capability.session_id.as_bytes().as_slice()],
        |row| row.get(0),
    )?;
    let stored: [u8; 32] = stored
        .try_into()
        .map_err(|_| RepositoryError::CorruptState)?;
    if !constant_time_equal(stored, csrf_digest) {
        return Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::Unavailable,
        ));
    }
    Ok(SessionAccessDecision::Granted(capability))
}

fn constant_time_equal(left: [u8; 32], right: [u8; 32]) -> bool {
    left.into_iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn capability_digest(capability: SessionAccessCapability) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.metadata.session-access-capability.v1\0");
    digest.update(capability.session_id.as_bytes());
    digest.update(capability.principal_id.as_bytes());
    digest.update(capability.gateway_node_id.as_bytes());
    digest.update(capability.gateway_incarnation.to_be_bytes());
    digest.update(capability.identity_revision.get().to_be_bytes());
    digest.update(capability.gateway_revision.get().to_be_bytes());
    digest.update(capability.expires_at.get().to_be_bytes());
    digest.update([u8::from(capability.persistent_cookie)]);
    digest.update(
        capability
            .system_management_expires_at
            .map_or(i64::MIN, UnixMicros::get)
            .to_be_bytes(),
    );
    digest.finalize().into()
}

fn assurance(value: i64) -> Result<AssuranceLevel, RepositoryError> {
    match value {
        1 => Ok(AssuranceLevel::SingleFactor),
        2 => Ok(AssuranceLevel::MultiFactor),
        3 => Ok(AssuranceLevel::RecentStepUp),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn revision(value: i64) -> Result<Revision, RepositoryError> {
    let value = u64::try_from(value).map_err(|_| RepositoryError::CorruptState)?;
    if value == 0 {
        Err(RepositoryError::CorruptState)
    } else {
        Ok(Revision::new(value))
    }
}

fn boolean(value: i64) -> Result<bool, RepositoryError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn identifier<const N: usize, T>(
    bytes: &[u8],
    decode: impl FnOnce([u8; N]) -> Result<T, meshspan_domain::IdentifierError>,
) -> Result<T, RepositoryError> {
    decode(
        bytes
            .try_into()
            .map_err(|_| RepositoryError::CorruptState)?,
    )
    .map_err(|_| RepositoryError::CorruptState)
}

fn to_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::CapacityExceeded)
}
