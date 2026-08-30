// SPDX-License-Identifier: GPL-2.0-only

//! Browser credential presentation composed with current mesh-wide session authority.

use axum::http::HeaderMap;
use meshspan_domain::{AssuranceLevel, NodeId, UnixMicros};
use meshspan_metadata::{
    AuthoritativeRepository, BrowserSessionAccessRequest, BrowserSessionProtection,
    RepositoryError, SessionAccessCapability, SessionAccessDecision, SessionAccessRequest,
};
use thiserror::Error;

use crate::{BrowserRequestProtection, BrowserSessionEvidence, parse_browser_session};

/// Current local gateway identity included in every session capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewaySessionIdentity {
    /// Enrolled gateway node.
    pub node_id: NodeId,
    /// Exact live daemon incarnation.
    pub incarnation: u64,
}

impl GatewaySessionIdentity {
    /// Constructs one usable live gateway identity.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero incarnation.
    pub const fn new(
        node_id: NodeId,
        incarnation: u64,
    ) -> Result<Self, BrowserAuthenticationError> {
        if incarnation == 0 {
            Err(BrowserAuthenticationError::InvalidGateway)
        } else {
            Ok(Self {
                node_id,
                incarnation,
            })
        }
    }
}

/// Minimal replicated-authority read needed by HTTP session authentication.
pub trait BrowserSessionAuthority {
    /// Evaluates one digest-only browser presentation against current session state.
    ///
    /// # Errors
    ///
    /// Fails closed when current authority cannot produce trustworthy evidence.
    fn evaluate_browser_session(
        &self,
        request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError>;
}

impl BrowserSessionAuthority for AuthoritativeRepository {
    fn evaluate_browser_session(
        &self,
        request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError> {
        self.evaluate_browser_session_access(request)
            .map_err(|error| map_repository_error(&error))
    }
}

impl<T> BrowserSessionAuthority for &T
where
    T: BrowserSessionAuthority + ?Sized,
{
    fn evaluate_browser_session(
        &self,
        request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError> {
        (*self).evaluate_browser_session(request)
    }
}

/// Reusable default-deny browser authenticator independent of endpoint semantics.
pub struct BrowserSessionAuthenticator<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> BrowserSessionAuthenticator<A>
where
    A: BrowserSessionAuthority,
{
    /// Binds authentication to one exact live gateway incarnation.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }

    /// Authenticates one read or mutation and returns only current capability evidence.
    ///
    /// # Errors
    ///
    /// All credential, identity, CSRF, expiry and assurance denials collapse to `Rejected`.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        required_assurance: AssuranceLevel,
        now: UnixMicros,
    ) -> Result<SessionAccessCapability, BrowserAuthenticationError> {
        let evidence = parse_browser_session(headers, protection)
            .map_err(|_| BrowserAuthenticationError::Rejected)?;
        self.authenticate_evidence(evidence, protection, required_assurance, now)
    }

    pub(crate) fn authenticate_evidence(
        &self,
        evidence: BrowserSessionEvidence,
        protection: BrowserRequestProtection,
        required_assurance: AssuranceLevel,
        now: UnixMicros,
    ) -> Result<SessionAccessCapability, BrowserAuthenticationError> {
        let protection = match protection {
            BrowserRequestProtection::Read => BrowserSessionProtection::Read,
            BrowserRequestProtection::Mutation => BrowserSessionProtection::Mutation {
                csrf_digest: evidence
                    .csrf_digest
                    .ok_or(BrowserAuthenticationError::Rejected)?,
            },
        };
        let request = BrowserSessionAccessRequest {
            expected_session_id: evidence.session_id,
            session: SessionAccessRequest {
                token_digest: evidence.token_digest,
                required_assurance,
                gateway_node_id: self.gateway.node_id,
                gateway_incarnation: self.gateway.incarnation,
                now,
            },
            protection,
        };
        match self.authority.evaluate_browser_session(request)? {
            SessionAccessDecision::Granted(capability) => Ok(capability),
            SessionAccessDecision::Denied(_) => Err(BrowserAuthenticationError::Rejected),
        }
    }
}

fn map_repository_error(error: &RepositoryError) -> BrowserSessionAuthorityError {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            BrowserSessionAuthorityError::Unavailable
        }
        _ => BrowserSessionAuthorityError::Failed,
    }
}

/// Closed replicated-authority failure safe to map at the public boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BrowserSessionAuthorityError {
    /// Current authority cannot be reached.
    #[error("browser session authority is unavailable")]
    Unavailable,
    /// Persisted authority or an invariant failed validation.
    #[error("browser session authority failed closed")]
    Failed,
}

/// Non-disclosing browser authentication failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BrowserAuthenticationError {
    /// Local gateway configuration is unusable.
    #[error("browser authentication gateway identity is invalid")]
    InvalidGateway,
    /// Credential presentation or current authority was not accepted.
    #[error("browser authentication was rejected")]
    Rejected,
    /// Replicated session authority could not provide a result.
    #[error("browser authentication authority failed")]
    Authority(#[from] BrowserSessionAuthorityError),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use axum::http::header::COOKIE;
    use axum::http::{HeaderMap, HeaderValue};
    use meshspan_domain::{
        ApiKeyBundle, AssuranceLevel, NodeId, OperationId, PrincipalId, Revision,
        SessionCsrfBundle, SessionId, SessionTokenBundle, UnixMicros,
    };
    use meshspan_metadata::{
        BrowserSessionAccessRequest, BrowserSessionProtection, SessionAccessCapability,
        SessionAccessDecision,
    };

    use super::{
        BrowserRequestProtection, BrowserSessionAuthenticator, BrowserSessionAuthority,
        BrowserSessionAuthorityError, GatewaySessionIdentity,
    };
    use crate::browser_session::CSRF_HEADER;

    #[test]
    fn mutation_authentication_passes_only_digest_evidence_to_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let node_id = NodeId::from_bytes([7; 16])?;
        let gateway = GatewaySessionIdentity::new(node_id, 3)?;
        let authority = CapturingAuthority::new(node_id);
        let authenticator = BrowserSessionAuthenticator::new(authority, gateway);
        let (headers, expected_session) = headers()?;
        let capability = authenticator.authenticate(
            &headers,
            BrowserRequestProtection::Mutation,
            AssuranceLevel::SingleFactor,
            UnixMicros::new(50),
        )?;
        assert_eq!(capability.session_id, expected_session);
        Ok(())
    }

    #[test]
    fn malformed_presentation_never_reaches_authority() -> Result<(), Box<dyn std::error::Error>> {
        let node_id = NodeId::from_bytes([7; 16])?;
        let authority = CapturingAuthority::new(node_id);
        let calls = authority.calls.clone();
        let authenticator =
            BrowserSessionAuthenticator::new(authority, GatewaySessionIdentity::new(node_id, 3)?);
        assert!(
            authenticator
                .authenticate(
                    &HeaderMap::new(),
                    BrowserRequestProtection::Mutation,
                    AssuranceLevel::SingleFactor,
                    UnixMicros::new(50),
                )
                .is_err()
        );
        assert_eq!(calls.get(), 0);
        Ok(())
    }

    struct CapturingAuthority {
        calls: Cell<u8>,
        node_id: NodeId,
    }

    impl CapturingAuthority {
        fn new(node_id: NodeId) -> Self {
            Self {
                calls: Cell::new(0),
                node_id,
            }
        }
    }

    impl BrowserSessionAuthority for CapturingAuthority {
        fn evaluate_browser_session(
            &self,
            request: BrowserSessionAccessRequest,
        ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError> {
            self.calls.set(self.calls.get().saturating_add(1));
            assert!(matches!(
                request.protection,
                BrowserSessionProtection::Mutation { csrf_digest } if csrf_digest != [0; 32]
            ));
            Ok(SessionAccessDecision::Granted(SessionAccessCapability {
                session_id: request.expected_session_id,
                principal_id: PrincipalId::from_bytes([8; 16])
                    .map_err(|_| BrowserSessionAuthorityError::Failed)?,
                gateway_node_id: self.node_id,
                gateway_incarnation: 3,
                identity_revision: Revision::new(1),
                gateway_revision: Revision::new(1),
                expires_at: UnixMicros::new(100),
                system_management_expires_at: None,
                capability_digest: [9; 32],
            }))
        }
    }

    fn headers() -> Result<(HeaderMap, SessionId), Box<dyn std::error::Error>> {
        let api_key = ApiKeyBundle::parse(concat!(
            "meshspan-key-v1.00000000000040008000000000000031.",
            "1111111111111111111111111111111111111111111111111111111111111111"
        ))?;
        let mut operation = [1; 16];
        operation[6] = 0x40;
        operation[8] = 0x80;
        let operation = OperationId::from_bytes(operation)?;
        let bearer = SessionTokenBundle::derive(&api_key, operation)?;
        let csrf = SessionCsrfBundle::derive(&api_key, operation)?;
        let session_id = bearer.session_id();
        let bearer = bearer.expose_encoded();
        let csrf = csrf.expose_encoded();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("meshspan_session={}", bearer.as_str()))?,
        );
        headers.insert(CSRF_HEADER, HeaderValue::from_str(&csrf)?);
        Ok((headers, session_id))
    }
}
