// SPDX-License-Identifier: GPL-2.0-only

//! Complete ordered protocol state for one embedded SMB TCP connection.

use meshspan_domain::UnixMicros;
use meshspan_filesystem::{FilesystemAccessContext, FilesystemFileAdapter};

use crate::{
    ConnectorFailure, NegotiateResponseConfig, NtlmChallengeConfig, Smb2Header,
    SmbCommandDispatchError, SmbCommandDispatcher, SmbCommandDispatcherConfigurationError,
    SmbConnectionControlError, SmbErrorResponse, SmbFilesystemLimits, SmbPublishedShare,
    SmbSessionAuthenticator, SmbSessionEstablishmentError, SmbSessionHandshake,
    SmbSessionHandshakeError,
};

/// Immutable daemon-owned handshake values generated independently for one connection.
pub struct SmbConnectionHandshakeConfig {
    /// Reserved random non-zero session identity.
    pub session_id: u64,
    /// Stable server identity, fresh salt and advertised resource bounds.
    pub negotiate: NegotiateResponseConfig,
    /// Fresh NTLM server challenge.
    pub server_challenge: [u8; 8],
    /// NetBIOS-compatible local server name.
    pub computer_name: String,
    /// Local authentication-domain display name.
    pub domain_name: String,
    /// Optional DNS server name included in the challenge target information.
    pub dns_computer_name: Option<String>,
    /// Optional DNS domain included in the challenge target information.
    pub dns_domain_name: Option<String>,
    /// Whether the established session requires encrypted messages.
    pub encryption_required: bool,
}

/// Services and policy moved into the authenticated dispatcher after proof succeeds.
pub struct SmbEstablishedSessionServices<F, C, M> {
    filesystem: F,
    filesystem_limits: SmbFilesystemLimits,
    shares: Vec<SmbPublishedShare>,
    make_context: C,
    classify_filesystem_error: M,
}

impl<F, C, M> SmbEstablishedSessionServices<F, C, M> {
    /// Groups the common filesystem boundary and its daemon-owned policies.
    #[must_use]
    pub const fn new(
        filesystem: F,
        filesystem_limits: SmbFilesystemLimits,
        shares: Vec<SmbPublishedShare>,
        make_context: C,
        classify_filesystem_error: M,
    ) -> Self {
        Self {
            filesystem,
            filesystem_limits,
            shares,
            make_context,
            classify_filesystem_error,
        }
    }
}

/// One connection's negotiate, authentication and authenticated command state.
pub struct SmbProtocolConnection<A: SmbSessionAuthenticator, F, C, M, N> {
    handshake: Option<SmbSessionHandshake>,
    handshake_config: SmbConnectionHandshakeConfig,
    authenticator: A,
    filesystem: Option<F>,
    filesystem_limits: SmbFilesystemLimits,
    shares: Option<Vec<SmbPublishedShare>>,
    make_context: Option<C>,
    classify_filesystem_error: Option<M>,
    classify_authentication_error: N,
    dispatcher: Option<SmbCommandDispatcher<A::Identity, F, C, M>>,
    phase: ConnectionPhase,
}

impl<A, F, C, M, N> SmbProtocolConnection<A, F, C, M, N>
where
    A: SmbSessionAuthenticator,
    F: FilesystemFileAdapter + Clone,
    C: FnMut(&A::Identity, UnixMicros) -> Result<FilesystemAccessContext, ConnectorFailure>,
    M: Fn(&F::Error) -> ConnectorFailure,
    N: Fn(&A::Error) -> ConnectorFailure,
{
    /// Builds one connection before any client-controlled bytes are accepted.
    ///
    /// # Errors
    ///
    /// Rejects a reserved session identity before allocating protocol state.
    pub fn new(
        handshake_config: SmbConnectionHandshakeConfig,
        authenticator: A,
        services: SmbEstablishedSessionServices<F, C, M>,
        classify_authentication_error: N,
    ) -> Result<Self, SmbSessionHandshakeError> {
        let handshake = SmbSessionHandshake::new(handshake_config.session_id)?;
        Ok(Self {
            handshake: Some(handshake),
            handshake_config,
            authenticator,
            filesystem: Some(services.filesystem),
            filesystem_limits: services.filesystem_limits,
            shares: Some(services.shares),
            make_context: Some(services.make_context),
            classify_filesystem_error: Some(services.classify_filesystem_error),
            classify_authentication_error,
            dispatcher: None,
            phase: ConnectionPhase::Negotiate,
        })
    }

    /// Processes one complete Direct TCP payload at an authoritative mesh instant.
    ///
    /// # Errors
    ///
    /// Returns failures which cannot safely be represented on the connection. Authentication
    /// rejection and all post-authentication command rejections are returned as exact SMB packets.
    pub fn receive(
        &mut self,
        packet: &[u8],
        observed_at: UnixMicros,
    ) -> Result<Vec<u8>, SmbProtocolConnectionError> {
        match self.phase {
            ConnectionPhase::Negotiate => self.negotiate(packet),
            ConnectionPhase::Challenge => self.challenge(packet),
            ConnectionPhase::Proof => self.authenticate(packet, observed_at),
            ConnectionPhase::Established => self
                .dispatcher
                .as_mut()
                .ok_or(SmbProtocolConnectionError::InvalidState)?
                .dispatch(packet, observed_at)
                .map_err(Into::into),
            ConnectionPhase::Rejected => Err(SmbProtocolConnectionError::Rejected),
        }
    }

    fn negotiate(&mut self, packet: &[u8]) -> Result<Vec<u8>, SmbProtocolConnectionError> {
        let config = self.handshake_config.negotiate;
        let response = self.handshake_mut()?.negotiate(packet, config)?;
        self.phase = ConnectionPhase::Challenge;
        Ok(response)
    }

    fn challenge(&mut self, packet: &[u8]) -> Result<Vec<u8>, SmbProtocolConnectionError> {
        let computer_name = self.handshake_config.computer_name.clone();
        let domain_name = self.handshake_config.domain_name.clone();
        let dns_computer_name = self.handshake_config.dns_computer_name.clone();
        let dns_domain_name = self.handshake_config.dns_domain_name.clone();
        let challenge = NtlmChallengeConfig {
            server_challenge: self.handshake_config.server_challenge,
            computer_name: &computer_name,
            domain_name: &domain_name,
            dns_computer_name: dns_computer_name.as_deref(),
            dns_domain_name: dns_domain_name.as_deref(),
        };
        let response = self.handshake_mut()?.challenge(packet, challenge)?;
        self.phase = ConnectionPhase::Proof;
        Ok(response)
    }

    fn authenticate(
        &mut self,
        packet: &[u8],
        observed_at: UnixMicros,
    ) -> Result<Vec<u8>, SmbProtocolConnectionError> {
        let encryption_required = self.handshake_config.encryption_required;
        let result = self
            .handshake
            .as_mut()
            .ok_or(SmbProtocolConnectionError::InvalidState)?
            .authenticate(
                packet,
                &mut self.authenticator,
                observed_at,
                encryption_required,
            );
        let session = match result {
            Ok(session) => session,
            Err(SmbSessionEstablishmentError::Authentication(error)) => {
                self.phase = ConnectionPhase::Rejected;
                return authentication_error_response(
                    packet,
                    (self.classify_authentication_error)(&error),
                );
            }
            Err(SmbSessionEstablishmentError::Handshake(error)) => return Err(error.into()),
        };
        let response = session.response().to_vec();
        let dispatcher = SmbCommandDispatcher::new(
            crate::SmbSecureChannel::new(session),
            self.filesystem
                .take()
                .ok_or(SmbProtocolConnectionError::InvalidState)?,
            self.filesystem_limits,
            self.shares
                .take()
                .ok_or(SmbProtocolConnectionError::InvalidState)?,
            self.make_context
                .take()
                .ok_or(SmbProtocolConnectionError::InvalidState)?,
            self.classify_filesystem_error
                .take()
                .ok_or(SmbProtocolConnectionError::InvalidState)?,
        )?;
        self.handshake = None;
        self.dispatcher = Some(dispatcher);
        self.phase = ConnectionPhase::Established;
        Ok(response)
    }

    fn handshake_mut(&mut self) -> Result<&mut SmbSessionHandshake, SmbProtocolConnectionError> {
        self.handshake
            .as_mut()
            .ok_or(SmbProtocolConnectionError::InvalidState)
    }
}

fn authentication_error_response(
    packet: &[u8],
    failure: ConnectorFailure,
) -> Result<Vec<u8>, SmbProtocolConnectionError> {
    let header = Smb2Header::parse_request(packet)
        .map_err(|_| SmbProtocolConnectionError::InvalidAuthenticationRequest)?;
    let status = match failure {
        ConnectorFailure::Success | ConnectorFailure::MoreEntries => {
            return Err(SmbProtocolConnectionError::InvalidAuthenticationClassification);
        }
        _ => failure.nt_status(),
    };
    SmbErrorResponse::encode(header, status, &[])
        .map(|response| response.packet)
        .map_err(Into::into)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionPhase {
    Negotiate,
    Challenge,
    Proof,
    Established,
    Rejected,
}

/// Failure which cannot safely continue one SMB connection.
#[derive(Debug, thiserror::Error)]
pub enum SmbProtocolConnectionError {
    /// Ordered handshake validation failed.
    #[error(transparent)]
    Handshake(#[from] SmbSessionHandshakeError),
    /// The established dispatcher could not protect or correlate a response.
    #[error(transparent)]
    Dispatch(#[from] SmbCommandDispatchError),
    /// Static share or dispatcher construction failed after authentication.
    #[error(transparent)]
    DispatcherConfiguration(#[from] SmbCommandDispatcherConfigurationError),
    /// Canonical authentication error construction failed.
    #[error(transparent)]
    ErrorResponse(#[from] SmbConnectionControlError),
    /// An authenticated request could not be correlated for rejection.
    #[error("SMB authentication request cannot be correlated")]
    InvalidAuthenticationRequest,
    /// Authentication failure was incorrectly classified as a successful outcome.
    #[error("SMB authentication failure classification is invalid")]
    InvalidAuthenticationClassification,
    /// Required connection-owned state is absent.
    #[error("SMB connection state is invalid")]
    InvalidState,
    /// The connection has already rejected authentication.
    #[error("SMB connection authentication was rejected")]
    Rejected,
}

#[cfg(test)]
#[path = "protocol_connection_tests.rs"]
mod tests;
