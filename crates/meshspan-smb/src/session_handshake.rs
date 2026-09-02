// SPDX-License-Identifier: GPL-2.0-only

//! Ordered SMB 3.1.1 negotiate and NTLM session-establishment state machine.

use meshspan_domain::UnixMicros;

use crate::{
    EncryptionCipher, NegotiateRequest, NegotiateRequestError, NegotiateResponse,
    NegotiateResponseConfig, NegotiateResponseError, NegotiateSelection, NtlmAuthenticate,
    NtlmChallenge, NtlmChallengeConfig, NtlmNegotiate, NtlmTokenKind, NtlmWireError,
    SessionSetupRequest, SessionSetupResponse, SessionSetupResponseConfig, SigningAlgorithm,
    Smb311PreauthHash, Smb311SessionKeys, SmbSessionSetupError, SpnegoClientToken,
    SpnegoTokenError, encode_spnego_challenge, encode_spnego_complete,
};

const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xc000_0016;

/// Authentication implementation consumed by the protocol-only handshake.
pub trait SmbSessionAuthenticator {
    /// Non-secret identity retained by the established connection.
    type Identity;
    /// Secret intermediate proof retained only until transcript-bound keys exist.
    type Verified;
    /// Opaque authentication or key-derivation failure.
    type Error;

    /// Verifies the final NTLM proof against current `MeshSpan` authority.
    ///
    /// # Errors
    ///
    /// Rejects invalid, revoked, expired or unavailable current authentication state.
    fn verify(
        &mut self,
        authenticate: &NtlmAuthenticate<'_>,
        challenge: &NtlmChallenge,
        observed_at: UnixMicros,
    ) -> Result<Self::Verified, Self::Error>;

    /// Converts a verified proof into identity and final transcript-bound SMB keys.
    ///
    /// # Errors
    ///
    /// Rejects invalid key material or unavailable protected authentication state.
    fn establish(
        &mut self,
        verified: Self::Verified,
        preauth: &Smb311PreauthHash,
        cipher: EncryptionCipher,
    ) -> Result<(Self::Identity, Smb311SessionKeys), Self::Error>;
}

/// Live protocol state before and during one authenticated SMB session.
pub struct SmbSessionHandshake {
    session_id: u64,
    phase: HandshakePhase,
    preauth: Smb311PreauthHash,
    selection: Option<NegotiateSelection>,
    challenge: Option<NtlmChallenge>,
    wrapped: bool,
}

impl SmbSessionHandshake {
    /// Creates one connection-local handshake with a reserved non-zero session identity.
    ///
    /// # Errors
    ///
    /// Rejects the reserved zero session identity.
    pub fn new(session_id: u64) -> Result<Self, SmbSessionHandshakeError> {
        if session_id == 0 {
            return Err(SmbSessionHandshakeError::InvalidSession);
        }
        Ok(Self {
            session_id,
            phase: HandshakePhase::Negotiate,
            preauth: Smb311PreauthHash::new(),
            selection: None,
            challenge: None,
            wrapped: false,
        })
    }

    /// Negotiates the single supported dialect and begins the exact pre-auth transcript.
    ///
    /// # Errors
    ///
    /// Rejects out-of-order, malformed, downgraded or incompatible negotiation messages.
    pub fn negotiate(
        &mut self,
        packet: &[u8],
        config: NegotiateResponseConfig,
    ) -> Result<Vec<u8>, SmbSessionHandshakeError> {
        self.require_phase(HandshakePhase::Negotiate)?;
        let request = NegotiateRequest::parse(packet)?;
        let response = NegotiateResponse::encode(&request, config)?;
        let mut transcript = self.preauth.clone();
        transcript.update(packet);
        transcript.update(&response.packet);
        self.preauth = transcript;
        self.selection = Some(response.selection);
        self.phase = HandshakePhase::Challenge;
        Ok(response.packet)
    }

    /// Validates the first session-setup round and issues one fresh `NTLMv2` challenge.
    ///
    /// # Errors
    ///
    /// Rejects out-of-order, malformed, bound-session or non-NTLM negotiate input.
    pub fn challenge(
        &mut self,
        packet: &[u8],
        config: NtlmChallengeConfig<'_>,
    ) -> Result<Vec<u8>, SmbSessionHandshakeError> {
        self.require_phase(HandshakePhase::Challenge)?;
        let request = SessionSetupRequest::parse(packet).map_err(SmbSessionHandshakeError::from)?;
        if request.header.session_id != 0 || request.binding || request.previous_session_id != 0 {
            return Err(SmbSessionHandshakeError::InvalidSession);
        }
        let token = SpnegoClientToken::parse(request.security_token)
            .map_err(SmbSessionHandshakeError::from)?;
        if token.kind != NtlmTokenKind::Negotiate {
            return Err(SmbSessionHandshakeError::WrongAuthenticationPhase);
        }
        let negotiate = NtlmNegotiate::parse(token.ntlm_message)?;
        let challenge = NtlmChallenge::encode(negotiate, config)?;
        let security_token = if token.wrapped {
            encode_spnego_challenge(challenge.message())?
        } else {
            challenge.message().to_vec()
        };
        let response = SessionSetupResponse::encode(
            &request,
            SessionSetupResponseConfig {
                status: STATUS_MORE_PROCESSING_REQUIRED,
                session_id: self.session_id,
                security_token: &security_token,
                encrypt_data: false,
            },
        )?;
        let mut transcript = self.preauth.clone();
        transcript.update(packet);
        transcript.update(&response.packet);
        self.preauth = transcript;
        self.challenge = Some(challenge);
        self.wrapped = token.wrapped;
        self.phase = HandshakePhase::Proof;
        Ok(response.packet)
    }

    /// Verifies the final proof and derives keys only after the successful response is transcripted.
    ///
    /// # Errors
    ///
    /// Rejects out-of-order, malformed, session-confused, wrapper-confused or denied input.
    pub fn authenticate<A: SmbSessionAuthenticator>(
        &mut self,
        packet: &[u8],
        authenticator: &mut A,
        observed_at: UnixMicros,
        encryption_required: bool,
    ) -> Result<AuthenticatedSmbSession<A::Identity>, SmbSessionEstablishmentError<A::Error>> {
        self.require_phase(HandshakePhase::Proof)?;
        let request = SessionSetupRequest::parse(packet).map_err(SmbSessionHandshakeError::from)?;
        if request.header.session_id != self.session_id
            || request.binding
            || request.previous_session_id != 0
        {
            return Err(SmbSessionHandshakeError::InvalidSession.into());
        }
        let token = SpnegoClientToken::parse(request.security_token)
            .map_err(SmbSessionHandshakeError::from)?;
        if token.kind != NtlmTokenKind::Authenticate || token.wrapped != self.wrapped {
            return Err(SmbSessionHandshakeError::WrongAuthenticationPhase.into());
        }
        let challenge = self
            .challenge
            .as_ref()
            .ok_or(SmbSessionHandshakeError::InvalidState)?;
        let authenticate = NtlmAuthenticate::parse(token.ntlm_message, challenge)
            .map_err(SmbSessionHandshakeError::from)?;
        let verified = authenticator
            .verify(&authenticate, challenge, observed_at)
            .map_err(SmbSessionEstablishmentError::Authentication)?;
        let security_token = if self.wrapped {
            encode_spnego_complete().map_err(SmbSessionHandshakeError::from)?
        } else {
            Vec::new()
        };
        let response = SessionSetupResponse::encode(
            &request,
            SessionSetupResponseConfig {
                status: 0,
                session_id: self.session_id,
                security_token: &security_token,
                encrypt_data: encryption_required,
            },
        )
        .map_err(SmbSessionHandshakeError::from)?;
        let mut transcript = self.preauth.clone();
        transcript.update(packet);
        transcript.update(&response.packet);
        let selection = self
            .selection
            .ok_or(SmbSessionHandshakeError::InvalidState)?;
        let (identity, keys) = authenticator
            .establish(verified, &transcript, selection.encryption)
            .map_err(SmbSessionEstablishmentError::Authentication)?;
        self.preauth = transcript;
        self.challenge = None;
        self.phase = HandshakePhase::Established;
        Ok(AuthenticatedSmbSession {
            response: response.packet,
            session_id: self.session_id,
            identity,
            keys,
            selection,
            encryption_required,
        })
    }

    fn require_phase(&self, phase: HandshakePhase) -> Result<(), SmbSessionHandshakeError> {
        if self.phase == phase {
            Ok(())
        } else {
            Err(SmbSessionHandshakeError::OutOfOrder)
        }
    }
}

/// Completed session establishment, including the exact response still to be sent.
pub struct AuthenticatedSmbSession<I> {
    response: Vec<u8>,
    session_id: u64,
    identity: I,
    keys: Smb311SessionKeys,
    selection: NegotiateSelection,
    encryption_required: bool,
}

impl<I> AuthenticatedSmbSession<I> {
    /// Returns the final unencrypted session-setup response.
    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }

    /// Returns the reserved non-zero session identity.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Returns the authenticated common identity.
    #[must_use]
    pub const fn identity(&self) -> &I {
        &self.identity
    }

    /// Returns the transcript-bound session keys for signing and transforms.
    #[must_use]
    pub const fn keys(&self) -> &Smb311SessionKeys {
        &self.keys
    }

    /// Returns the negotiated signing algorithm.
    #[must_use]
    pub const fn signing_algorithm(&self) -> SigningAlgorithm {
        self.selection.signing
    }

    /// Returns the negotiated encryption cipher.
    #[must_use]
    pub const fn encryption_cipher(&self) -> EncryptionCipher {
        self.selection.encryption
    }

    /// Returns whether every tree message must use the encrypted transform.
    #[must_use]
    pub const fn encryption_required(&self) -> bool {
        self.encryption_required
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandshakePhase {
    Negotiate,
    Challenge,
    Proof,
    Established,
}

/// Invalid protocol state or wire data during SMB session establishment.
#[derive(Debug, thiserror::Error)]
pub enum SmbSessionHandshakeError {
    /// This message is valid only in another handshake phase.
    #[error("SMB handshake message is out of order")]
    OutOfOrder,
    /// Session fields do not name the expected connection-local transition.
    #[error("SMB handshake session transition is invalid")]
    InvalidSession,
    /// NTLM token kind or SPNEGO wrapping changed between rounds.
    #[error("SMB authentication token is in the wrong phase")]
    WrongAuthenticationPhase,
    /// Required negotiated or challenge state is absent.
    #[error("SMB handshake internal state is invalid")]
    InvalidState,
    /// Dialect negotiation request failed validation.
    #[error(transparent)]
    NegotiateRequest(#[from] NegotiateRequestError),
    /// Dialect negotiation response could not be selected or encoded.
    #[error(transparent)]
    NegotiateResponse(#[from] NegotiateResponseError),
    /// Session-setup framing failed validation.
    #[error(transparent)]
    SessionSetup(#[from] SmbSessionSetupError),
    /// SPNEGO token failed strict canonical parsing.
    #[error(transparent)]
    Spnego(#[from] SpnegoTokenError),
    /// NTLM message failed strict semantic parsing.
    #[error(transparent)]
    Ntlm(#[from] NtlmWireError),
}

/// Protocol or authority failure while completing the final authentication round.
#[derive(Debug, thiserror::Error)]
pub enum SmbSessionEstablishmentError<E> {
    /// Handshake state or wire input failed validation.
    #[error(transparent)]
    Handshake(#[from] SmbSessionHandshakeError),
    /// Current common authentication authority rejected or could not verify the proof.
    #[error("SMB session authentication failed")]
    Authentication(#[source] E),
}

#[cfg(test)]
#[path = "session_handshake_tests.rs"]
mod tests;
