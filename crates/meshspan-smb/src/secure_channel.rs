// SPDX-License-Identifier: GPL-2.0-only

//! Post-authentication SMB 3.1.1 signing and encryption boundary.

use crate::{
    AuthenticatedSmbSession, Smb2Header, Smb311Transform, SmbPacketSender, SmbSigningError,
    SmbTransformError, sign_smb311, verify_smb311,
};

const TRANSFORM_PROTOCOL: [u8; 4] = [0xfd, b'S', b'M', b'B'];

/// One established session's mandatory inbound and outbound protection.
pub struct SmbSecureChannel<I> {
    session: AuthenticatedSmbSession<I>,
}

impl<I> SmbSecureChannel<I> {
    /// Takes ownership of the transcript-bound authenticated session.
    #[must_use]
    pub const fn new(session: AuthenticatedSmbSession<I>) -> Self {
        Self { session }
    }

    /// Returns the authenticated common identity retained by this channel.
    #[must_use]
    pub const fn identity(&self) -> &I {
        self.session.identity()
    }

    /// Returns the non-zero session identity required on every inner request.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session.session_id()
    }

    /// Authenticates one post-session request and returns its exact plaintext SMB message.
    ///
    /// # Errors
    ///
    /// Rejects missing required encryption, invalid transforms/signatures, wrong direction,
    /// malformed inner headers and session substitution.
    pub fn decode_request(&self, packet: &[u8]) -> Result<Vec<u8>, SmbSecureChannelError> {
        let plaintext = if packet.starts_with(&TRANSFORM_PROTOCOL) {
            self.transform()?.decrypt(packet)?
        } else {
            if self.session.encryption_required() {
                return Err(SmbSecureChannelError::EncryptionRequired);
            }
            let mut plaintext = packet.to_vec();
            verify_smb311(
                &mut plaintext,
                self.session.keys().signing_key(),
                self.session.signing_algorithm(),
                SmbPacketSender::Client,
            )?;
            plaintext
        };
        let header = Smb2Header::parse_request(&plaintext)
            .map_err(|_| SmbSecureChannelError::InvalidPlaintext)?;
        if header.session_id != self.session.session_id() {
            return Err(SmbSecureChannelError::SessionMismatch);
        }
        Ok(plaintext)
    }

    /// Protects one successfully encoded server response under the negotiated policy.
    ///
    /// # Errors
    ///
    /// Rejects malformed/session-confused plaintext, signing failure or transform failure.
    pub fn encode_response(&self, mut packet: Vec<u8>) -> Result<Vec<u8>, SmbSecureChannelError> {
        validate_response_session(&packet, self.session.session_id())?;
        if self.session.encryption_required() {
            self.transform()?.encrypt(&packet).map_err(Into::into)
        } else {
            sign_smb311(
                &mut packet,
                self.session.keys().signing_key(),
                self.session.signing_algorithm(),
                SmbPacketSender::Server,
            )?;
            Ok(packet)
        }
    }

    fn transform(&self) -> Result<Smb311Transform<'_>, SmbSecureChannelError> {
        Smb311Transform::new(
            self.session.keys(),
            self.session.encryption_cipher(),
            self.session.session_id(),
        )
        .map_err(Into::into)
    }
}

fn validate_response_session(packet: &[u8], expected: u64) -> Result<(), SmbSecureChannelError> {
    if packet.len() < 64 || packet.get(..4) != Some(&[0xfe, b'S', b'M', b'B']) {
        return Err(SmbSecureChannelError::InvalidPlaintext);
    }
    let flags = u32::from_le_bytes(
        packet[16..20]
            .try_into()
            .map_err(|_| SmbSecureChannelError::InvalidPlaintext)?,
    );
    let session_id = u64::from_le_bytes(
        packet[40..48]
            .try_into()
            .map_err(|_| SmbSecureChannelError::InvalidPlaintext)?,
    );
    if flags & 1 == 0 {
        return Err(SmbSecureChannelError::InvalidPlaintext);
    }
    if session_id != expected {
        return Err(SmbSecureChannelError::SessionMismatch);
    }
    Ok(())
}

/// Stable post-authentication protection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SmbSecureChannelError {
    /// Session policy requires an encrypted transform for every post-authentication message.
    #[error("SMB session requires encrypted requests")]
    EncryptionRequired,
    /// Plaintext does not contain a valid request or response header for its direction.
    #[error("SMB protected plaintext is invalid")]
    InvalidPlaintext,
    /// Inner or outer session identity does not match this channel.
    #[error("SMB protected message names another session")]
    SessionMismatch,
    /// Packet signing or verification failed.
    #[error(transparent)]
    Signing(#[from] SmbSigningError),
    /// Authenticated encryption or decryption failed.
    #[error(transparent)]
    Transform(#[from] SmbTransformError),
}
