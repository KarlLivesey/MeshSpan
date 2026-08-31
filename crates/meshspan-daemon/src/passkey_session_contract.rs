// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable boundary between passkey ceremonies and session issuance.

use meshspan_api_contract::SessionAuthentication;
use meshspan_domain::{OperationId, UnixMicros};
use meshspan_metadata::PasskeyVerificationMaterial;

use crate::{PasskeySessionError, VerifiedPasskeyFactor};

/// Replaceable passkey-ceremony boundary consumed by authoritative session issuance.
pub trait PasskeySessionCeremony {
    /// Adapter-owned reserved assertion state.
    type Prepared: PreparedPasskeyProof;

    /// Reserves and opens one exact assertion.
    ///
    /// # Errors
    ///
    /// Rejects unsupported, malformed, expired, reused or unavailable ceremonies.
    fn prepare(
        &mut self,
        authentication: &SessionAuthentication,
        operation_id: OperationId,
        now: UnixMicros,
    ) -> Result<Self::Prepared, PasskeySessionError>;

    /// Makes local completion terminal after the authoritative result is durable.
    ///
    /// # Errors
    ///
    /// Fails closed until the exact receipt is restart-safely recorded.
    fn complete(
        &mut self,
        prepared: &Self::Prepared,
        result_digest: [u8; 32],
        now: UnixMicros,
    ) -> Result<(), PasskeySessionError>;
}

/// Evidence exposed by a reserved passkey assertion without exposing adapter persistence.
pub trait PreparedPasskeyProof {
    /// Borrows the opaque credential identity selected by the assertion.
    fn credential_id(&self) -> &[u8];

    /// Borrows secret material used only for exact session-delivery reconstruction.
    fn session_seed(&self) -> &[u8; 32];

    /// Returns a locally retained authoritative receipt after interrupted completion.
    fn recorded_result_digest(&self) -> Option<[u8; 32]>;

    /// Verifies the assertion against current authoritative credential material.
    ///
    /// # Errors
    ///
    /// Rejects every failed transport, cryptographic, identity, freshness or policy binding.
    fn verify(
        &self,
        material: &PasskeyVerificationMaterial,
    ) -> Result<VerifiedPasskeyFactor, PasskeySessionError>;
}

/// Default adapter which keeps passkey login closed until explicitly composed.
pub struct DisabledPasskeySessions;

impl PasskeySessionCeremony for DisabledPasskeySessions {
    type Prepared = DisabledPasskeyProof;

    fn prepare(
        &mut self,
        _: &SessionAuthentication,
        _: OperationId,
        _: UnixMicros,
    ) -> Result<Self::Prepared, PasskeySessionError> {
        Err(PasskeySessionError::Unsupported)
    }

    fn complete(
        &mut self,
        _: &Self::Prepared,
        _: [u8; 32],
        _: UnixMicros,
    ) -> Result<(), PasskeySessionError> {
        Err(PasskeySessionError::Unsupported)
    }
}

/// Uninhabited proof type used by the default-deny passkey adapter.
pub enum DisabledPasskeyProof {}

impl PreparedPasskeyProof for DisabledPasskeyProof {
    fn credential_id(&self) -> &[u8] {
        match *self {}
    }

    fn session_seed(&self) -> &[u8; 32] {
        match *self {}
    }

    fn recorded_result_digest(&self) -> Option<[u8; 32]> {
        match *self {}
    }

    fn verify(
        &self,
        _: &PasskeyVerificationMaterial,
    ) -> Result<VerifiedPasskeyFactor, PasskeySessionError> {
        match *self {}
    }
}
