// SPDX-License-Identifier: GPL-2.0-only

//! Node-local federation signing capability, separate from replicated public authority.

use crate::FederationSessionRuntime;
use ed25519_dalek::{Signer, SigningKey};
use meshspan_transport::{FederationHelloConfig, FederationNegotiationConfig};

/// Private federation identity. No clone, debug or private-key export is provided.
pub struct FederationSigningKey(SigningKey);

impl FederationSigningKey {
    /// Imports an exact protected 32-byte seed owned by the current node.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Returns the public key retained in signed federation authority.
    #[must_use]
    pub fn verifying_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs the canonical, domain-separated pairing transcript digest.
    #[must_use]
    pub fn sign_pairing(&self, digest: [u8; 32]) -> [u8; 64] {
        self.0
            .sign(&meshspan_metadata::federation_pairing_signing_message(
                digest,
            ))
            .to_bytes()
    }

    /// Signs capacity evidence after the provider has durably sealed local admission.
    /// The caller must register this public key for the statement's node/key generation
    /// and use the local ledger's returned seal. Signing alone neither fences IO nor
    /// credits quota; the owning consensus authority verifies and commits the statement.
    #[must_use]
    pub fn sign_storage_seal(
        &self,
        mut statement: meshspan_metadata::RecordFederationStorageSeal,
    ) -> meshspan_metadata::RecordFederationStorageSeal {
        statement.signature = self.0.sign(&statement.signing_payload()).to_bytes();
        statement
    }

    /// Borrows this identity into the existing mutually authenticated federation transport.
    #[must_use]
    pub fn session<'a>(
        &'a self,
        certificate_der: &'a [u8],
        hello: FederationHelloConfig,
        negotiation: FederationNegotiationConfig,
    ) -> FederationSessionRuntime<'a> {
        FederationSessionRuntime::new(certificate_der, &self.0, hello, negotiation)
    }
}
