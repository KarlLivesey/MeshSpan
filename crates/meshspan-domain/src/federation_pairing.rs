// SPDX-License-Identifier: GPL-2.0-only

//! Short-lived administrator pairing material, never a node-enrolment credential.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Checks a bounded canonical HTTPS origin for federation bootstrap or peer routing.
#[must_use]
pub fn is_valid_federation_endpoint(endpoint: &str) -> bool {
    crate::join_grant::valid_https_origin(endpoint)
}

use crate::secret_text::{append_hex, decode_hex};
use crate::{FederationRelationshipId, MeshId, OperationId, PrincipalId, UnixMicros, uuid_v8};

const PREFIX: &str = "meshspan-federate-v1.";
const ID_DOMAIN: &[u8] = b"meshspan.federation.pairing.id.v1\0";
const SECRET_DOMAIN: &[u8] = b"meshspan.federation.pairing.secret.v1\0";
const VERIFIER_DOMAIN: &[u8] = b"meshspan.federation.pairing.verifier.v1\0";

/// Maximum size of one complete connection code, including its HTTPS origin.
pub const MAXIMUM_FEDERATION_PAIRING_CODE_BYTES: usize = PREFIX.len() + 224 + 6 + 512;
/// Pairing material may remain usable for at most one hour, independent of trust-key lifetime.
pub const MAXIMUM_FEDERATION_PAIRING_LIFETIME_MICROS: i64 = 3_600_000_000;

/// Exact administrator request inputs retained for lost-response replay.
pub struct FederationPairingIssuance<'a> {
    /// Issuing autonomous swarm, not a node joining another swarm.
    pub mesh_id: MeshId,
    /// Current approving local administrator.
    pub principal_id: PrincipalId,
    /// Stable API operation identity.
    pub operation_id: OperationId,
    /// Original committed issuance instant, retained on retry.
    pub issued_at: UnixMicros,
    /// Exclusive short-lived deadline.
    pub expires_at: UnixMicros,
    /// Exact HTTPS origin contacted for initial pairing, without redirects.
    pub endpoint: &'a str,
    /// Exact issuing gateway leaf certificate pin.
    pub certificate_fingerprint: [u8; 32],
}

impl FederationPairingIssuance<'_> {
    /// Validates public routing and lifetime fields without using a secret or contacting a peer.
    ///
    /// # Errors
    /// Rejects an invalid HTTPS origin, zero pin or interval longer than one hour.
    pub fn validate(&self) -> Result<(), FederationPairingInvitationError> {
        validate_public(
            self.issued_at,
            self.expires_at,
            self.endpoint,
            self.certificate_fingerprint,
        )
    }
}

/// Non-exportable derivation key; generation and persistence belong to the gateway secret owner.
pub struct FederationPairingIssuanceKey(Zeroizing<[u8; 32]>);

impl FederationPairingIssuanceKey {
    /// Loads an existing protected key without providing formatting or cloning capabilities.
    ///
    /// # Errors
    /// Rejects the reserved all-zero key.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, FederationPairingInvitationError> {
        if bytes == [0; 32] {
            return Err(FederationPairingInvitationError::Invalid);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    fn derive(
        &self,
        domain: &[u8],
        request: &FederationPairingIssuance<'_>,
    ) -> Result<[u8; 32], FederationPairingInvitationError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref())
            .map_err(|_| FederationPairingInvitationError::Invalid)?;
        mac.update(domain);
        mac.update(&request.mesh_id.as_bytes());
        mac.update(&request.principal_id.as_bytes());
        mac.update(&request.operation_id.as_bytes());
        mac.update(&request.issued_at.get().to_be_bytes());
        mac.update(&request.expires_at.get().to_be_bytes());
        mac.update(&request.certificate_fingerprint);
        mac.update(request.endpoint.as_bytes());
        Ok(mac.finalize().into_bytes().into())
    }
}

/// Secret-bearing connection material. Possession does not itself activate a relationship.
///
/// The issuing swarm must consume the matching live, unused, administrator-approved metadata
/// record. The receiving swarm must separately authenticate its own administrator. Neither
/// private identity keys nor user credentials are copied by this code.
pub struct FederationPairingInvitation {
    mesh_id: MeshId,
    relationship_id: FederationRelationshipId,
    issued_at: UnixMicros,
    expires_at: UnixMicros,
    certificate_fingerprint: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
    endpoint: String,
}

impl FederationPairingInvitation {
    /// Derives exactly replayable, operation-bound pairing material under a distinct HMAC domain.
    ///
    /// # Errors
    /// Rejects invalid origin, certificate pin or an empty/overlong validity interval.
    pub fn issue(
        key: &FederationPairingIssuanceKey,
        request: &FederationPairingIssuance<'_>,
    ) -> Result<Self, FederationPairingInvitationError> {
        validate_public(
            request.issued_at,
            request.expires_at,
            request.endpoint,
            request.certificate_fingerprint,
        )?;
        let derived_id = key.derive(ID_DOMAIN, request)?;
        let mut identifier = [0; 16];
        identifier.copy_from_slice(&derived_id[..16]);
        let secret = Zeroizing::new(key.derive(SECRET_DOMAIN, request)?);
        if *secret == [0; 32] {
            return Err(FederationPairingInvitationError::Invalid);
        }
        Ok(Self {
            mesh_id: request.mesh_id,
            relationship_id: FederationRelationshipId::from_bytes(uuid_v8(identifier))
                .map_err(|_| FederationPairingInvitationError::Invalid)?,
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            certificate_fingerprint: request.certificate_fingerprint,
            secret,
            endpoint: request.endpoint.to_owned(),
        })
    }

    /// Decodes bounded canonical connection material without trusting its claimed authority.
    ///
    /// # Errors
    /// Rejects node join codes, unknown versions, malformed fields, invalid origins and trailing data.
    pub fn parse(value: &str) -> Result<Self, FederationPairingInvitationError> {
        if value.len() > MAXIMUM_FEDERATION_PAIRING_CODE_BYTES {
            return Err(FederationPairingInvitationError::Invalid);
        }
        let mut fields = value
            .strip_prefix(PREFIX)
            .ok_or(FederationPairingInvitationError::Invalid)?
            .split('|');
        let mesh_id = MeshId::from_bytes(field(&mut fields)?)
            .map_err(|_| FederationPairingInvitationError::Invalid)?;
        let relationship_id = FederationRelationshipId::from_bytes(field(&mut fields)?)
            .map_err(|_| FederationPairingInvitationError::Invalid)?;
        let issued_at = UnixMicros::new(i64::from_be_bytes(field(&mut fields)?));
        let expires_at = UnixMicros::new(i64::from_be_bytes(field(&mut fields)?));
        let certificate_fingerprint = field(&mut fields)?;
        let secret = Zeroizing::new(field(&mut fields)?);
        let endpoint = fields
            .next()
            .ok_or(FederationPairingInvitationError::Invalid)?;
        if fields.next().is_some() || *secret == [0; 32] {
            return Err(FederationPairingInvitationError::Invalid);
        }
        validate_public(issued_at, expires_at, endpoint, certificate_fingerprint)?;
        Ok(Self {
            mesh_id,
            relationship_id,
            issued_at,
            expires_at,
            certificate_fingerprint,
            secret,
            endpoint: endpoint.to_owned(),
        })
    }

    /// Explicitly exposes secret text at an authenticated output or pinned pairing boundary.
    #[must_use]
    pub fn expose_encoded(&self) -> Zeroizing<String> {
        let mut value =
            Zeroizing::new(String::with_capacity(MAXIMUM_FEDERATION_PAIRING_CODE_BYTES));
        value.push_str(PREFIX);
        for bytes in [
            self.mesh_id.as_bytes().as_slice(),
            self.relationship_id.as_bytes().as_slice(),
            &self.issued_at.get().to_be_bytes(),
            &self.expires_at.get().to_be_bytes(),
            &self.certificate_fingerprint,
            self.secret.as_ref(),
        ] {
            append_hex(&mut value, bytes);
            value.push('|');
        }
        value.push_str(&self.endpoint);
        value
    }

    /// Returns the full material verifier for the replicated one-use invitation record.
    #[must_use]
    pub fn verifier(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(VERIFIER_DOMAIN);
        digest.update(self.expose_encoded().as_bytes());
        digest.finalize().into()
    }

    /// Returns the issuing autonomous swarm.
    #[must_use]
    pub const fn mesh_id(&self) -> MeshId {
        self.mesh_id
    }
    /// Returns the reserved relationship identity, not a local node identity.
    #[must_use]
    pub const fn relationship_id(&self) -> FederationRelationshipId {
        self.relationship_id
    }
    /// Returns the inclusive issuance time.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMicros {
        self.issued_at
    }
    /// Returns the exclusive connection-material deadline.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMicros {
        self.expires_at
    }
    /// Returns the exact HTTPS origin; callers must disable redirects.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    /// Returns the exact gateway leaf pin required before sending the code.
    #[must_use]
    pub const fn certificate_fingerprint(&self) -> [u8; 32] {
        self.certificate_fingerprint
    }
    /// Checks the material's interval only; this is not a substitute for current metadata approval.
    #[must_use]
    pub fn is_current(&self, now: UnixMicros) -> bool {
        self.issued_at <= now && now < self.expires_at
    }
}

fn field<'a, const N: usize>(
    fields: &mut impl Iterator<Item = &'a str>,
) -> Result<[u8; N], FederationPairingInvitationError> {
    fields
        .next()
        .and_then(decode_hex)
        .ok_or(FederationPairingInvitationError::Invalid)
}

fn validate_public(
    issued_at: UnixMicros,
    expires_at: UnixMicros,
    endpoint: &str,
    pin: [u8; 32],
) -> Result<(), FederationPairingInvitationError> {
    let duration = expires_at
        .get()
        .checked_sub(issued_at.get())
        .ok_or(FederationPairingInvitationError::Invalid)?;
    if issued_at.get() < 0
        || !(1..=MAXIMUM_FEDERATION_PAIRING_LIFETIME_MICROS).contains(&duration)
        || pin == [0; 32]
        || !crate::join_grant::valid_https_origin(endpoint)
    {
        return Err(FederationPairingInvitationError::Invalid);
    }
    Ok(())
}

/// Secret-free failure to issue or parse federation connection material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationPairingInvitationError {
    /// Invalid canonical representation, origin, pin, key or lifetime.
    #[error("federation pairing material is invalid")]
    Invalid,
}

#[cfg(test)]
mod tests;
