// SPDX-License-Identifier: GPL-2.0-only

//! Explicit offline-root permission to form a replacement consensus group, not file readiness.

use meshspan_certificates::verify_recovery_signature;

use crate::{RecoveredAuthority, RecoveryAuthorization, RecoveryBundleError as Error};

const MAGIC: &[u8] = b"MSRCNSNS\x01";

/// One common installed state and its exact root-selected replacement authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryConsensusAdmissionClaims {
    /// Source position, recovery epoch, replacement manifest and content inventory.
    pub authorization: RecoveryAuthorization,
    /// SHA-256 of the common encrypted metadata/history archive installed by all selected nodes.
    pub state_digest: [u8; 32],
    /// Exact archive length, independently checked by every installer.
    pub state_length: u64,
}

impl RecoveryConsensusAdmissionClaims {
    fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.state_digest == [0; 32] || self.state_length == 0 {
            return Err(Error::Corrupt);
        }
        let authorization = self.authorization.encode()?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(
            &u16::try_from(authorization.len())
                .map_err(|_| Error::Corrupt)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&authorization);
        bytes.extend_from_slice(&self.state_digest);
        bytes.extend_from_slice(&self.state_length.to_be_bytes());
        Ok(bytes)
    }
}

/// Signed permission to install the replacement consensus epoch on this exact candidate.
/// Receivers must still validate projected identities, membership, keys and source history.
/// This does not assert current reachability, storage protection or HTTPS/SMB readiness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryConsensusAdmission {
    claims: RecoveryConsensusAdmissionClaims,
    signature: Vec<u8>,
}

impl RecoveredAuthority {
    /// Signs consensus permission after the coordinator verifies every selected installation.
    /// The coordinator must durably retain one decision and reject competing state sets.
    /// # Errors
    /// Rejects another root/swarm, invalid claims or signing failure.
    pub fn authorize_recovery_consensus(
        &self,
        claims: RecoveryConsensusAdmissionClaims,
    ) -> Result<RecoveryConsensusAdmission, Error> {
        RecoveryAuthorization::decode(
            self.root_certificate_der(),
            &claims.authorization.encode()?,
        )?;
        if claims.authorization.claims().mesh_id != self.mesh_id() {
            return Err(Error::Corrupt);
        }
        let signature = self
            .root_authority
            .sign_recovery_manifest(&claims.canonical_bytes()?)
            .map_err(|_| Error::Certificate)?;
        Ok(RecoveryConsensusAdmission { claims, signature })
    }
}

impl RecoveryConsensusAdmission {
    /// Exact authenticated recovery source and common state, never implicit file readiness.
    #[must_use]
    pub const fn claims(&self) -> &RecoveryConsensusAdmissionClaims {
        &self.claims
    }

    /// Encodes the bounded, domain-separated public permission.
    /// # Errors
    /// Rejects malformed in-memory claims or signature lengths.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = self.claims.canonical_bytes()?;
        let length = u8::try_from(self.signature.len()).map_err(|_| Error::Corrupt)?;
        if !(8..=72).contains(&length) {
            return Err(Error::Corrupt);
        }
        bytes.push(length);
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    /// Verifies both root signatures and exact framing against an independent trust anchor.
    /// # Errors
    /// Rejects other message types, changed bytes, foreign roots and malformed/excess input.
    pub fn decode(root: &[u8], bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 512 || !bytes.starts_with(MAGIC) {
            return Err(Error::Corrupt);
        }
        let mut fields = &bytes[MAGIC.len()..];
        let length = usize::from(u16::from_be_bytes(take(&mut fields)?));
        let (encoded, tail) = fields.split_at_checked(length).ok_or(Error::Corrupt)?;
        let authorization = RecoveryAuthorization::decode(root, encoded)?;
        fields = tail;
        let claims = RecoveryConsensusAdmissionClaims {
            authorization,
            state_digest: take(&mut fields)?,
            state_length: u64::from_be_bytes(take(&mut fields)?),
        };
        let [length] = take(&mut fields)?;
        if !(8..=72).contains(&length) || usize::from(length) != fields.len() {
            return Err(Error::Corrupt);
        }
        verify_recovery_signature(root, &claims.canonical_bytes()?, fields)
            .map_err(|_| Error::Certificate)?;
        Ok(Self {
            claims,
            signature: fields.to_vec(),
        })
    }
}

fn take<const N: usize>(remaining: &mut &[u8]) -> Result<[u8; N], Error> {
    let (field, tail) = remaining.split_at_checked(N).ok_or(Error::Corrupt)?;
    *remaining = tail;
    field.try_into().map_err(|_| Error::Corrupt)
}
