// SPDX-License-Identifier: GPL-2.0-only

//! Root-signed delivery of prepared state, distinct from permission to serve that state.

use meshspan_certificates::verify_recovery_signature;
use meshspan_domain::NodeId;

use crate::{RecoveredAuthority, RecoveryAuthorization, RecoveryBundleError as Error};

const MAGIC: &[u8] = b"MSRSTATE\x01";

/// Exact encrypted files delivered to one replacement identity. No path is an authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryStateTransferClaims {
    /// Independently root-authenticated source, replacement plan and verified inventory.
    pub authorization: RecoveryAuthorization,
    /// Selected recipient of both files.
    pub node_id: NodeId,
    /// Selected replacement incarnation, not a certificate generation.
    pub incarnation: u64,
    /// SHA-256 of the entire encrypted metadata/history archive.
    pub state_digest: [u8; 32],
    /// Exact encrypted archive length.
    pub state_length: u64,
    /// SHA-256 of the entire encrypted key and certificate bundle.
    pub key_bundle_digest: [u8; 32],
    /// Exact encrypted key bundle length.
    pub key_bundle_length: u64,
}

impl RecoveryStateTransferClaims {
    fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.incarnation == 0
            || self.incarnation > i64::MAX.unsigned_abs()
            || self.state_digest == [0; 32]
            || self.key_bundle_digest == [0; 32]
            || self.state_length == 0
            || self.key_bundle_length == 0
        {
            return Err(Error::Corrupt);
        }
        let authorization = self.authorization.encode()?;
        let length = u16::try_from(authorization.len()).map_err(|_| Error::Corrupt)?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&authorization);
        bytes.extend_from_slice(&self.node_id.as_bytes());
        bytes.extend_from_slice(&self.incarnation.to_be_bytes());
        bytes.extend_from_slice(&self.state_digest);
        bytes.extend_from_slice(&self.state_length.to_be_bytes());
        bytes.extend_from_slice(&self.key_bundle_digest);
        bytes.extend_from_slice(&self.key_bundle_length.to_be_bytes());
        Ok(bytes)
    }
}

/// Authenticated transfer, never service admission or evidence of available shards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryStateTransfer {
    claims: RecoveryStateTransferClaims,
    signature: Vec<u8>,
}

impl RecoveredAuthority {
    /// Authorises exact prepared files after the coordinator verifies their common source.
    /// # Errors
    /// Rejects another root/swarm, invalid evidence or signing failure.
    pub fn authorize_state_transfer(
        &self,
        claims: RecoveryStateTransferClaims,
    ) -> Result<RecoveryStateTransfer, Error> {
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
        Ok(RecoveryStateTransfer { claims, signature })
    }
}

impl RecoveryStateTransfer {
    /// Exact validated delivery claims; installation must still verify both file streams.
    #[must_use]
    pub const fn claims(&self) -> &RecoveryStateTransferClaims {
        &self.claims
    }

    /// Encodes bounded public delivery evidence without a supplied trust anchor.
    /// # Errors
    /// Rejects invalid in-memory claims or signature length.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = self.claims.canonical_bytes()?;
        let length = u8::try_from(self.signature.len()).map_err(|_| Error::Corrupt)?;
        if length == 0 || length > 72 {
            return Err(Error::Corrupt);
        }
        bytes.push(length);
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    /// Verifies closed framing and both signatures against an independently selected root.
    /// # Errors
    /// Rejects substitution, unknown formats, truncation, excess bytes or invalid claims.
    pub fn decode(root: &[u8], bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 512 || !bytes.starts_with(MAGIC) {
            return Err(Error::Corrupt);
        }
        let mut fields = &bytes[MAGIC.len()..];
        let length = usize::from(u16::from_be_bytes(take(&mut fields)?));
        let (encoded, tail) = fields.split_at_checked(length).ok_or(Error::Corrupt)?;
        let authorization = RecoveryAuthorization::decode(root, encoded)?;
        fields = tail;
        let claims = RecoveryStateTransferClaims {
            authorization,
            node_id: NodeId::from_bytes(take(&mut fields)?).map_err(|_| Error::Corrupt)?,
            incarnation: u64::from_be_bytes(take(&mut fields)?),
            state_digest: take(&mut fields)?,
            state_length: u64::from_be_bytes(take(&mut fields)?),
            key_bundle_digest: take(&mut fields)?,
            key_bundle_length: u64::from_be_bytes(take(&mut fields)?),
        };
        let [length] = take(&mut fields)?;
        if length == 0 || length > 72 || usize::from(length) != fields.len() {
            return Err(Error::Corrupt);
        }
        verify_recovery_signature(root, &claims.canonical_bytes()?, fields)
            .map_err(|_| Error::Certificate)?;
        Ok(Self {
            claims,
            signature: fields.to_vec(),
        })
    }

    /// Node attestation domain; sign only after both verified files are durably installed.
    /// This explicitly does not attest to shard readiness or service admission.
    /// # Errors
    /// Rejects invalid in-memory evidence.
    pub fn installation_message(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = b"MeshSpan recovery state installation v1\0".to_vec();
        bytes.extend_from_slice(&self.encode()?);
        Ok(bytes)
    }
}

fn take<const N: usize>(remaining: &mut &[u8]) -> Result<[u8; N], Error> {
    let (field, tail) = remaining.split_at_checked(N).ok_or(Error::Corrupt)?;
    *remaining = tail;
    field.try_into().map_err(|_| Error::Corrupt)
}
