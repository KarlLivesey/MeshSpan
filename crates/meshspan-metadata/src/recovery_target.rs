// SPDX-License-Identifier: GPL-2.0-only

//! Node-attested replacement-folder identity; neither active membership nor a shard receipt.

use meshspan_domain::{NodeId, OperationId, TargetId};
use meshspan_recovery_bundle::RecoveryAuthorization;

use crate::{RepositoryError as Error, StorageUsageLimit};

const MAGIC: &[u8] = b"MSRTARGET\x01";

/// Exact probed replacement target proposed by a selected recovery node.
/// Local folder paths never enter this portable record or replicated metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedRecoveryTarget {
    /// Offline-root-signed preparation to which this local work belongs.
    pub authorization: RecoveryAuthorization,
    /// Selected node whose private identity signs the report.
    pub node_id: NodeId,
    /// Exact selected replacement incarnation.
    pub incarnation: u64,
    /// Stable user-requested preparation identity.
    pub operation_id: OperationId,
    /// Fresh target, not an alias for an old backup target.
    pub target_id: TargetId,
    /// Initial physical generation; fresh replacement targets start at one.
    pub generation: u64,
    /// Fingerprint of the durably installed, capability-probed target marker.
    pub marker_fingerprint: [u8; 32],
    /// Explicit capacity ceiling; not an observation of currently available bytes.
    pub usage_limit: StorageUsageLimit,
}

impl PreparedRecoveryTarget {
    /// Canonical, domain-separated node-attestation message.
    /// # Errors
    /// Rejects malformed authorisation, generation, fingerprint or capacity bounds.
    pub fn installation_message(&self) -> Result<Vec<u8>, Error> {
        self.usage_limit
            .validate()
            .map_err(|_| Error::InvalidCommand)?;
        if self.incarnation == 0
            || self.incarnation > i64::MAX.unsigned_abs()
            || self.generation != 1
            || self.marker_fingerprint == [0; 32]
        {
            return Err(Error::InvalidCommand);
        }
        let authorization = self
            .authorization
            .encode()
            .map_err(|_| Error::InvalidCommand)?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(
            &u16::try_from(authorization.len())
                .map_err(|_| Error::InvalidCommand)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&authorization);
        bytes.extend_from_slice(&self.node_id.as_bytes());
        bytes.extend_from_slice(&self.incarnation.to_be_bytes());
        bytes.extend_from_slice(&self.operation_id.as_bytes());
        bytes.extend_from_slice(&self.target_id.as_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.marker_fingerprint);
        let (kind, value) = match self.usage_limit {
            StorageUsageLimit::Percent(value) => (1, u64::from(value)),
            StorageUsageLimit::Bytes(value) => (2, value),
        };
        bytes.push(kind);
        bytes.extend_from_slice(&value.to_be_bytes());
        Ok(bytes)
    }

    /// Encodes claims and a bounded DER node signature. This does not verify that signature.
    /// # Errors
    /// Rejects invalid claims or signature length.
    pub fn encode_report(&self, signature: &[u8]) -> Result<Vec<u8>, Error> {
        if !(8..=72).contains(&signature.len()) {
            return Err(Error::InvalidCommand);
        }
        let mut bytes = self.installation_message()?;
        bytes.push(u8::try_from(signature.len()).map_err(|_| Error::InvalidCommand)?);
        bytes.extend_from_slice(signature);
        Ok(bytes)
    }

    /// Decodes a closed report and validates its original authorisation against an independent root.
    /// The coordinator must still verify the node signature and exact selected-node/target scope.
    /// # Errors
    /// Rejects excessive, malformed, noncanonical, truncated or trailing bytes and another root.
    pub fn decode_report(root: &[u8], bytes: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        if bytes.len() > 512 {
            return Err(Error::InvalidCommand);
        }
        let (record, mut remaining) = Self::decode_prefix(root, bytes)?;
        let [length] = take(&mut remaining)?;
        if !(8..=72).contains(&length) || usize::from(length) != remaining.len() {
            return Err(Error::InvalidCommand);
        }
        Ok((record, remaining.to_vec()))
    }

    pub(crate) fn decode_prefix<'a>(
        root: &[u8],
        bytes: &'a [u8],
    ) -> Result<(Self, &'a [u8]), Error> {
        if !bytes.starts_with(MAGIC) {
            return Err(Error::InvalidCommand);
        }
        let mut remaining = &bytes[MAGIC.len()..];
        let length = usize::from(u16::from_be_bytes(take(&mut remaining)?));
        let (encoded, tail) = remaining
            .split_at_checked(length)
            .ok_or(Error::InvalidCommand)?;
        let authorization =
            RecoveryAuthorization::decode(root, encoded).map_err(|_| Error::InvalidCommand)?;
        remaining = tail;
        let node_id =
            NodeId::from_bytes(take(&mut remaining)?).map_err(|_| Error::InvalidCommand)?;
        let incarnation = u64::from_be_bytes(take(&mut remaining)?);
        let operation_id =
            OperationId::from_bytes(take(&mut remaining)?).map_err(|_| Error::InvalidCommand)?;
        let target_id =
            TargetId::from_bytes(take(&mut remaining)?).map_err(|_| Error::InvalidCommand)?;
        let generation = u64::from_be_bytes(take(&mut remaining)?);
        let marker_fingerprint = take(&mut remaining)?;
        let [kind] = take(&mut remaining)?;
        let value = u64::from_be_bytes(take(&mut remaining)?);
        let usage_limit = match kind {
            1 => {
                StorageUsageLimit::Percent(u8::try_from(value).map_err(|_| Error::InvalidCommand)?)
            }
            2 => StorageUsageLimit::Bytes(value),
            _ => return Err(Error::InvalidCommand),
        };
        let record = Self {
            authorization,
            node_id,
            incarnation,
            operation_id,
            target_id,
            generation,
            marker_fingerprint,
            usage_limit,
        };
        record.installation_message()?;
        Ok((record, remaining))
    }
}

pub(crate) fn take<const N: usize>(remaining: &mut &[u8]) -> Result<[u8; N], Error> {
    let (field, tail) = remaining.split_at_checked(N).ok_or(Error::InvalidCommand)?;
    *remaining = tail;
    field.try_into().map_err(|_| Error::InvalidCommand)
}
