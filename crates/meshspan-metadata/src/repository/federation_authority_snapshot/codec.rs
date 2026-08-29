// SPDX-License-Identifier: GPL-2.0-only

//! Fixed byte layout for relationship authority snapshots.

use meshspan_domain::{FederationRelationshipId, MeshId, UnixMicros};

use super::{
    FederationAuthoritySnapshotError, decode_direction, decode_kind, decode_owner, decode_state,
    direction_code, kind_code, owner_code, positive_revision, state_code,
};
use crate::{
    FederationIdentityOwner, FederationRelationshipRecord, FederationTransportAuthority,
    FederationTrustIdentity, FederationTrustIdentityRecord,
};

pub(super) const DOMAIN: &[u8] = b"meshspan.federation.relationship-authority";
const FORMAT_VERSION: u8 = 1;
const MAXIMUM_DISPLAY_NAME_BYTES: usize = 256;

pub(super) fn encode(
    authority: &FederationTransportAuthority,
) -> Result<Vec<u8>, FederationAuthoritySnapshotError> {
    let name = authority.relationship.remote_display_name.as_bytes();
    let name_length =
        u16::try_from(name.len()).map_err(|_| FederationAuthoritySnapshotError::Invalid)?;
    let mut bytes = Vec::with_capacity(260_usize.saturating_add(name.len()));
    bytes.extend_from_slice(DOMAIN);
    bytes.push(0);
    bytes.push(FORMAT_VERSION);
    bytes.extend_from_slice(&authority.authority_revision.get().to_be_bytes());
    encode_relationship(&mut bytes, &authority.relationship, name_length);
    encode_identity(&mut bytes, authority.local_identity);
    encode_identity(&mut bytes, authority.remote_identity);
    Ok(bytes)
}

pub(super) fn decode(
    bytes: &[u8],
) -> Result<FederationTransportAuthority, FederationAuthoritySnapshotError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect(DOMAIN)?;
    if decoder.byte()? != 0 {
        return Err(FederationAuthoritySnapshotError::Invalid);
    }
    if decoder.byte()? != FORMAT_VERSION {
        return Err(FederationAuthoritySnapshotError::UnsupportedVersion);
    }
    let authority_revision = positive_revision(decoder.unsigned()?)?;
    let relationship = decode_relationship(&mut decoder)?;
    let local_identity = decode_identity(
        &mut decoder,
        relationship.relationship_id,
        FederationIdentityOwner::Local,
    )?;
    let remote_identity = decode_identity(
        &mut decoder,
        relationship.relationship_id,
        FederationIdentityOwner::Remote,
    )?;
    decoder.finish()?;
    Ok(FederationTransportAuthority {
        authority_revision,
        relationship,
        local_identity,
        remote_identity,
    })
}

fn encode_relationship(
    bytes: &mut Vec<u8>,
    relationship: &FederationRelationshipRecord,
    name_length: u16,
) {
    bytes.extend_from_slice(&relationship.relationship_id.as_bytes());
    bytes.extend_from_slice(&relationship.local_mesh_id.as_bytes());
    bytes.extend_from_slice(&relationship.remote_mesh_id.as_bytes());
    bytes.push(kind_code(relationship.kind));
    bytes.push(direction_code(relationship.governance_direction));
    bytes.push(state_code(relationship.state));
    bytes.extend_from_slice(&relationship.authority_epoch.to_be_bytes());
    bytes.extend_from_slice(&relationship.revision.get().to_be_bytes());
    bytes.extend_from_slice(&name_length.to_be_bytes());
    bytes.extend_from_slice(relationship.remote_display_name.as_bytes());
}

fn encode_identity(bytes: &mut Vec<u8>, record: FederationTrustIdentityRecord) {
    bytes.push(owner_code(record.owner));
    bytes.extend_from_slice(&record.identity.generation.to_be_bytes());
    bytes.extend_from_slice(&record.identity.certificate_fingerprint);
    bytes.extend_from_slice(&record.identity.verifying_key);
    bytes.extend_from_slice(&record.identity.valid_from.get().to_be_bytes());
    bytes.extend_from_slice(&record.identity.valid_until.get().to_be_bytes());
    bytes.extend_from_slice(&record.revision.get().to_be_bytes());
}

fn decode_relationship(
    decoder: &mut Decoder<'_>,
) -> Result<FederationRelationshipRecord, FederationAuthoritySnapshotError> {
    let relationship_id = FederationRelationshipId::from_bytes(decoder.array()?)
        .map_err(|_| FederationAuthoritySnapshotError::Invalid)?;
    let local_mesh_id = MeshId::from_bytes(decoder.array()?)
        .map_err(|_| FederationAuthoritySnapshotError::Invalid)?;
    let remote_mesh_id = MeshId::from_bytes(decoder.array()?)
        .map_err(|_| FederationAuthoritySnapshotError::Invalid)?;
    let kind = decode_kind(decoder.byte()?)?;
    let governance_direction = decode_direction(decoder.byte()?)?;
    let state = decode_state(decoder.byte()?)?;
    let authority_epoch = decoder.unsigned()?;
    let revision = positive_revision(decoder.unsigned()?)?;
    let name_length = usize::from(decoder.short()?);
    if name_length == 0 || name_length > MAXIMUM_DISPLAY_NAME_BYTES {
        return Err(FederationAuthoritySnapshotError::Invalid);
    }
    let remote_display_name = String::from_utf8(decoder.bytes(name_length)?.to_vec())
        .map_err(|_| FederationAuthoritySnapshotError::Invalid)?;
    Ok(FederationRelationshipRecord {
        relationship_id,
        local_mesh_id,
        remote_mesh_id,
        kind,
        governance_direction,
        state,
        authority_epoch,
        remote_display_name,
        revision,
    })
}

fn decode_identity(
    decoder: &mut Decoder<'_>,
    relationship_id: FederationRelationshipId,
    expected_owner: FederationIdentityOwner,
) -> Result<FederationTrustIdentityRecord, FederationAuthoritySnapshotError> {
    if decode_owner(decoder.byte()?)? != expected_owner {
        return Err(FederationAuthoritySnapshotError::Invalid);
    }
    Ok(FederationTrustIdentityRecord {
        relationship_id,
        owner: expected_owner,
        identity: FederationTrustIdentity {
            generation: decoder.unsigned()?,
            certificate_fingerprint: decoder.array()?,
            verifying_key: decoder.array()?,
            valid_from: UnixMicros::new(decoder.signed()?),
            valid_until: UnixMicros::new(decoder.signed()?),
        },
        revision: positive_revision(decoder.unsigned()?)?,
    })
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), FederationAuthoritySnapshotError> {
        if self.bytes(expected.len())? == expected {
            Ok(())
        } else {
            Err(FederationAuthoritySnapshotError::Invalid)
        }
    }

    fn byte(&mut self) -> Result<u8, FederationAuthoritySnapshotError> {
        Ok(self.array::<1>()?[0])
    }

    fn short(&mut self) -> Result<u16, FederationAuthoritySnapshotError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn unsigned(&mut self) -> Result<u64, FederationAuthoritySnapshotError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn signed(&mut self) -> Result<i64, FederationAuthoritySnapshotError> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    fn array<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], FederationAuthoritySnapshotError> {
        self.bytes(LENGTH)?
            .try_into()
            .map_err(|_| FederationAuthoritySnapshotError::Invalid)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], FederationAuthoritySnapshotError> {
        if self.remaining.len() < length {
            return Err(FederationAuthoritySnapshotError::Invalid);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn finish(self) -> Result<(), FederationAuthoritySnapshotError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(FederationAuthoritySnapshotError::Invalid)
        }
    }
}
