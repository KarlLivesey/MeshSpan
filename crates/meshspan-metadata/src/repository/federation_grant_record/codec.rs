// SPDX-License-Identifier: GPL-2.0-only

//! Fixed byte layout for complete federation grant authority records.

use meshspan_domain::{
    DurationMicros, FederatedPrincipal, FederationAccess, FederationGrant, FederationGrantId,
    FederationPolicy, FederationRelationshipId, FederationResourceScope, MeshId,
    NamespaceFederationPolicy, ObjectId, PrincipalId, Revision, Rights, StorageFederationPolicy,
    StorageParticipation, UnixMicros, VolumeId,
};

use super::FederationGrantRecordCodecError;
use crate::{
    FederationGrantRecord, FederationGrantRestriction, FederationGrantState,
    FederationGrantTermination, FederationGrantTerminationKind,
};

const DOMAIN: &[u8] = b"meshspan.federation.grant-authority";
const FORMAT_VERSION: u8 = 1;
const MAXIMUM_RESTRICTIONS: usize = 64;
const MAXIMUM_REASON_BYTES: usize = 512;

pub(super) fn encode(
    record: &FederationGrantRecord,
) -> Result<Vec<u8>, FederationGrantRecordCodecError> {
    let mut bytes = Vec::with_capacity(256_usize.saturating_add(record.restrictions.len() * 48));
    bytes.extend_from_slice(DOMAIN);
    bytes.push(0);
    bytes.push(FORMAT_VERSION);
    bytes.extend_from_slice(&record.revision.get().to_be_bytes());
    encode_grant(&mut bytes, record.grant);
    bytes.push(state_code(record.state));
    bytes.extend_from_slice(&record.issued_at.get().to_be_bytes());
    encode_termination(&mut bytes, record.termination.as_ref())?;
    encode_optional_id(&mut bytes, record.predecessor_grant_id);
    encode_optional_id(&mut bytes, record.successor_grant_id);
    let count = u16::try_from(record.restrictions.len())
        .map_err(|_| FederationGrantRecordCodecError::Invalid)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for restriction in &record.restrictions {
        bytes.extend_from_slice(&restriction.imposing_mesh_id.as_bytes());
        encode_policy(&mut bytes, restriction.policy);
    }
    Ok(bytes)
}

pub(super) fn decode(
    bytes: &[u8],
) -> Result<FederationGrantRecord, FederationGrantRecordCodecError> {
    let mut decoder = Decoder::new(bytes);
    decoder.expect(DOMAIN)?;
    if decoder.byte()? != 0 {
        return Err(FederationGrantRecordCodecError::Invalid);
    }
    if decoder.byte()? != FORMAT_VERSION {
        return Err(FederationGrantRecordCodecError::UnsupportedVersion);
    }
    let revision = positive_revision(decoder.unsigned()?)?;
    let grant = decode_grant(&mut decoder)?;
    let state = decode_state(decoder.byte()?)?;
    let issued_at = UnixMicros::new(decoder.signed()?);
    let termination = decode_termination(&mut decoder)?;
    let predecessor_grant_id = decode_optional_id(&mut decoder)?;
    let successor_grant_id = decode_optional_id(&mut decoder)?;
    let restriction_count = usize::from(decoder.short()?);
    if !(2..=MAXIMUM_RESTRICTIONS).contains(&restriction_count) {
        return Err(FederationGrantRecordCodecError::Invalid);
    }
    let mut restrictions = Vec::with_capacity(restriction_count);
    for _ in 0..restriction_count {
        restrictions.push(FederationGrantRestriction {
            imposing_mesh_id: decode_mesh(&mut decoder)?,
            policy: decode_policy(&mut decoder)?,
        });
    }
    decoder.finish()?;
    Ok(FederationGrantRecord {
        grant,
        restrictions,
        state,
        issued_at,
        termination,
        predecessor_grant_id,
        successor_grant_id,
        revision,
    })
}

fn encode_grant(bytes: &mut Vec<u8>, grant: FederationGrant) {
    bytes.extend_from_slice(&grant.grant_id().as_bytes());
    bytes.extend_from_slice(&grant.relationship_id().as_bytes());
    bytes.extend_from_slice(&grant.subject().home_mesh_id().as_bytes());
    bytes.extend_from_slice(&grant.subject().principal_id().as_bytes());
    encode_resource(bytes, grant.resource());
    encode_policy(bytes, grant.policy());
    bytes.extend_from_slice(&grant.authority_epoch().to_be_bytes());
    bytes.extend_from_slice(&grant.valid_from().get().to_be_bytes());
    encode_optional_time(bytes, grant.valid_until());
}

fn decode_grant(
    decoder: &mut Decoder<'_>,
) -> Result<FederationGrant, FederationGrantRecordCodecError> {
    let grant_id = decode_grant_id(decoder)?;
    let relationship_id = decode_relationship(decoder)?;
    let subject = FederatedPrincipal::new(decode_mesh(decoder)?, decode_principal(decoder)?);
    let resource = decode_resource(decoder)?;
    let policy = decode_policy(decoder)?;
    let authority_epoch = decoder.unsigned()?;
    let valid_from = UnixMicros::new(decoder.signed()?);
    let valid_until = decode_optional_time(decoder)?;
    FederationGrant::new(
        grant_id,
        relationship_id,
        subject,
        resource,
        policy,
        authority_epoch,
        valid_from,
        valid_until,
    )
    .map_err(|_| FederationGrantRecordCodecError::Invalid)
}

fn encode_resource(bytes: &mut Vec<u8>, resource: FederationResourceScope) {
    match resource {
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&owner_mesh_id.as_bytes());
            bytes.extend_from_slice(&volume_id.as_bytes());
        }
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&owner_mesh_id.as_bytes());
            bytes.extend_from_slice(&volume_id.as_bytes());
            bytes.extend_from_slice(&root_object_id.as_bytes());
        }
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(&owner_mesh_id.as_bytes());
            bytes.extend_from_slice(&volume_id.as_bytes());
            bytes.extend_from_slice(&object_id.as_bytes());
        }
        FederationResourceScope::StorageCapacity { provider_mesh_id } => {
            bytes.push(4);
            bytes.extend_from_slice(&provider_mesh_id.as_bytes());
        }
    }
}

fn decode_resource(
    decoder: &mut Decoder<'_>,
) -> Result<FederationResourceScope, FederationGrantRecordCodecError> {
    match decoder.byte()? {
        1 => Ok(FederationResourceScope::Volume {
            owner_mesh_id: decode_mesh(decoder)?,
            volume_id: decode_volume(decoder)?,
        }),
        2 => Ok(FederationResourceScope::Subtree {
            owner_mesh_id: decode_mesh(decoder)?,
            volume_id: decode_volume(decoder)?,
            root_object_id: decode_object(decoder)?,
        }),
        3 => Ok(FederationResourceScope::File {
            owner_mesh_id: decode_mesh(decoder)?,
            volume_id: decode_volume(decoder)?,
            object_id: decode_object(decoder)?,
        }),
        4 => Ok(FederationResourceScope::StorageCapacity {
            provider_mesh_id: decode_mesh(decoder)?,
        }),
        _ => Err(FederationGrantRecordCodecError::Invalid),
    }
}

fn encode_policy(bytes: &mut Vec<u8>, policy: FederationPolicy) {
    match policy {
        FederationPolicy::Namespace(policy) => {
            bytes.push(1);
            bytes.extend_from_slice(&policy.access().rights().bits().to_be_bytes());
            bytes.push(u8::from(policy.access().allows_downstream_delegation()));
            encode_optional_duration(bytes, policy.maximum_offline_duration());
        }
        FederationPolicy::Storage(policy) => {
            bytes.push(2);
            bytes.extend_from_slice(&policy.maximum_storage_bytes().to_be_bytes());
            bytes.push(u8::from(policy.participation().counts_towards_protection()));
            bytes.push(u8::from(policy.participation().serves_reads()));
            encode_optional_duration(bytes, policy.maximum_offline_duration());
        }
    }
}

fn decode_policy(
    decoder: &mut Decoder<'_>,
) -> Result<FederationPolicy, FederationGrantRecordCodecError> {
    match decoder.byte()? {
        1 => {
            let rights = Rights::from_bits(decoder.long()?)
                .map_err(|_| FederationGrantRecordCodecError::Invalid)?;
            let allows_downstream_delegation = decoder.boolean()?;
            let offline = decode_optional_duration(decoder)?;
            Ok(FederationPolicy::Namespace(NamespaceFederationPolicy::new(
                FederationAccess::new(rights, allows_downstream_delegation),
                offline,
            )))
        }
        2 => StorageFederationPolicy::new(
            decoder.unsigned()?,
            StorageParticipation::new(decoder.boolean()?, decoder.boolean()?),
            decode_optional_duration(decoder)?,
        )
        .map(FederationPolicy::Storage)
        .map_err(|_| FederationGrantRecordCodecError::Invalid),
        _ => Err(FederationGrantRecordCodecError::Invalid),
    }
}

fn encode_termination(
    bytes: &mut Vec<u8>,
    termination: Option<&FederationGrantTermination>,
) -> Result<(), FederationGrantRecordCodecError> {
    let Some(termination) = termination else {
        bytes.push(0);
        return Ok(());
    };
    bytes.push(1);
    bytes.push(termination_kind_code(termination.kind));
    match termination.reason.as_deref() {
        None => bytes.push(0),
        Some(reason) => {
            bytes.push(1);
            let length = u16::try_from(reason.len())
                .map_err(|_| FederationGrantRecordCodecError::Invalid)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(reason.as_bytes());
        }
    }
    bytes.extend_from_slice(&termination.terminated_at.get().to_be_bytes());
    bytes.extend_from_slice(&termination.revision.get().to_be_bytes());
    Ok(())
}

fn decode_termination(
    decoder: &mut Decoder<'_>,
) -> Result<Option<FederationGrantTermination>, FederationGrantRecordCodecError> {
    if !decoder.boolean()? {
        return Ok(None);
    }
    let kind = decode_termination_kind(decoder.byte()?)?;
    let reason = if decoder.boolean()? {
        let length = usize::from(decoder.short()?);
        if length == 0 || length > MAXIMUM_REASON_BYTES {
            return Err(FederationGrantRecordCodecError::Invalid);
        }
        Some(
            String::from_utf8(decoder.bytes(length)?.to_vec())
                .map_err(|_| FederationGrantRecordCodecError::Invalid)?,
        )
    } else {
        None
    };
    Ok(Some(FederationGrantTermination {
        kind,
        reason,
        terminated_at: UnixMicros::new(decoder.signed()?),
        revision: positive_revision(decoder.unsigned()?)?,
    }))
}

fn encode_optional_id(bytes: &mut Vec<u8>, value: Option<FederationGrantId>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.as_bytes());
        }
        None => bytes.push(0),
    }
}

fn decode_optional_id(
    decoder: &mut Decoder<'_>,
) -> Result<Option<FederationGrantId>, FederationGrantRecordCodecError> {
    if decoder.boolean()? {
        decode_grant_id(decoder).map(Some)
    } else {
        Ok(None)
    }
}

fn encode_optional_time(bytes: &mut Vec<u8>, value: Option<UnixMicros>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.get().to_be_bytes());
        }
        None => bytes.push(0),
    }
}

fn decode_optional_time(
    decoder: &mut Decoder<'_>,
) -> Result<Option<UnixMicros>, FederationGrantRecordCodecError> {
    if decoder.boolean()? {
        Ok(Some(UnixMicros::new(decoder.signed()?)))
    } else {
        Ok(None)
    }
}

fn encode_optional_duration(bytes: &mut Vec<u8>, value: Option<DurationMicros>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.get().to_be_bytes());
        }
        None => bytes.push(0),
    }
}

fn decode_optional_duration(
    decoder: &mut Decoder<'_>,
) -> Result<Option<DurationMicros>, FederationGrantRecordCodecError> {
    if decoder.boolean()? {
        Ok(Some(DurationMicros::new(decoder.unsigned()?)))
    } else {
        Ok(None)
    }
}

const fn state_code(state: FederationGrantState) -> u8 {
    match state {
        FederationGrantState::Active => 1,
        FederationGrantState::Revoked => 2,
    }
}

fn decode_state(value: u8) -> Result<FederationGrantState, FederationGrantRecordCodecError> {
    match value {
        1 => Ok(FederationGrantState::Active),
        2 => Ok(FederationGrantState::Revoked),
        _ => Err(FederationGrantRecordCodecError::Invalid),
    }
}

const fn termination_kind_code(kind: FederationGrantTerminationKind) -> u8 {
    match kind {
        FederationGrantTerminationKind::Revoked => 1,
        FederationGrantTerminationKind::Renewed => 2,
        FederationGrantTerminationKind::Restricted => 3,
        FederationGrantTerminationKind::LegacyReasonUnknown => 4,
    }
}

fn decode_termination_kind(
    value: u8,
) -> Result<FederationGrantTerminationKind, FederationGrantRecordCodecError> {
    match value {
        1 => Ok(FederationGrantTerminationKind::Revoked),
        2 => Ok(FederationGrantTerminationKind::Renewed),
        3 => Ok(FederationGrantTerminationKind::Restricted),
        4 => Ok(FederationGrantTerminationKind::LegacyReasonUnknown),
        _ => Err(FederationGrantRecordCodecError::Invalid),
    }
}

fn positive_revision(value: u64) -> Result<Revision, FederationGrantRecordCodecError> {
    if value == 0 {
        Err(FederationGrantRecordCodecError::Invalid)
    } else {
        Ok(Revision::new(value))
    }
}

fn decode_mesh(decoder: &mut Decoder<'_>) -> Result<MeshId, FederationGrantRecordCodecError> {
    MeshId::from_bytes(decoder.array()?).map_err(|_| FederationGrantRecordCodecError::Invalid)
}

fn decode_principal(
    decoder: &mut Decoder<'_>,
) -> Result<PrincipalId, FederationGrantRecordCodecError> {
    PrincipalId::from_bytes(decoder.array()?).map_err(|_| FederationGrantRecordCodecError::Invalid)
}

fn decode_grant_id(
    decoder: &mut Decoder<'_>,
) -> Result<FederationGrantId, FederationGrantRecordCodecError> {
    FederationGrantId::from_bytes(decoder.array()?)
        .map_err(|_| FederationGrantRecordCodecError::Invalid)
}

fn decode_relationship(
    decoder: &mut Decoder<'_>,
) -> Result<FederationRelationshipId, FederationGrantRecordCodecError> {
    FederationRelationshipId::from_bytes(decoder.array()?)
        .map_err(|_| FederationGrantRecordCodecError::Invalid)
}

fn decode_volume(decoder: &mut Decoder<'_>) -> Result<VolumeId, FederationGrantRecordCodecError> {
    VolumeId::from_bytes(decoder.array()?).map_err(|_| FederationGrantRecordCodecError::Invalid)
}

fn decode_object(decoder: &mut Decoder<'_>) -> Result<ObjectId, FederationGrantRecordCodecError> {
    ObjectId::from_bytes(decoder.array()?).map_err(|_| FederationGrantRecordCodecError::Invalid)
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), FederationGrantRecordCodecError> {
        if self.bytes(expected.len())? == expected {
            Ok(())
        } else {
            Err(FederationGrantRecordCodecError::Invalid)
        }
    }

    fn byte(&mut self) -> Result<u8, FederationGrantRecordCodecError> {
        Ok(self.array::<1>()?[0])
    }

    fn boolean(&mut self) -> Result<bool, FederationGrantRecordCodecError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(FederationGrantRecordCodecError::Invalid),
        }
    }

    fn short(&mut self) -> Result<u16, FederationGrantRecordCodecError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn long(&mut self) -> Result<u32, FederationGrantRecordCodecError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn unsigned(&mut self) -> Result<u64, FederationGrantRecordCodecError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn signed(&mut self) -> Result<i64, FederationGrantRecordCodecError> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    fn array<const LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; LENGTH], FederationGrantRecordCodecError> {
        self.bytes(LENGTH)?
            .try_into()
            .map_err(|_| FederationGrantRecordCodecError::Invalid)
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], FederationGrantRecordCodecError> {
        if self.remaining.len() < length {
            return Err(FederationGrantRecordCodecError::Invalid);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn finish(self) -> Result<(), FederationGrantRecordCodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(FederationGrantRecordCodecError::Invalid)
        }
    }
}
