// SPDX-License-Identifier: GPL-2.0-only

//! Convert provider intent into existing immutable grant commands without broadening peer limits.

use super::{PairingError, parse_uuid};
use meshspan_api_contract::{
    FederationStorageGrantChange, FederationStorageGrantLifetime, FederationStorageGrantPolicy,
    NullableField,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    DurationMicros, FederationGrant, FederationGrantId, FederationGrantRoute, FederationPolicy,
    FederationRelationshipId, FederationResourceScope, MeshId, StorageFederationPolicy,
    StorageParticipation, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, FederationGrantRecord,
    FederationGrantRestriction, IssueFederationGrant, ReplaceFederationGrant,
    RevokeFederationGrant,
};

pub(super) fn prepare(
    reader: &AuthoritativeRepository,
    change: &FederationStorageGrantChange,
    now: UnixMicros,
    retry: bool,
) -> Result<(FederationGrantId, AuthoritativeCommand), PairingError> {
    let local = reader
        .local_mesh_id()
        .map_err(|_| PairingError::Unavailable)?
        .ok_or(PairingError::Unavailable)?;
    match change {
        FederationStorageGrantChange::Issue {
            grant_id,
            relationship_id,
            policy,
            valid_for_seconds,
        } => {
            let id = grant_id_from_api(grant_id)?;
            let relationship = FederationRelationshipId::from_bytes(
                parse_uuid(relationship_id.as_str()).map_err(|_| PairingError::Invalid)?,
            )
            .map_err(|_| PairingError::Invalid)?;
            let definition = definition(
                reader,
                &GrantIntent {
                    id,
                    relationship,
                    policy,
                    lifetime: valid_for_seconds,
                    now,
                    retry,
                },
                local,
                None,
            )?;
            Ok((id, AuthoritativeCommand::IssueFederationGrant(definition)))
        }
        FederationStorageGrantChange::Replace {
            predecessor_grant_id,
            grant_id,
            policy,
            valid_for_seconds,
            restricts_authority,
            reason,
        } => {
            let predecessor = owned_grant(reader, grant_id_from_api(predecessor_grant_id)?, local)?;
            let id = grant_id_from_api(grant_id)?;
            let definition = definition(
                reader,
                &GrantIntent {
                    id,
                    relationship: predecessor.grant.relationship_id(),
                    policy,
                    lifetime: valid_for_seconds,
                    now,
                    retry,
                },
                local,
                Some(&predecessor),
            )?;
            Ok((
                id,
                AuthoritativeCommand::ReplaceFederationGrant(ReplaceFederationGrant {
                    predecessor_grant_id: predecessor.grant.grant_id(),
                    grant: definition.grant,
                    restrictions: definition.restrictions,
                    restricts_authority: *restricts_authority,
                    reason: reason.clone(),
                }),
            ))
        }
        FederationStorageGrantChange::Revoke { grant_id, reason } => {
            let id = grant_id_from_api(grant_id)?;
            let record = owned_grant(reader, id, local)?;
            Ok((
                id,
                AuthoritativeCommand::RevokeFederationGrant(RevokeFederationGrant {
                    grant_id: id,
                    expected_authority_epoch: record.grant.authority_epoch(),
                    reason: reason.clone(),
                }),
            ))
        }
    }
}

struct GrantIntent<'a> {
    id: FederationGrantId,
    relationship: FederationRelationshipId,
    policy: &'a FederationStorageGrantPolicy,
    lifetime: &'a NullableField<FederationStorageGrantLifetime>,
    now: UnixMicros,
    retry: bool,
}

fn definition(
    reader: &AuthoritativeRepository,
    intent: &GrantIntent<'_>,
    local: MeshId,
    predecessor: Option<&FederationGrantRecord>,
) -> Result<IssueFederationGrant, PairingError> {
    let relationship = reader
        .federation_relationship(intent.relationship)
        .map_err(|_| PairingError::Unavailable)?
        .ok_or(PairingError::Conflict)?;
    if relationship.local_mesh_id != local {
        return Err(PairingError::Forbidden);
    }
    let restrictions = restrictions(
        local,
        relationship.remote_mesh_id,
        intent.policy,
        predecessor,
    )?;
    let policies = restrictions
        .iter()
        .map(|restriction| restriction.policy)
        .collect::<Vec<_>>();
    let effective = FederationPolicy::intersect(&policies).map_err(|_| PairingError::Invalid)?;
    // An exact retry must bind the original immutable epoch, even if the relationship moved on.
    let epoch = if intent.retry {
        owned_grant(reader, intent.id, local)?
            .grant
            .authority_epoch()
    } else {
        relationship.authority_epoch
    };
    let grant = FederationGrant::new(
        intent.id,
        intent.relationship,
        FederationGrantRoute::direct(local, relationship.remote_mesh_id)
            .map_err(|_| PairingError::Invalid)?,
        None,
        FederationResourceScope::StorageCapacity {
            provider_mesh_id: local,
        },
        effective,
        epoch,
        intent.now,
        expires(intent.now, intent.lifetime)?,
    )
    .map_err(|_| PairingError::Invalid)?;
    Ok(IssueFederationGrant {
        grant,
        restrictions: BoundedItems::new(restrictions, 2).map_err(|_| PairingError::Invalid)?,
    })
}

fn restrictions(
    local: MeshId,
    remote: MeshId,
    policy: &FederationStorageGrantPolicy,
    predecessor: Option<&FederationGrantRecord>,
) -> Result<Vec<FederationGrantRestriction>, PairingError> {
    let bytes = policy
        .maximum_bytes
        .parse::<u64>()
        .map_err(|_| PairingError::Invalid)?;
    if bytes == 0 || bytes > i64::MAX as u64 {
        return Err(PairingError::Invalid);
    }
    let offered = FederationPolicy::Storage(
        StorageFederationPolicy::new(
            bytes,
            StorageParticipation::new(policy.counts_towards_protection, policy.serves_reads),
            policy.allow_downstream_delegation,
            None,
        )
        .map_err(|_| PairingError::Invalid)?,
    );
    let mut restrictions = match predecessor {
        Some(record) => record.restrictions.clone(),
        None => vec![
            FederationGrantRestriction {
                imposing_mesh_id: local,
                policy: offered,
            },
            // Neutral recipient ceiling is not recipient consent or backup configuration.
            // This operation grants use of local provider capacity, never remote file access.
            FederationGrantRestriction {
                imposing_mesh_id: remote,
                policy: FederationPolicy::Storage(
                    StorageFederationPolicy::new(
                        i64::MAX as u64,
                        StorageParticipation::new(true, true),
                        true,
                        None,
                    )
                    .map_err(|_| PairingError::Failed)?,
                ),
            },
        ],
    };
    let own = restrictions
        .iter_mut()
        .find(|restriction| restriction.imposing_mesh_id == local)
        .ok_or(PairingError::Failed)?;
    own.policy = offered;
    Ok(restrictions)
}

pub(super) fn owned_grant(
    reader: &AuthoritativeRepository,
    id: FederationGrantId,
    local: MeshId,
) -> Result<FederationGrantRecord, PairingError> {
    let record = reader
        .federation_grant(id)
        .map_err(|_| PairingError::Unavailable)?
        .ok_or(PairingError::Conflict)?;
    ensure_owned(&record, local)?;
    Ok(record)
}

pub(super) fn ensure_owned(
    record: &FederationGrantRecord,
    local: MeshId,
) -> Result<(), PairingError> {
    if record.grant.issuer_mesh_id() != local
        || record.grant.upstream_grant_id().is_some()
        || record.grant.resource()
            != (FederationResourceScope::StorageCapacity {
                provider_mesh_id: local,
            })
    {
        return Err(PairingError::Forbidden);
    }
    Ok(())
}

pub(super) fn grant_id_from_api(
    id: &meshspan_api_contract::OperationId,
) -> Result<FederationGrantId, PairingError> {
    FederationGrantId::from_bytes(parse_uuid(id.as_str()).map_err(|_| PairingError::Invalid)?)
        .map_err(|_| PairingError::Invalid)
}

fn expires(
    now: UnixMicros,
    value: &NullableField<FederationStorageGrantLifetime>,
) -> Result<Option<UnixMicros>, PairingError> {
    let seconds = match value {
        NullableField::Missing => 30 * 24 * 60 * 60,
        NullableField::Null => return Ok(None),
        NullableField::Value(value) => value.0,
    };
    now.checked_add(DurationMicros::new(u64::from(seconds) * 1_000_000))
        .map(Some)
        .ok_or(PairingError::Invalid)
}
