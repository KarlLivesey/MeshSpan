// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, FederatedMutationAdmission, FederatedMutationEvidence, FederatedPrincipal,
    FederationGrant, FederationGrantId, FederationGrantRoute, FederationPolicy,
    FederationRelationshipId, FederationRelationshipKind, FederationResourceScope, HostId, MeshId,
    NodeId, OperationId, PartitionId, PrincipalId, QuarantineReason, Revision, RoleId,
    StorageFederationPolicy, StorageParticipation, UnixMicros,
};
use tempfile::tempdir;

use super::{AuthoritativeRepository, LogPosition, RepositoryError, federation_grant};
use crate::{
    ApproveFederationRelationship, AuthoritativeCommand, BootstrapMesh, CommandContext,
    FederationGovernanceDirection, FederationGrantRestriction, FederationTrustIdentity,
    IssueFederationGrant, PartitionDatabase, ProposeFederationRelationship, RecordName,
    RevokeFederationGrant,
};

#[test]
fn upstream_revocation_quarantines_later_downstream_work_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let database_path = directory.path().join("downstream.sqlite3");
    let ids = Ids::new()?;
    let mut repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &database_path,
        ids.partition,
        UnixMicros::new(0),
    )?);
    bootstrap_and_connect(&mut repository, ids)?;
    issue_chain(&mut repository, ids)?;

    assert_eq!(
        classify(&repository, ids, 9)?,
        FederatedMutationAdmission::Admitted
    );
    apply(
        &mut repository,
        8,
        10,
        ids.administrator,
        &AuthoritativeCommand::RevokeFederationGrant(RevokeFederationGrant {
            grant_id: ids.upstream_grant,
            expected_authority_epoch: 1,
            reason: "Owner withdrew downstream edit authority".to_owned(),
        }),
    )?;
    assert_eq!(
        classify(&repository, ids, 11)?,
        FederatedMutationAdmission::Quarantined(QuarantineReason::Revoked)
    );
    assert_eq!(
        classify(&repository, ids, 9)?,
        FederatedMutationAdmission::Admitted
    );
    drop(repository);

    let reopened = AuthoritativeRepository::new(PartitionDatabase::open(
        &database_path,
        ids.partition,
        UnixMicros::new(12),
    )?);
    assert_eq!(
        classify(&reopened, ids, 11)?,
        FederatedMutationAdmission::Quarantined(QuarantineReason::Revoked)
    );
    Ok(())
}

fn bootstrap_and_connect(
    repository: &mut AuthoritativeRepository,
    ids: Ids,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        1,
        ids.administrator,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: ids.intermediary,
            mesh_name: RecordName::new("Intermediary swarm")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([30; 16])?,
            host_id: HostId::from_bytes([31; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([32; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    connect(repository, ids, ids.owner_relationship, ids.owner, 2, 3)?;
    connect(
        repository,
        ids,
        ids.recipient_relationship,
        ids.recipient,
        4,
        5,
    )
}

fn connect(
    repository: &mut AuthoritativeRepository,
    ids: Ids,
    relationship_id: FederationRelationshipId,
    remote_mesh_id: MeshId,
    propose_index: u64,
    approve_index: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        propose_index,
        i64::try_from(propose_index)?,
        ids.administrator,
        &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id,
            remote_mesh_id,
            remote_name: RecordName::new("Federated peer")?,
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
        }),
    )?;
    apply(
        repository,
        approve_index,
        i64::try_from(approve_index)?,
        ids.administrator,
        &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
            relationship_id,
            expected_authority_epoch: 1,
            local_identity: identity(40_u8.saturating_add(u8::try_from(approve_index)?)),
            remote_identity: identity(50_u8.saturating_add(u8::try_from(approve_index)?)),
            governance_proof: None,
        }),
    )?;
    Ok(())
}

fn issue_chain(
    repository: &mut AuthoritativeRepository,
    ids: Ids,
) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_policy = policy(100, true)?;
    issue(
        repository,
        6,
        6,
        ids.administrator,
        FederationGrant::new(
            ids.upstream_grant,
            ids.owner_relationship,
            FederationGrantRoute::direct(ids.owner, ids.intermediary)?,
            None,
            resource(ids),
            upstream_policy,
            1,
            UnixMicros::new(6),
            Some(UnixMicros::new(20)),
        )?,
        restrictions(&[
            (ids.owner, upstream_policy),
            (ids.intermediary, upstream_policy),
        ])?,
    )?;
    let child_policy = policy(50, false)?;
    issue(
        repository,
        7,
        7,
        ids.administrator,
        FederationGrant::new(
            ids.child_grant,
            ids.recipient_relationship,
            FederationGrantRoute::from_meshes(vec![ids.owner, ids.intermediary, ids.recipient])?,
            Some(ids.upstream_grant),
            resource(ids),
            child_policy,
            1,
            UnixMicros::new(7),
            Some(UnixMicros::new(20)),
        )?,
        restrictions(&[
            (ids.owner, child_policy),
            (ids.intermediary, child_policy),
            (ids.recipient, child_policy),
        ])?,
    )
}

fn issue(
    repository: &mut AuthoritativeRepository,
    index: u64,
    occurred_at: i64,
    actor: PrincipalId,
    grant: FederationGrant,
    restrictions: BoundedItems<FederationGrantRestriction>,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        index,
        occurred_at,
        actor,
        &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
            grant,
            restrictions,
        }),
    )?;
    Ok(())
}

fn classify(
    repository: &AuthoritativeRepository,
    ids: Ids,
    accepted_at: i64,
) -> Result<FederatedMutationAdmission, RepositoryError> {
    federation_grant::classify_persisted_mutation(
        repository.database.connection(),
        FederatedMutationEvidence::new(
            ids.child_grant,
            ids.recipient_relationship,
            FederatedPrincipal::new(ids.recipient, ids.recipient_user),
            resource(ids),
            1,
            UnixMicros::new(accepted_at),
            meshspan_domain::Rights::default(),
            10,
        ),
    )
}

fn resource(ids: Ids) -> FederationResourceScope {
    FederationResourceScope::StorageCapacity {
        provider_mesh_id: ids.owner,
    }
}

fn policy(
    maximum_bytes: u64,
    allows_downstream: bool,
) -> Result<FederationPolicy, Box<dyn std::error::Error>> {
    Ok(FederationPolicy::Storage(StorageFederationPolicy::new(
        maximum_bytes,
        StorageParticipation::new(true, true),
        allows_downstream,
        None,
    )?))
}

fn restrictions(
    values: &[(MeshId, FederationPolicy)],
) -> Result<BoundedItems<FederationGrantRestriction>, Box<dyn std::error::Error>> {
    let mut restrictions = values
        .iter()
        .map(|(imposing_mesh_id, policy)| FederationGrantRestriction {
            imposing_mesh_id: *imposing_mesh_id,
            policy: *policy,
        })
        .collect::<Vec<_>>();
    restrictions.sort_by_key(|restriction| restriction.imposing_mesh_id);
    Ok(BoundedItems::new(restrictions, values.len())?)
}

fn identity(seed: u8) -> FederationTrustIdentity {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    FederationTrustIdentity {
        generation: 1,
        certificate_fingerprint: [seed; 32],
        verifying_key: key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(100),
    }
}

fn apply(
    repository: &mut AuthoritativeRepository,
    index: u64,
    occurred_at: i64,
    actor: PrincipalId,
    command: &AuthoritativeCommand,
) -> Result<(), RepositoryError> {
    let seed = u8::try_from(index).map_err(|_| RepositoryError::InvalidCommand)?;
    repository.apply_committed(
        LogPosition { index, term: 1 },
        CommandContext {
            operation_id: OperationId::from_bytes([seed; 16])
                .map_err(|_| RepositoryError::InvalidCommand)?,
            actor_principal_id: actor,
            audit_event_id: AuditEventId::from_bytes([100_u8.saturating_add(seed); 16])
                .map_err(|_| RepositoryError::InvalidCommand)?,
            occurred_at: UnixMicros::new(occurred_at),
            expected_revision: Some(Revision::new(index.saturating_sub(1))),
        },
        command,
    )?;
    Ok(())
}

#[derive(Clone, Copy)]
struct Ids {
    administrator: PrincipalId,
    recipient_user: PrincipalId,
    partition: PartitionId,
    owner: MeshId,
    intermediary: MeshId,
    recipient: MeshId,
    owner_relationship: FederationRelationshipId,
    recipient_relationship: FederationRelationshipId,
    upstream_grant: FederationGrantId,
    child_grant: FederationGrantId,
}

impl Ids {
    fn new() -> Result<Self, meshspan_domain::IdentifierError> {
        Ok(Self {
            administrator: PrincipalId::from_bytes([1; 16])?,
            recipient_user: PrincipalId::from_bytes([2; 16])?,
            partition: PartitionId::from_bytes([3; 16])?,
            owner: MeshId::from_bytes([4; 16])?,
            intermediary: MeshId::from_bytes([5; 16])?,
            recipient: MeshId::from_bytes([6; 16])?,
            owner_relationship: FederationRelationshipId::from_bytes([7; 16])?,
            recipient_relationship: FederationRelationshipId::from_bytes([8; 16])?,
            upstream_grant: FederationGrantId::from_bytes([9; 16])?,
            child_grant: FederationGrantId::from_bytes([10; 16])?,
        })
    }
}
