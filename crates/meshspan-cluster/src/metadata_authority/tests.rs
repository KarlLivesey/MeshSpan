// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};

use meshspan_consensus::{ConsensusCore, CoreConfig, MemberIncarnations, compile_plan, flat_plan};
use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, HostId, MeshId, PartitionId, PrincipalId,
    QuorumPlanId, Revision, RoleId,
};
use meshspan_metadata::{
    BootstrapAppliance, BootstrapMesh, CreateAuthenticationMethod, NewAuthenticationCredential,
    PartitionDatabase, RecordName,
};

use super::*;

#[tokio::test]
async fn single_owner_returns_only_a_durable_exact_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = NodeId::from_bytes([1; 16])?;
    let driver = driver(&directory.path().join("authority.sqlite3"), local)?;
    let transport: Arc<dyn ConsensusMessageTransport> = Arc::new(|_, _| {});
    let (authority, runtime) =
        spawn_metadata_authority(driver, transport, MetadataAuthorityConfig::default())?;
    authority.begin_election().await?;
    let (context, initial_command) = command(local, [2; 16])?;
    let receipt = authority
        .commit_or_resolve(context, initial_command.clone())
        .await?;
    assert_eq!(receipt.operation_id, context.operation_id);
    assert_eq!(receipt.committed_revision, Revision::new(1));

    let replay = authority
        .commit_or_resolve(context, initial_command)
        .await?;
    assert_eq!(replay.result_digest, receipt.result_digest);
    let (_, changed) = command(local, [9; 16])?;
    assert_eq!(
        authority.commit_or_resolve(context, changed).await,
        Err(MetadataAuthorityRequestError::Conflict)
    );
    authority.shutdown().await?;
    runtime.await??;
    Ok(())
}

#[tokio::test]
async fn follower_rejects_before_enqueuing_a_mutation() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = NodeId::from_bytes([11; 16])?;
    let driver = driver(&directory.path().join("follower.sqlite3"), local)?;
    let transport: Arc<dyn ConsensusMessageTransport> = Arc::new(|_, _| {});
    let (authority, runtime) =
        spawn_metadata_authority(driver, transport, MetadataAuthorityConfig::default())?;
    let (context, command) = command(local, [12; 16])?;
    assert_eq!(
        authority.commit_or_resolve(context, command).await,
        Err(MetadataAuthorityRequestError::NotLeader { leader_id: None })
    );
    authority.shutdown().await?;
    runtime.await??;
    Ok(())
}

fn driver(
    file_path: &std::path::Path,
    local: NodeId,
) -> Result<PartitionConsensusDriver<AuthoritativeRepository>, Box<dyn std::error::Error>> {
    let partition_id = PartitionId::from_bytes([20; 16])?;
    let plan = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([21; 16])?,
        1,
        BTreeSet::from([local]),
        BTreeSet::new(),
    )?)?;
    let database = PartitionDatabase::open(file_path, partition_id, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    repository.initialise_consensus_quorum_plan(&plan, UnixMicros::new(2))?;
    let incarnations = MemberIncarnations::new(BTreeMap::from([(local, 1)]), &plan)?;
    let core = ConsensusCore::new(CoreConfig {
        partition_id,
        local_node_id: local,
        local_incarnation: 1,
        plan,
        member_incarnations: incarnations,
    })?;
    Ok(PartitionConsensusDriver::new(core, repository))
}

fn command(
    node_id: NodeId,
    mesh_marker: [u8; 16],
) -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
    let administrator_id = PrincipalId::from_bytes([30; 16])?;
    let context = CommandContext {
        operation_id: OperationId::from_bytes([31; 16])?,
        actor_principal_id: administrator_id,
        audit_event_id: AuditEventId::from_bytes([32; 16])?,
        occurred_at: UnixMicros::new(10),
        expected_revision: Some(Revision::ZERO),
    };
    Ok((
        context,
        AuthoritativeCommand::BootstrapAppliance(BootstrapAppliance {
            mesh: BootstrapMesh {
                mesh_id: MeshId::from_bytes(mesh_marker)?,
                mesh_name: RecordName::new("Authority mesh")?,
                administrator_id,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([33; 16])?,
                host_id: HostId::from_bytes([34; 16])?,
                host_name: RecordName::new("Host")?,
                node_id,
                node_name: RecordName::new("Node")?,
                partition_name: RecordName::new("Root authority")?,
            },
            authentication: CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([35; 16])?,
                principal_id: administrator_id,
                label: "Initial API key".to_owned(),
                service_scope: 7,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([36; 16])?,
                    key_digest: [37; 32],
                    scopes: 1,
                    valid_from: context.occurred_at,
                },
            },
        }),
    ))
}
