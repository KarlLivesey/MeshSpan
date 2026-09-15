// SPDX-License-Identifier: GPL-2.0-only

//! An enrolled storage identity is not a metadata administrator.

use super::{Error, ProcessFixture};
use meshspan_cluster::ConsensusNetwork;
use meshspan_daemon::OperatingSystemClock;
use meshspan_domain::{
    AuditEventId, Clock as _, GroupId, HostId, NodeId, OperationId, PrincipalId,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, CreateGroup, LocalTargetRecord,
    METADATA_COMMAND_VERSION, PartitionDatabase, RecordName, encode_authoritative_command,
};
use meshspan_protocol::v1::{
    ControlEnvelope, ErrorCode, MetadataCommand, NodeRole, OperationOutcome, OperationResult,
    VersionedPayload, control_envelope::Message, metadata_command::Command,
};

pub(super) async fn prove(
    gateway: &ProcessFixture,
    storage: &ProcessFixture,
    target: &LocalTargetRecord,
) -> Result<(), Box<dyn Error>> {
    let directory = storage.state_path.clone();
    let local = target.intent.node_id;
    let destination = (
        NodeId::from_bytes(meshspan_domain::uuid_v8([171; 16]))?,
        gateway.private_address,
    );
    let runtime = tokio::runtime::Handle::current();
    let network = tokio::task::spawn_blocking(move || {
        super::recovery_storage_io::start_network(
            &directory,
            local,
            destination,
            vec![NodeRole::Storage],
            &runtime,
        )
        .map_err(|e| e.to_string())
    })
    .await??;
    let result = async {
        exercise(&network, destination.0, target).await?;
        prove_read_fence(&network, destination.0, gateway).await
    }
    .await;
    let closed = network.close();
    result?;
    closed?;
    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &gateway.state_path.join("root-authority.sqlite3"),
        OperatingSystemClock.now(),
    )?);
    for marker in [233, 236, 237, 238] {
        assert!(
            repository
                .resolve_operation(OperationId::from_bytes([marker; 16])?)?
                .is_none()
        );
    }
    Ok(())
}

/// The pre-recovery identity is still cryptographically rooted in the mesh CA, but no longer
/// belongs to the admitted membership. A timeout or failed local setup is not rejection proof.
pub(super) async fn reject_returning_identity(
    original: &ProcessFixture,
    gateway: &ProcessFixture,
    storage: &ProcessFixture,
) -> Result<(), Box<dyn Error>> {
    let source = original.state_path.clone();
    let replacement = gateway.state_path.clone();
    let old_node = super::fixture_node_id(original)?;
    let (credentials, roots, peers) = tokio::task::spawn_blocking(move || {
        returning_credentials(&source, &replacement, old_node).map_err(|e| e.to_string())
    })
    .await??;
    let limits = meshspan_transport::TransportLimits::new(
        meshspan_protocol::WireLimits::new(64 * 1024, 64 * 1024, 256, 4096)?,
        4,
        64 * 1024,
        256 * 1024,
    )?;
    let client =
        meshspan_transport::client_endpoint("127.0.0.1:0".parse()?, credentials, roots, limits)?;
    let exercise = async {
        for (marker, fixture) in [(171, gateway), (188, storage)] {
            let node = NodeId::from_bytes(meshspan_domain::uuid_v8([marker; 16]))?;
            let name = format!(
                "node-{}.meshspan.internal",
                node.to_string().replace('-', "")
            );
            let connection =
                meshspan_transport::connect(&client, fixture.private_address, &name).await?;
            assert_eq!(peers.authenticate_connection(&connection)?.node_id(), node);
            let quinn::ConnectionError::ApplicationClosed(rejected) = connection.closed().await
            else {
                return Err(
                    "returning node was not explicitly rejected by the live receiver".into(),
                );
            };
            assert_eq!(rejected.error_code, quinn::VarInt::from_u32(1));
            assert_eq!(rejected.reason.as_ref(), b"unknown peer");
        }
        Ok::<_, Box<dyn Error>>(())
    };
    let outcome = tokio::time::timeout(super::WAIT_LIMIT, exercise)
        .await
        .map_err(|error| format!("returning-node rejection proof: {error}"));
    client.close(0_u32.into(), b"proof complete");
    outcome??;
    Ok(())
}

fn returning_credentials(
    source: &std::path::Path,
    replacement: &std::path::Path,
    old_node: NodeId,
) -> Result<
    (
        meshspan_transport::NodeCredentials,
        rustls::RootCertStore,
        meshspan_transport::PeerRegistry,
    ),
    Box<dyn Error>,
> {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use sha2::Digest as _;
    let original = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &source.join("root-authority.sqlite3"),
        OperatingSystemClock.now(),
    )?);
    let recovered = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &replacement.join("root-authority.sqlite3"),
        OperatingSystemClock.now(),
    )?);
    let mesh = original.local_mesh_id()?.ok_or("original mesh missing")?;
    assert_eq!(recovered.local_mesh_id()?, Some(mesh));
    assert!(recovered.active_node_certificate(old_node)?.is_none());
    let certificate = original
        .active_node_certificate(old_node)?
        .ok_or("original certificate missing")?;
    let issuer = original
        .online_certificate_authority(mesh)?
        .ok_or("original issuer missing")?;
    let credentials = meshspan_transport::NodeCredentials::new(
        vec![
            CertificateDer::from(certificate.certificate_der),
            CertificateDer::from(issuer.certificate_der),
        ],
        PrivatePkcs8KeyDer::from(std::fs::read(source.join("secrets/node-identity.pk8"))?).into(),
    )?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(std::fs::read(
        replacement.join("recovery-root.der"),
    )?))?;
    let mut peers = Vec::new();
    for marker in [171, 188] {
        let node = NodeId::from_bytes(meshspan_domain::uuid_v8([marker; 16]))?;
        let certificate = recovered
            .active_node_certificate(node)?
            .ok_or("replacement certificate missing")?;
        peers.push(meshspan_transport::PeerBinding {
            node_id: node,
            incarnation: certificate.incarnation,
            certificate_fingerprint: sha2::Sha256::digest(&certificate.certificate_der).into(),
        });
    }
    Ok((
        credentials,
        roots,
        meshspan_transport::PeerRegistry::new(peers)?,
    ))
}

async fn exercise(
    network: &ConsensusNetwork,
    destination: NodeId,
    target: &LocalTargetRecord,
) -> Result<(), Box<dyn Error>> {
    // Replaying the exact owned registration must still work on this connection.
    let (context, command) = target.authority_input()?;
    let outcome = submit(network, destination, context, &command).await?;
    assert_eq!(outcome.outcome, i32::from(OperationOutcome::Durable));
    let context = CommandContext {
        operation_id: OperationId::from_bytes([233; 16])?,
        audit_event_id: AuditEventId::from_bytes([234; 16])?,
        occurred_at: OperatingSystemClock.now(),
        ..context
    };
    let forged = AuthoritativeCommand::CreateGroup(CreateGroup {
        group_id: GroupId::from_bytes([235; 16])?,
        name: RecordName::new("storage-must-not-create-this-group")?,
        activation_policy_id: None,
    });
    assert_denied(&submit(network, destination, context, &forged).await?);
    for (marker, substitution) in [
        (236, Substitution::Node),
        (237, Substitution::Host),
        (238, Substitution::Actor),
    ] {
        let mut forged = command.clone();
        let mut context = CommandContext {
            operation_id: OperationId::from_bytes([marker; 16])?,
            ..context
        };
        let AuthoritativeCommand::RegisterStorageTarget(target) = &mut forged else {
            return Err("fixture is not a target registration".into());
        };
        match substitution {
            Substitution::Node => target.node_id = destination,
            Substitution::Host => target.host_id = HostId::from_bytes([marker; 16])?,
            Substitution::Actor => {
                context.actor_principal_id = PrincipalId::from_bytes([marker; 16])?;
            }
        }
        assert_denied(&submit(network, destination, context, &forged).await?);
    }
    // Rejection does not poison the authenticated connection or change the valid receipt.
    let (context, command) = target.authority_input()?;
    assert_eq!(
        submit(network, destination, context, &command)
            .await?
            .outcome,
        i32::from(OperationOutcome::Durable)
    );
    Ok(())
}

async fn prove_read_fence(
    network: &ConsensusNetwork,
    destination: NodeId,
    gateway: &ProcessFixture,
) -> Result<(), Box<dyn Error>> {
    let operation = OperationId::from_bytes([239; 16])?;
    let fence = network
        .fetch_metadata_read_fence(
            destination,
            operation,
            [240; 32],
            OperatingSystemClock.now(),
        )
        .await?;
    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &gateway.state_path.join("root-authority.sqlite3"),
        OperatingSystemClock.now(),
    )?);
    assert_eq!(fence.partition_id, repository.partition_id());
    assert_eq!(fence.leader_node_id, destination);
    let plan = repository
        .load_active_consensus_quorum_plan()?
        .ok_or("read plan missing")?;
    assert_eq!(fence.membership_epoch, plan.membership_epoch());
    assert_eq!(fence.plan_digest, plan.proof_digest());
    let durable = repository.load_consensus_state(plan.membership_epoch())?;
    let entry = durable
        .log
        .iter()
        .find(|entry| entry.position == fence.applied)
        .ok_or("read frontier not durable")?;
    assert_eq!(fence.applied_digest, entry.entry_digest());
    assert_eq!(fence.term, fence.applied.term);
    assert!(repository.current_revision()? >= fence.revision);
    assert!(repository.resolve_operation(operation)?.is_none());
    let expired = ControlEnvelope {
        header: Some(network.control_header(operation, OperatingSystemClock.now().get() - 1)?),
        message: Some(Message::FetchMetadataReadFence(
            meshspan_protocol::v1::FetchMetadataReadFence {
                nonce: vec![241; 32],
            },
        )),
    };
    let response = network.request_control(destination, &expired).await?;
    let Some(Message::MetadataReadFenceResult(result)) = &response.as_inner().message else {
        return Err("read-fence rejection missing".into());
    };
    assert_eq!(result.nonce, vec![241; 32]);
    let Some(meshspan_protocol::v1::metadata_read_fence_result::Outcome::Rejection(rejection)) =
        &result.outcome
    else {
        return Err("expired read incorrectly succeeded".into());
    };
    assert_eq!(rejection.code, i32::from(ErrorCode::Deadline));
    Ok(())
}

enum Substitution {
    Node,
    Host,
    Actor,
}

fn assert_denied(result: &OperationResult) {
    assert_eq!(result.outcome, i32::from(OperationOutcome::Rejected));
    assert_eq!(
        result.error.as_ref().map(|error| error.code),
        Some(i32::from(ErrorCode::Unauthorised))
    );
    assert_eq!(result.committed_revision, None);
    assert!(result.result_digest.is_empty());
}

pub(super) async fn submit(
    network: &ConsensusNetwork,
    destination: NodeId,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<OperationResult, Box<dyn Error>> {
    let deadline = OperatingSystemClock
        .now()
        .get()
        .checked_add(30_000_000)
        .ok_or("clock overflow")?;
    let request = ControlEnvelope {
        header: Some(network.control_header(context.operation_id, deadline)?),
        message: Some(Message::MetadataCommand(MetadataCommand {
            expected_revision: context
                .expected_revision
                .map(meshspan_domain::Revision::get),
            request_digest: command.request_digest(context).to_vec(),
            command: Some(Command::ClusterControl(VersionedPayload {
                format_version: u32::from(METADATA_COMMAND_VERSION),
                canonical_bytes: encode_authoritative_command(context, command)?,
            })),
        })),
    };
    let response = network
        .request_control(destination, &request)
        .await
        .map_err(|error| format!("submit recovery control operation: {error:?}"))?;
    let Some(Message::OperationStatusResponse(response)) = response.as_inner().message.as_ref()
    else {
        return Err("wrong control response".into());
    };
    Ok(response.result.clone().ok_or("missing operation result")?)
}
