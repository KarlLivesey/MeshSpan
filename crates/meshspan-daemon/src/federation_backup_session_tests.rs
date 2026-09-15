// SPDX-License-Identifier: GPL-2.0-only

//! Native federation sessions issue signed backup permits against actual committed storage grants.

use super::{RunningAuthority, TestResult, authority};
use crate::federation_sessions::NativeFederationSession;
use meshspan_contracts::{
    BackupObjectIdentity, BackupStoreRequest, BoundedItems, ContractVersion,
    FederatedBackupRequest, FederatedBackupScope, RequestContext,
};
use meshspan_domain::{
    AuditEventId, BackupDestinationId, BackupId, DurationMicros, FederationGrant,
    FederationGrantId, FederationGrantRoute, FederationPolicy, FederationRelationshipId,
    FederationResourceScope, FederationStorageAllocation, FederationStorageAllocationId, MeshId,
    OperationId, StorageFederationPolicy, StorageParticipation, TargetId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, FederationGrantRestriction,
    IssueFederationGrant, IssueFederationStorageAllocation, PartitionDatabase,
    RevokeFederationGrant,
};
use meshspan_protocol::v1::{FederationEnvelope, ProtocolVersion, federation_envelope::Message};
use meshspan_transport::{
    FederationExchangeContext, FederationHelloConfig, FederationNegotiationConfig,
    FederationPeerRegistry, FederationReplayGuard, StreamKind, open_stream, receive_federation,
    send_federation, signed_federation_backup_message,
};
use std::time::Duration;

#[path = "federation_allocation_session_tests.rs"]
mod allocations;
#[path = "federation_backup_execution_tests.rs"]
mod execution;
#[path = "federation_backup_relay_tests.rs"]
mod relay;
#[path = "federation_backup_renewal_tests.rs"]
mod renewal;
#[path = "federation_backup_route_tests.rs"]
mod routing;

pub(super) async fn verify_capability(
    provider: &RunningAuthority,
    consumer: &RunningAuthority,
    session: &NativeFederationSession,
    hosts: &super::SessionHosts,
) -> TestResult<()> {
    crate::consensus_authentication_authority_tests::backup_destination_service_tests::register_target(provider).await?;
    let scope = provision(provider, session.relationship)?;
    let now = crate::api_http::current_time().ok_or("clock")?;
    let reader = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &consumer.directory.path().join("partition.sqlite3"),
        now,
    )?);
    let local = crate::local_federation_identity::LocalFederationIdentity::open_or_create(
        &consumer.directory.path().join("federation-identity.v1"),
        now,
    )?;
    let version = ProtocolVersion { major: 1, minor: 0 };
    let limits = session.limits.wire;
    let runtime = local.signing.session(
        local
            .certificate
            .certificate_chain()
            .first()
            .ok_or("certificate")?,
        FederationHelloConfig::new(vec![version], Vec::new(), limits, 3)?,
        FederationNegotiationConfig::new(vec![version], limits, 3)?,
    );
    let current =
        meshspan_cluster::federation_connection_authority(&reader, session.relationship, now)?
            .ok_or("consumer authority")?;
    let identity = runtime.local_identity(&current, now)?;
    let request = request(now)?;
    let context = FederationExchangeContext::new(
        version,
        [201; 16],
        request.context().operation_id.as_bytes(),
        [202; 16],
        request.context().deadline,
        [203; 32],
    )?;
    let peers = FederationPeerRegistry::new([current.peer])?;
    let discovered = allocations::discover(session, &identity, &peers, scope.grant_id).await?;
    let mut capability =
        meshspan_data_plane::encode_federated_backup_request(scope, &request, now)?;
    assert_eq!(capability.scope.as_ref(), Some(&discovered));
    capability.scope = Some(discovered);
    let message = Message::RequestBackupCapability(capability);
    let outbound =
        signed_federation_backup_message(&identity, context, message.clone(), limits, now)?;
    let response = exchange(session, outbound.envelope()).await??;
    let mut replay = FederationReplayGuard::new(32, DurationMicros::new(30_000_000))?;
    let authenticated = peers.authenticate_backup_response(
        &session.connection,
        &response,
        &outbound.expectation()?,
        crate::api_http::current_time().ok_or("clock")?,
        &mut replay,
    )?;
    verify_permit(authenticated.message(), scope, &request)?;
    let internal =
        relay::verify_owner_admission(provider, &identity, authenticated.message(), limits).await?;
    let renewed = Box::pin(
        execution::Client::new(session, &identity, &peers, scope, &hosts.joiner)
            .verify(provider, consumer, hosts, internal),
    )
    .await?;
    let mut unsupported = context;
    unsupported.version.minor = 1;
    unsupported.request_id = [208; 16];
    unsupported.replay_nonce = [209; 32];
    let wrong_version =
        signed_federation_backup_message(&identity, unsupported, message.clone(), limits, now)?;
    assert!(
        exchange(session, wrong_version.envelope()).await?.is_err(),
        "a signed request bypassed the exact negotiated protocol version"
    );
    assert!(
        exchange(session, outbound.envelope()).await?.is_err(),
        "replayed request was accepted"
    );
    verify_permission_retirement(provider, session, &identity, &peers, &(scope, renewed)).await?;
    Ok(())
}

async fn verify_permission_retirement(
    provider: &RunningAuthority,
    session: &NativeFederationSession,
    identity: &meshspan_transport::FederationLocalIdentity<'_>,
    peers: &FederationPeerRegistry,
    scopes: &(FederatedBackupScope, FederatedBackupScope),
) -> TestResult<()> {
    let (previous, current) = *scopes;
    // Renew the test request's deadline independently of the stored object's earlier IO.
    // A live successor is the positive control; neither denial may pass through expiry.
    let now = crate::api_http::current_time().ok_or("clock")?;
    let request = request(now)?;
    let mut context = FederationExchangeContext::new(
        ProtocolVersion { major: 1, minor: 0 },
        [226; 16],
        request.context().operation_id.as_bytes(),
        [226; 16],
        request.context().deadline,
        [226; 32],
    )?;
    let message = Message::RequestBackupCapability(
        meshspan_data_plane::encode_federated_backup_request(current, &request, now)?,
    );
    let live = signed_federation_backup_message(
        identity,
        context,
        message.clone(),
        session.limits.wire,
        now,
    )?;
    let response = exchange(session, live.envelope()).await??;
    let mut replay = FederationReplayGuard::new(8, DurationMicros::new(30_000_000))?;
    let verified = peers.authenticate_backup_response(
        &session.connection,
        &response,
        &live.expectation()?,
        crate::api_http::current_time().ok_or("clock")?,
        &mut replay,
    )?;
    verify_permit(verified.message(), current, &request)?;
    context.request_id = [225; 16];
    context.replay_nonce = [225; 32];
    let retired = signed_federation_backup_message(
        identity,
        context,
        Message::RequestBackupCapability(meshspan_data_plane::encode_federated_backup_request(
            previous, &request, now,
        )?),
        session.limits.wire,
        now,
    )?;
    assert!(
        exchange(session, retired.envelope()).await?.is_err(),
        "retired grant issued a capability"
    );
    authority(provider)?.commit_authoritative(
        context_for(provider, 205)?,
        &AuthoritativeCommand::RevokeFederationGrant(RevokeFederationGrant {
            grant_id: current.grant_id,
            expected_authority_epoch: current.relationship_authority_epoch,
            reason: "Withdraw native backup authority".into(),
        }),
    )?;
    context.request_id = [206; 16];
    context.replay_nonce = [207; 32];
    let revoked =
        signed_federation_backup_message(identity, context, message, session.limits.wire, now)?;
    assert!(
        exchange(session, revoked.envelope()).await?.is_err(),
        "revoked successor issued a capability"
    );
    assert!(
        crate::api_http::current_time().ok_or("clock")? < request.context().deadline,
        "denial proof outlived its fresh request"
    );
    Ok(())
}

fn verify_permit(
    message: &Message,
    scope: FederatedBackupScope,
    request: &FederatedBackupRequest,
) -> TestResult<()> {
    let Message::BackupCapability(value) = message else {
        return Err("expected signed native capability".into());
    };
    assert!(value.rejection.is_none());
    let permit = meshspan_data_plane::decode_federated_backup_permit(
        value.permit.as_ref().ok_or("permit")?,
        crate::api_http::current_time().ok_or("clock")?,
    )?;
    assert_eq!(permit.scope, scope);
    assert_eq!(&permit.request, request);
    assert_eq!(permit.expires_at, request.context().deadline);
    assert_ne!(permit.permit_digest, [0; 32]);
    Ok(())
}

async fn exchange(
    session: &NativeFederationSession,
    envelope: &FederationEnvelope,
) -> TestResult<
    Result<meshspan_protocol::ValidatedFederationEnvelope, meshspan_transport::TransportError>,
> {
    // Keep the harness deadline outside the protocol result: timing out cannot count as rejection.
    Ok(tokio::time::timeout(Duration::from_secs(2), async {
        let (mut send, mut receive) =
            open_stream(&session.connection, StreamKind::Federation).await?;
        send_federation(&mut send, envelope, session.limits.wire).await?;
        send.finish()?;
        receive_federation(&mut receive, session.limits.wire).await
    })
    .await
    .map_err(|error| {
        format!(
            "native backup control exchange for request {:?}: {error}",
            envelope.header.as_ref().map(|header| &header.request_id)
        )
    })?)
}

fn provision(
    provider: &RunningAuthority,
    relationship: FederationRelationshipId,
) -> TestResult<FederatedBackupScope> {
    let now = crate::api_http::current_time().ok_or("clock")?;
    let until = now
        .checked_add(DurationMicros::new(60_000_000))
        .ok_or("expiry")?;
    let local = MeshId::from_bytes([9; 16])?;
    let remote = MeshId::from_bytes([91; 16])?;
    let grant_id = FederationGrantId::from_bytes([210; 16])?;
    let policy = FederationPolicy::Storage(StorageFederationPolicy::new(
        4096,
        StorageParticipation::new(true, false),
        false,
        None,
    )?);
    let grant = IssueFederationGrant {
        grant: FederationGrant::new(
            grant_id,
            relationship,
            FederationGrantRoute::direct(local, remote)?,
            None,
            FederationResourceScope::StorageCapacity {
                provider_mesh_id: local,
            },
            policy,
            1,
            now,
            Some(until),
        )?,
        restrictions: BoundedItems::new(
            vec![
                FederationGrantRestriction {
                    imposing_mesh_id: local,
                    policy,
                },
                FederationGrantRestriction {
                    imposing_mesh_id: remote,
                    policy,
                },
            ],
            2,
        )?,
    };
    let authority = authority(provider)?;
    let grant_receipt = authority.commit_authoritative(
        context_for(provider, 210)?,
        &AuthoritativeCommand::IssueFederationGrant(grant),
    )?;
    let allocation = FederationStorageAllocation::new(
        FederationStorageAllocationId::from_bytes([211; 16])?,
        grant_id,
        provider.node_id,
        TargetId::from_bytes(uuid_v8([32; 16]))?,
        1,
        2048,
        now,
        until,
    )?;
    let allocated = authority.commit_authoritative(
        context_for(provider, 211)?,
        &AuthoritativeCommand::IssueFederationStorageAllocation(IssueFederationStorageAllocation {
            allocation,
            expected_grant_revision: grant_receipt.committed_revision,
        }),
    )?;
    let second = FederationStorageAllocation::new(
        FederationStorageAllocationId::from_bytes([218; 16])?,
        grant_id,
        provider.node_id,
        allocation.target_id(),
        1,
        2048,
        now,
        until,
    )?;
    authority.commit_authoritative(
        context_for(provider, 218)?,
        &AuthoritativeCommand::IssueFederationStorageAllocation(IssueFederationStorageAllocation {
            allocation: second,
            expected_grant_revision: grant_receipt.committed_revision,
        }),
    )?;
    Ok(FederatedBackupScope {
        relationship_id: relationship,
        remote_mesh_id: remote,
        provider_mesh_id: local,
        allocation_id: allocation.allocation_id(),
        grant_id,
        namespace_grant_id: allocation.grant_id(),
        provider_node_id: provider.node_id,
        target_id: allocation.target_id(),
        target_generation: 1,
        relationship_authority_epoch: 1,
        grant_revision: grant_receipt.committed_revision,
        allocation_revision: allocated.committed_revision,
    })
}

fn request(now: UnixMicros) -> TestResult<FederatedBackupRequest> {
    Ok(FederatedBackupRequest::Store(BackupStoreRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([201; 16])?,
            expected_revision: Some(meshspan_domain::Revision::new(1)),
            deadline: now
                .checked_add(DurationMicros::new(5_000_000))
                .ok_or("deadline")?,
        },
        object: BackupObjectIdentity {
            destination_id: BackupDestinationId::from_bytes([212; 16])?,
            backup_id: BackupId::from_bytes([213; 16])?,
            provider_generation: 1,
            byte_length: 1024,
            digest: <sha2::Sha256 as sha2::Digest>::digest([214; 1024]).into(),
        },
    }))
}

fn context_for(fixture: &RunningAuthority, marker: u8) -> TestResult<CommandContext> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([marker; 16])?,
        actor_principal_id: fixture.administrator_id,
        audit_event_id: AuditEventId::from_bytes([marker; 16])?,
        occurred_at: crate::api_http::current_time().ok_or("clock")?,
        expected_revision: None,
    })
}
