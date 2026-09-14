// SPDX-License-Identifier: GPL-2.0-only

//! Owner admission against the existing recovered/bootstrap authority and real internal node TLS.

use super::{RunningAuthority, TestResult, authority, context_for};
use meshspan_cluster::{FederationBackupCapabilityError, authorise_forwarded_backup};
use meshspan_contracts::ContractError;
use meshspan_domain::{HostId, JoinGrantId, NodeId, UnixMicros};
use meshspan_metadata::{
    ActivateNode, AuthoritativeCommand, ConsumeJoinGrant, IssueJoinGrant, JoinRoles, RecordName,
};
use meshspan_protocol::{
    WireLimits, encode_federation_frame,
    v1::{
        DataControlEnvelope, ExecuteFederatedBackup, ForwardFederatedBackupRequest, RequestHeader,
        data_control_envelope::Message as DataMessage, federation_envelope::Message,
    },
};
use meshspan_transport::{
    AuthenticatedPeer, FederationExchangeContext, FederationLocalIdentity, FederationPeerRegistry,
    FederationReplayGuard, NodeCredentials, PeerBinding, PeerRegistry, StreamKind, TransportLimits,
    accept_stream, client_endpoint, connect, open_stream, receive_data_control, send_data_control,
    server_endpoint, signed_federation_backup_message,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

#[path = "federation_backup_owner_stream_tests.rs"]
mod streams;

pub(super) async fn verify_owner_admission(
    provider: &RunningAuthority,
    identity: &FederationLocalIdentity<'_>,
    capability: &Message,
    limits: WireLimits,
) -> TestResult<InternalConnection> {
    let internal = InternalConnection::new(limits).await?;
    let gateway = NodeId::from_bytes([180; 16])?;
    let peer = PeerRegistry::new([PeerBinding {
        node_id: gateway,
        incarnation: 1,
        certificate_fingerprint: Sha256::digest(&internal.client_certificate).into(),
    }])?
    .authenticate_connection(&internal.server)?;
    let forwarded = forwarded(provider, identity, capability, peer, limits)?;
    let (mut send, _receive) = open_stream(&internal.client, StreamKind::Data).await?;
    let mut accepted = accept_stream(&internal.server).await?;
    send_data_control(
        &mut send,
        &DataControlEnvelope {
            message: Some(DataMessage::ForwardFederatedBackupRequest(
                forwarded.clone(),
            )),
        },
        limits,
    )
    .await?;
    send.finish()?;
    let envelope = receive_data_control(&mut accepted.receive, limits).await?;
    let now = crate::api_http::current_time().ok_or("clock")?;
    let authority = authority(provider)?;
    let current = meshspan_cluster::federation_connection_authority(
        authority.reader(),
        identity.binding().relationship_id,
        now,
    )?
    .ok_or("provider authority")?;
    let relay = FederationPeerRegistry::new([current.peer])?
        .authenticate_forwarded_backup_request(
            peer,
            &envelope,
            limits,
            now,
            &mut FederationReplayGuard::new(8, meshspan_domain::DurationMicros::new(30_000_000))?,
        )?;
    assert!(matches!(
        authorise_forwarded_backup(authority.reader(), provider.node_id, 1, &relay, now),
        Err(FederationBackupCapabilityError::Contract(
            ContractError::Unauthorized
        ))
    ));
    enrol_gateway(provider, gateway, &internal.client_certificate)?;
    let admitted =
        authorise_forwarded_backup(authority.reader(), provider.node_id, 1, &relay, now)?;
    let Message::BackupCapability(capability) = capability else {
        return Err("capability".into());
    };
    let expected = meshspan_data_plane::decode_federated_backup_permit(
        capability.permit.as_ref().ok_or("permit")?,
        now,
    )?;
    assert_eq!(admitted.permit(), &expected);
    for (owner, epoch) in [(gateway, 1), (provider.node_id, 2)] {
        assert!(matches!(
            authorise_forwarded_backup(authority.reader(), owner, epoch, &relay, now),
            Err(FederationBackupCapabilityError::Contract(
                ContractError::Unauthorized
            ))
        ));
    }
    assert!(matches!(
        authorise_forwarded_backup(
            authority.reader(),
            provider.node_id,
            1,
            &relay,
            UnixMicros::new(
                forwarded
                    .header
                    .as_ref()
                    .ok_or("header")?
                    .deadline_unix_micros
            )
        ),
        Err(FederationBackupCapabilityError::Contract(
            ContractError::DeadlineExceeded
        ))
    ));
    streams::verify(provider, &relay, &internal, limits).await?;
    Ok(internal)
}

fn forwarded(
    provider: &RunningAuthority,
    identity: &FederationLocalIdentity<'_>,
    capability: &Message,
    peer: AuthenticatedPeer,
    limits: WireLimits,
) -> TestResult<ForwardFederatedBackupRequest> {
    let Message::BackupCapability(capability) = capability else {
        return Err("capability".into());
    };
    let permit = capability.permit.as_ref().ok_or("permit")?;
    let now = crate::api_http::current_time().ok_or("clock")?;
    let expected = meshspan_data_plane::decode_federated_backup_permit(permit, now)?;
    let context = FederationExchangeContext::new(
        meshspan_protocol::v1::ProtocolVersion { major: 1, minor: 0 },
        [181; 16],
        expected.request.context().operation_id.as_bytes(),
        [182; 16],
        expected.request.context().deadline,
        [183; 32],
    )?;
    let signed = signed_federation_backup_message(
        identity,
        context,
        Message::ExecuteBackup(ExecuteFederatedBackup {
            permit: Some(permit.clone()),
            signature: Vec::new(),
        }),
        limits,
        now,
    )?;
    Ok(ForwardFederatedBackupRequest {
        header: Some(RequestHeader {
            version: Some(context.version),
            mesh_id: expected.scope.provider_mesh_id.as_bytes().to_vec(),
            partition_id: authority(provider)?
                .reader()
                .partition_id()
                .as_bytes()
                .to_vec(),
            routing_epoch: 1,
            sender_node_id: peer.node_id().as_bytes().to_vec(),
            sender_incarnation: peer.incarnation(),
            request_id: context.request_id.to_vec(),
            operation_id: context.operation_id.to_vec(),
            trace_id: context.trace_id.to_vec(),
            deadline_unix_micros: expected.expires_at.get(),
        }),
        provider_node_id: provider.node_id.as_bytes().to_vec(),
        request: encode_federation_frame(signed.envelope(), limits)?,
        maximum_frame_bytes: 64,
    })
}

fn enrol_gateway(
    provider: &RunningAuthority,
    gateway: NodeId,
    certificate: &[u8],
) -> TestResult<()> {
    let grant = JoinGrantId::from_bytes([185; 16])?;
    let roles = JoinRoles::new(JoinRoles::GATEWAY)?;
    let endpoint = "127.0.0.1:4400".to_owned();
    let until = crate::api_http::current_time()
        .ok_or("clock")?
        .checked_add(meshspan_domain::DurationMicros::new(60_000_000))
        .ok_or("expiry")?;
    let commands = [
        AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
            join_grant_id: grant,
            secret_digest: [186; 32],
            allowed_roles: roles,
            maximum_uses: 1,
            expires_at: until,
        }),
        AuthoritativeCommand::ConsumeJoinGrant(ConsumeJoinGrant {
            join_grant_id: grant,
            secret_digest: [186; 32],
            host_id: HostId::from_bytes([187; 16])?,
            new_host_name: Some(RecordName::new("Relay host")?),
            node_id: gateway,
            node_name: RecordName::new("Relay gateway")?,
            incarnation: 1,
            requested_roles: roles,
            wrapping_public_key: [188; 32],
            private_endpoint: endpoint.clone(),
            certificate_der: certificate.to_vec(),
            certificate_fingerprint: Sha256::digest(certificate).into(),
            certificate_valid_until: until,
        }),
        AuthoritativeCommand::ActivateNode(ActivateNode {
            node_id: gateway,
            incarnation: 1,
            private_endpoint: endpoint,
            capability_digest: [189; 32],
        }),
    ];
    for (index, command) in commands.into_iter().enumerate() {
        authority(provider)?
            .commit_authoritative(context_for(provider, 190 + u8::try_from(index)?)?, &command)?;
    }
    Ok(())
}

pub(super) struct InternalConnection {
    server_endpoint: quinn::Endpoint,
    client_endpoint: quinn::Endpoint,
    pub(super) server: quinn::Connection,
    pub(super) client: quinn::Connection,
    pub(super) client_certificate: Vec<u8>,
}

impl InternalConnection {
    async fn new(wire: WireLimits) -> TestResult<Self> {
        let authority = meshspan_certificates::CertificateAuthority::new()?;
        let server_certificate = authority.issue_node("relay.meshspan.internal")?;
        let client_certificate = authority.issue_node("gateway.meshspan.internal")?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(authority.certificate_der().to_vec()))?;
        let limits = TransportLimits::new(wire, 4, 64 * 1024, 256 * 1024)?;
        let address = "127.0.0.1:0".parse()?;
        let server_endpoint = server_endpoint(
            address,
            NodeCredentials::new(
                vec![CertificateDer::from(
                    server_certificate.certificate_der().to_vec(),
                )],
                PrivatePkcs8KeyDer::from(server_certificate.private_key().to_vec()).into(),
            )?,
            roots.clone(),
            limits,
        )?;
        let client_endpoint = client_endpoint(
            address,
            NodeCredentials::new(
                vec![CertificateDer::from(
                    client_certificate.certificate_der().to_vec(),
                )],
                PrivatePkcs8KeyDer::from(client_certificate.private_key().to_vec()).into(),
            )?,
            roots,
            limits,
        )?;
        let (client, server) = tokio::try_join!(
            connect(
                &client_endpoint,
                server_endpoint.local_addr()?,
                "relay.meshspan.internal"
            ),
            async {
                server_endpoint
                    .accept()
                    .await
                    .ok_or(meshspan_transport::TransportError::InvalidConfiguration)?
                    .await
                    .map_err(meshspan_transport::TransportError::from)
            },
        )?;
        Ok(Self {
            server_endpoint,
            client_endpoint,
            server,
            client,
            client_certificate: client_certificate.certificate_der().to_vec(),
        })
    }

    pub(super) async fn close(self) {
        self.client.close(0_u32.into(), b"test complete");
        self.server.close(0_u32.into(), b"test complete");
        self.client_endpoint.wait_idle().await;
        self.server_endpoint.wait_idle().await;
    }
}
