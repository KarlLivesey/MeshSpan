// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ed25519_dalek::{Signer, SigningKey};
use meshspan_domain::{
    DurationMicros, FederationRelationshipId, MeshId, NodeId, PartitionId, UnixMicros,
};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::data_control_envelope::Message as DataMessage;
use meshspan_protocol::v1::federation_envelope::Message as FederationMessage;
use meshspan_protocol::v1::{
    ControlEnvelope, DataControlEnvelope, DataFrame, FederationEnvelope, NodeHello, Ping,
    ProtocolVersion, PutShardFinish, VersionedPayload,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, decode_federation_frame, encode_federation_frame,
    federation_hello_signing_payload, federation_welcome_signing_payload,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::identity::certificate_fingerprint;
use super::{
    AuthenticatedFederationHello, FederationAuthorityPageExpectation, FederationExchangeContext,
    FederationHelloConfig, FederationHelloContext, FederationHelloExpectation,
    FederationLocalIdentity, FederationLocalIdentityBinding, FederationNegotiationConfig,
    FederationPeerBinding, FederationPeerRegistry, FederationReplayGuard, FederationWelcomeNonces,
    NegotiationConfig, NodeCredentials, OutboundFederationHello, PeerBinding, PeerRegistry,
    StreamKind, TransportError, TransportLimits, accept_stream, client_endpoint, connect,
    open_stream, receive_control, receive_data_control, receive_data_frame, receive_federation,
    send_control, send_data_control, send_data_frame, send_federation, server_endpoint,
    signed_federation_authority_fetch, signed_federation_authority_page, signed_federation_hello,
};

mod federation_branch_page;
mod federation_content_layout;
mod federation_storage;

const CERTIFICATE_NAME: &str = "meshspan.internal";

#[tokio::test]
async fn real_quinn_mtls_binds_peers_and_round_trips_an_independent_stream()
-> Result<(), Box<dyn Error>> {
    let certificates = certificates()?;
    let server_node = node(1)?;
    let client_node = node(2)?;
    let server_registry = PeerRegistry::new([PeerBinding {
        node_id: client_node,
        incarnation: 7,
        certificate_fingerprint: certificate_fingerprint(&certificates.client_certificate),
    }])?;
    let client_registry = PeerRegistry::new([PeerBinding {
        node_id: server_node,
        incarnation: 3,
        certificate_fingerprint: certificate_fingerprint(&certificates.server_certificate),
    }])?;
    let limits = limits()?;
    let server = server_endpoint(
        loopback(),
        certificates.server_credentials()?,
        roots(&certificates.authority_certificate)?,
        limits,
    )?;
    let client = client_endpoint(
        loopback(),
        certificates.client_credentials()?,
        roots(&certificates.authority_certificate)?,
        limits,
    )?;
    let server_address = server.local_addr()?;
    let server_connection = async {
        server
            .accept()
            .await
            .ok_or(TransportError::InvalidConfiguration)?
            .await
            .map_err(TransportError::from)
    };
    let (client_connection, server_connection) = tokio::try_join!(
        connect(&client, server_address, CERTIFICATE_NAME),
        server_connection
    )?;

    let authenticated_client = server_registry.authenticate_connection(&server_connection)?;
    let authenticated_server = client_registry.authenticate_connection(&client_connection)?;
    assert_eq!(authenticated_client.node_id(), client_node);
    assert_eq!(authenticated_server.node_id(), server_node);

    let mesh_id = MeshId::from_bytes([9; 16])?;
    authenticated_client.verify_hello(mesh_id, &hello(mesh_id, client_node, 7))?;
    assert!(matches!(
        authenticated_client.verify_hello(mesh_id, &hello(mesh_id, server_node, 7)),
        Err(TransportError::UntrustedPeer)
    ));
    let mut offered = hello(mesh_id, client_node, 7);
    offered.versions = vec![version(1, 0), version(1, 2), version(2, 0)];
    offered.maximum_control_bytes = 128 * 1_024;
    offered.maximum_data_frame_bytes = 2 * 1_024 * 1_024;
    offered.maximum_streams = 96;
    let welcome = authenticated_client.negotiate(
        mesh_id,
        &offered,
        &NegotiationConfig {
            versions: vec![version(1, 0), version(1, 2)],
            partition_ids: vec![PartitionId::from_bytes([11; 16])?.as_bytes()],
            leader_node_id: Some(server_node),
            routing_epoch: 4,
            maximum_control_bytes: 64 * 1_024,
            maximum_data_frame_bytes: 4 * 1_024 * 1_024,
            maximum_streams: 128,
        },
    )?;
    assert_eq!(welcome.selected_version, Some(version(1, 2)));
    assert_eq!(welcome.maximum_control_bytes, 64 * 1_024);
    assert_eq!(welcome.maximum_data_frame_bytes, 2 * 1_024 * 1_024);
    assert_eq!(welcome.maximum_streams, 96);
    assert_eq!(welcome.peer_node_id, client_node.as_bytes());

    let (mut client_send, _client_receive) =
        open_stream(&client_connection, StreamKind::Consensus).await?;
    let mut accepted = accept_stream(&server_connection).await?;
    assert_eq!(accepted.kind, StreamKind::Consensus);
    let envelope = ControlEnvelope {
        header: None,
        message: Some(Message::Ping(Ping {
            nonce: 44,
            sent_monotonic_micros: 2,
        })),
    };
    send_control(&mut client_send, &envelope, limits.wire).await?;
    assert_eq!(
        receive_control(&mut accepted.receive, limits.wire)
            .await?
            .into_inner(),
        envelope
    );

    prove_data_framing(&client_connection, &server_connection, limits.wire).await?;

    client_connection.close(0_u32.into(), b"test complete");
    server_connection.close(0_u32.into(), b"test complete");
    client.wait_idle().await;
    server.wait_idle().await;
    Ok(())
}

async fn prove_data_framing(
    client: &quinn::Connection,
    server: &quinn::Connection,
    limits: meshspan_protocol::WireLimits,
) -> Result<(), Box<dyn Error>> {
    let (mut send, _receive) = open_stream(client, StreamKind::Data).await?;
    let mut accepted = accept_stream(server).await?;
    assert_eq!(accepted.kind, StreamKind::Data);
    let finish = DataControlEnvelope {
        message: Some(DataMessage::PutShardFinish(PutShardFinish {
            final_length: 4,
            final_digest: vec![8; 32],
        })),
    };
    let data = DataFrame {
        offset: 0,
        bytes: vec![1, 2, 3, 4],
    };
    send_data_control(&mut send, &finish, limits).await?;
    send_data_frame(&mut send, &data, limits).await?;
    assert_eq!(
        receive_data_control(&mut accepted.receive, limits)
            .await?
            .into_inner(),
        finish
    );
    assert_eq!(
        receive_data_frame(&mut accepted.receive, limits)
            .await?
            .into_inner(),
        data
    );
    Ok(())
}

#[tokio::test]
async fn certificate_valid_in_tls_but_absent_from_topology_is_rejected()
-> Result<(), Box<dyn Error>> {
    let certificates = certificates()?;
    let limits = limits()?;
    let server = server_endpoint(
        loopback(),
        certificates.server_credentials()?,
        roots(&certificates.authority_certificate)?,
        limits,
    )?;
    let client = client_endpoint(
        loopback(),
        certificates.client_credentials()?,
        roots(&certificates.authority_certificate)?,
        limits,
    )?;
    let server_address = server.local_addr()?;
    let server_connection = async {
        server
            .accept()
            .await
            .ok_or(TransportError::InvalidConfiguration)?
            .await
            .map_err(TransportError::from)
    };
    let (client_connection, server_connection) = tokio::try_join!(
        connect(&client, server_address, CERTIFICATE_NAME),
        server_connection
    )?;
    let unrelated = PeerRegistry::new([PeerBinding {
        node_id: node(8)?,
        incarnation: 1,
        certificate_fingerprint: [8; 32],
    }])?;
    assert!(matches!(
        unrelated.authenticate_connection(&server_connection),
        Err(TransportError::UntrustedPeer)
    ));
    client_connection.close(0_u32.into(), b"test complete");
    server_connection.close(0_u32.into(), b"test complete");
    Ok(())
}

#[tokio::test]
async fn saturated_data_stream_does_not_block_consensus_control() -> Result<(), Box<dyn Error>> {
    let certificates = certificates()?;
    let limits = limits()?;
    let server = server_endpoint(
        loopback(),
        certificates.server_credentials()?,
        roots(&certificates.authority_certificate)?,
        limits,
    )?;
    let client = client_endpoint(
        loopback(),
        certificates.client_credentials()?,
        roots(&certificates.authority_certificate)?,
        limits,
    )?;
    let server_address = server.local_addr()?;
    let server_connection = async {
        server
            .accept()
            .await
            .ok_or(TransportError::InvalidConfiguration)?
            .await
            .map_err(TransportError::from)
    };
    let (client_connection, server_connection) = tokio::try_join!(
        connect(&client, server_address, CERTIFICATE_NAME),
        server_connection
    )?;

    let (mut data_send, _data_receive) = open_stream(&client_connection, StreamKind::Data).await?;
    let held_data_stream = accept_stream(&server_connection).await?;
    assert_eq!(held_data_stream.kind, StreamKind::Data);
    let blocked_data_write =
        tokio::spawn(async move { data_send.write_all(&vec![7_u8; 8 * 1_024 * 1_024]).await });

    let (mut consensus_send, _consensus_receive) =
        open_stream(&client_connection, StreamKind::Consensus).await?;
    let envelope = ControlEnvelope {
        header: None,
        message: Some(Message::Ping(Ping {
            nonce: 71,
            sent_monotonic_micros: 9,
        })),
    };
    send_control(&mut consensus_send, &envelope, limits.wire).await?;
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let mut accepted = accept_stream(&server_connection).await?;
        if accepted.kind != StreamKind::Consensus {
            return Err(TransportError::InvalidFrame);
        }
        receive_control(&mut accepted.receive, limits.wire).await
    })
    .await??;
    assert_eq!(received.into_inner(), envelope);
    assert!(!blocked_data_write.is_finished());
    blocked_data_write.abort();
    drop(held_data_stream);

    client_connection.close(0_u32.into(), b"test complete");
    server_connection.close(0_u32.into(), b"test complete");
    client.wait_idle().await;
    server.wait_idle().await;
    Ok(())
}

#[tokio::test]
async fn federation_envelope_round_trips_on_its_own_bounded_stream() -> Result<(), Box<dyn Error>> {
    let certificates = certificates()?;
    let limits = limits()?;
    let server = server_endpoint(
        loopback(),
        certificates.server_credentials()?,
        roots(&certificates.authority_certificate)?,
        limits,
    )?;
    let client = client_endpoint(
        loopback(),
        certificates.client_credentials()?,
        roots(&certificates.authority_certificate)?,
        limits,
    )?;
    let server_address = server.local_addr()?;
    let server_connection = async {
        server
            .accept()
            .await
            .ok_or(TransportError::InvalidConfiguration)?
            .await
            .map_err(TransportError::from)
    };
    let (client_connection, server_connection) = tokio::try_join!(
        connect(&client, server_address, CERTIFICATE_NAME),
        server_connection
    )?;
    let client_signing_key = SigningKey::from_bytes(&[42; 32]);
    let relationship_id = FederationRelationshipId::from_bytes([1; 16])?;
    let remote_mesh_id = MeshId::from_bytes([2; 16])?;
    let local_mesh_id = MeshId::from_bytes([3; 16])?;
    let outbound = outbound_federation_hello(
        &certificates.client_certificate,
        &client_signing_key,
        limits.wire,
    )?;
    let envelope = outbound.envelope().clone();
    let expectation = outbound.expectation().clone();
    let (mut send, mut receive) = open_stream(&client_connection, StreamKind::Federation).await?;
    let mut accepted = accept_stream(&server_connection).await?;
    assert_eq!(accepted.kind, StreamKind::Federation);
    send_federation(&mut send, &envelope, limits.wire).await?;
    let received = receive_federation(&mut accepted.receive, limits.wire).await?;
    assert_eq!(received.as_inner(), &envelope);
    let registry = FederationPeerRegistry::new([FederationPeerBinding {
        relationship_id,
        local_mesh_id,
        remote_mesh_id,
        authority_epoch: 1,
        identity_generation: 1,
        certificate_fingerprint: certificate_fingerprint(&certificates.client_certificate),
        verifying_key: client_signing_key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(3_000_000),
    }])?;
    let mut replay = FederationReplayGuard::new(8, DurationMicros::new(1_000_000))?;
    let authenticated = registry.authenticate_hello(
        &server_connection,
        &received,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(authenticated.relationship_id(), relationship_id);
    assert_eq!(authenticated.remote_mesh_id(), remote_mesh_id);
    assert!(matches!(
        registry.authenticate_hello(
            &server_connection,
            &received,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    prove_hostile_federation_hellos(
        &registry,
        &server_connection,
        &envelope,
        &client_signing_key,
        limits.wire,
    )?;
    prove_federation_welcome(
        &authenticated,
        &expectation,
        &mut accepted.send,
        &mut receive,
        &client_connection,
        &certificates,
        limits.wire,
    )
    .await?;
    client_connection.close(0_u32.into(), b"test complete");
    server_connection.close(0_u32.into(), b"test complete");
    client.wait_idle().await;
    server.wait_idle().await;
    Ok(())
}

fn prove_signed_authority_fetch(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let local_identity = FederationLocalIdentity::authenticate(
        FederationLocalIdentityBinding {
            relationship_id: FederationRelationshipId::from_bytes([1; 16])?,
            local_mesh_id: MeshId::from_bytes([2; 16])?,
            remote_mesh_id: MeshId::from_bytes([3; 16])?,
            authority_epoch: 1,
            identity_generation: 1,
            certificate_fingerprint: certificate_fingerprint(certificate),
            verifying_key: signing_key.verifying_key().to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(3_000_000),
        },
        certificate.as_ref(),
        signing_key,
        UnixMicros::new(1_500_000),
    )?;
    let context = FederationExchangeContext::new(
        version(1, 2),
        [41; 16],
        [42; 16],
        [43; 16],
        UnixMicros::new(2_000_000),
        [44; 32],
    )?;
    let outbound = signed_federation_authority_fetch(
        &local_identity,
        context,
        8,
        vec![45; 96],
        2,
        limits,
        UnixMicros::new(1_500_000),
    )?;
    let validated = validated_federation(outbound.envelope(), limits)?;
    let mut replay = FederationReplayGuard::new(8, DurationMicros::new(1_000_000))?;
    let authenticated = registry.authenticate_authority_fetch(
        connection,
        &validated,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(authenticated.after_revision(), 8);
    assert_eq!(authenticated.cursor(), &[45; 96]);
    assert_eq!(authenticated.limit(), 2);
    assert_eq!(
        authenticated.response_context([46; 32])?.request_id,
        [41; 16]
    );
    assert!(matches!(
        registry.authenticate_authority_fetch(
            connection,
            &validated,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));

    let mut tampered = outbound.envelope().clone();
    let Some(FederationMessage::FetchAuthority(fetch)) = tampered.message.as_mut() else {
        unreachable!("fixture authority fetch")
    };
    fetch.cursor[0] ^= 1;
    let tampered = validated_federation(&tampered, limits)?;
    let mut fresh_replay = FederationReplayGuard::new(8, DurationMicros::new(1_000_000))?;
    assert!(matches!(
        registry.authenticate_authority_fetch(
            connection,
            &tampered,
            UnixMicros::new(1_500_000),
            &mut fresh_replay,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    Ok(())
}

fn outbound_federation_hello(
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
    limits: WireLimits,
) -> Result<OutboundFederationHello, Box<dyn Error>> {
    let identity = FederationLocalIdentity::authenticate(
        FederationLocalIdentityBinding {
            relationship_id: FederationRelationshipId::from_bytes([1; 16])?,
            local_mesh_id: MeshId::from_bytes([2; 16])?,
            remote_mesh_id: MeshId::from_bytes([3; 16])?,
            authority_epoch: 1,
            identity_generation: 1,
            certificate_fingerprint: certificate_fingerprint(certificate),
            verifying_key: signing_key.verifying_key().to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(3_000_000),
        },
        certificate.as_ref(),
        signing_key,
        UnixMicros::new(1_000_000),
    )?;
    Ok(signed_federation_hello(
        &identity,
        &FederationHelloConfig::new(vec![version(1, 0), version(1, 2)], vec![1], limits, 128)?,
        FederationHelloContext::new(
            [4; 16],
            [5; 16],
            [6; 16],
            UnixMicros::new(2_000_000),
            [7; 32],
            [9; 32],
        )?,
        UnixMicros::new(1_000_000),
    )?)
}

async fn prove_federation_welcome(
    authenticated: &AuthenticatedFederationHello,
    expectation: &FederationHelloExpectation,
    send: &mut quinn::SendStream,
    receive: &mut quinn::RecvStream,
    connection: &quinn::Connection,
    certificates: &Certificates,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let signing_key = SigningKey::from_bytes(&[43; 32]);
    let local_identity = FederationLocalIdentity::authenticate(
        FederationLocalIdentityBinding {
            relationship_id: authenticated.relationship_id(),
            local_mesh_id: authenticated.local_mesh_id(),
            remote_mesh_id: authenticated.remote_mesh_id(),
            authority_epoch: 1,
            identity_generation: 4,
            certificate_fingerprint: certificate_fingerprint(&certificates.server_certificate),
            verifying_key: signing_key.verifying_key().to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(3_000_000),
        },
        certificates.server_certificate.as_ref(),
        &signing_key,
        UnixMicros::new(1_500_000),
    )?;
    let welcome_limits = WireLimits::new(32 * 1_024, 16 * 1_024, 128, 2_048)?;
    let welcome = authenticated.signed_welcome(
        &FederationNegotiationConfig::new(vec![version(1, 0), version(1, 2)], welcome_limits, 64)?,
        FederationWelcomeNonces::new([21; 32], [22; 32])?,
        &local_identity,
        9,
    )?;
    assert_eq!(welcome.session().remote_identity_generation, 1);
    assert_eq!(welcome.session().version, version(1, 2));
    send_federation(send, welcome.envelope(), welcome_limits).await?;
    let received_welcome = receive_federation(receive, limits).await?;
    let relationship_id = authenticated.relationship_id();
    let client_registry = FederationPeerRegistry::new([FederationPeerBinding {
        relationship_id,
        local_mesh_id: authenticated.remote_mesh_id(),
        remote_mesh_id: authenticated.local_mesh_id(),
        authority_epoch: 1,
        identity_generation: 4,
        certificate_fingerprint: certificate_fingerprint(&certificates.server_certificate),
        verifying_key: signing_key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(3_000_000),
    }])?;
    let mut welcome_replay = FederationReplayGuard::new(8, DurationMicros::new(1_000_000))?;
    let session = client_registry.authenticate_welcome(
        connection,
        &received_welcome,
        expectation,
        UnixMicros::new(1_500_000),
        &mut welcome_replay,
    )?;
    assert_eq!(session.version, version(1, 2));
    assert_eq!(session.remote_authority_revision, 9);
    assert_eq!(session.maximum_control_bytes, 32 * 1_024);
    assert_eq!(session.maximum_data_frame_bytes, 16 * 1_024);
    assert_eq!(session.maximum_streams, 64);
    assert!(matches!(
        client_registry.authenticate_welcome(
            connection,
            &received_welcome,
            expectation,
            UnixMicros::new(1_500_001),
            &mut welcome_replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    prove_hostile_federation_welcomes(
        &client_registry,
        connection,
        expectation,
        welcome.envelope(),
        &signing_key,
        limits,
    )?;
    prove_federation_authority_page(&mut AuthorityPageProof {
        send,
        receive,
        connection,
        registry: &client_registry,
        server_identity: &local_identity,
        authenticated,
        certificates,
        limits,
    })
    .await?;
    Ok(())
}

struct AuthorityPageProof<'a> {
    send: &'a mut quinn::SendStream,
    receive: &'a mut quinn::RecvStream,
    connection: &'a quinn::Connection,
    registry: &'a FederationPeerRegistry,
    server_identity: &'a FederationLocalIdentity<'a>,
    authenticated: &'a AuthenticatedFederationHello,
    certificates: &'a Certificates,
    limits: WireLimits,
}

async fn prove_federation_authority_page(
    proof: &mut AuthorityPageProof<'_>,
) -> Result<(), Box<dyn Error>> {
    let request_context = FederationExchangeContext::new(
        version(1, 2),
        [31; 16],
        [32; 16],
        [33; 16],
        UnixMicros::new(2_000_000),
        [30; 32],
    )?;
    let response_context = FederationExchangeContext::new(
        request_context.version,
        request_context.request_id,
        request_context.operation_id,
        request_context.trace_id,
        request_context.deadline,
        [34; 32],
    )?;
    let outbound = signed_federation_authority_page(
        proof.server_identity,
        response_context,
        9,
        vec![VersionedPayload {
            format_version: 1,
            canonical_bytes: b"restricted-authority-epoch-4".to_vec(),
        }],
        vec![35; 96],
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    send_federation(proof.send, outbound.envelope(), proof.limits).await?;
    let received = receive_federation(proof.receive, proof.limits).await?;
    let expected = FederationAuthorityPageExpectation::new(
        FederationLocalIdentityBinding {
            relationship_id: proof.authenticated.relationship_id(),
            local_mesh_id: proof.authenticated.remote_mesh_id(),
            remote_mesh_id: proof.authenticated.local_mesh_id(),
            authority_epoch: 1,
            identity_generation: 1,
            certificate_fingerprint: certificate_fingerprint(
                &proof.certificates.client_certificate,
            ),
            verifying_key: SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(3_000_000),
        },
        request_context,
        9,
    );
    let mut replay = FederationReplayGuard::new(8, DurationMicros::new(1_000_000))?;
    let page = proof.registry.authenticate_authority_page(
        proof.connection,
        &received,
        expected,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(page.authority_revision(), 9);
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.next_cursor(), &[35; 96]);
    assert!(matches!(
        proof.registry.authenticate_authority_page(
            proof.connection,
            &received,
            expected,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));

    let mut tampered = outbound.envelope().clone();
    let Some(FederationMessage::AuthorityPage(page)) = tampered.message.as_mut() else {
        unreachable!("fixture authority page")
    };
    page.records[0].canonical_bytes[0] ^= 1;
    let tampered = validated_federation(&tampered, proof.limits)?;
    let mut fresh_replay = FederationReplayGuard::new(8, DurationMicros::new(1_000_000))?;
    assert!(matches!(
        proof.registry.authenticate_authority_page(
            proof.connection,
            &tampered,
            expected,
            UnixMicros::new(1_500_000),
            &mut fresh_replay,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    federation_branch_page::prove_federation_branch_page(proof).await?;
    federation_content_layout::prove_federation_content_layout_page(proof).await?;
    federation_storage::prove_storage_capability_response(proof)?;
    Ok(())
}

fn prove_hostile_federation_hellos(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    original: &FederationEnvelope,
    signing_key: &SigningKey,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let now = UnixMicros::new(1_500_000);
    let mut replay = FederationReplayGuard::new(8, DurationMicros::new(1_000_000))?;

    let wrong_epoch = federation_hello_variant(original, signing_key, 11, 2_000_000, 2);
    assert!(matches!(
        registry.authenticate_hello(
            connection,
            &validated_federation(&wrong_epoch, limits)?,
            now,
            &mut replay,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));

    let mut bad_signature = federation_hello_variant(original, signing_key, 12, 2_000_000, 1);
    let Some(FederationMessage::Hello(hello)) = bad_signature.message.as_mut() else {
        unreachable!("fixture hello")
    };
    hello.signature[0] ^= 1;
    assert!(matches!(
        registry.authenticate_hello(
            connection,
            &validated_federation(&bad_signature, limits)?,
            now,
            &mut replay,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));

    for (nonce, deadline) in [(13, 1_500_000), (14, 2_500_001)] {
        let outside_window = federation_hello_variant(original, signing_key, nonce, deadline, 1);
        assert!(matches!(
            registry.authenticate_hello(
                connection,
                &validated_federation(&outside_window, limits)?,
                now,
                &mut replay,
            ),
            Err(TransportError::StaleFederationMessage)
        ));
    }

    let mut one_entry = FederationReplayGuard::new(1, DurationMicros::new(1_000_000))?;
    let first = federation_hello_variant(original, signing_key, 15, 2_000_000, 1);
    registry.authenticate_hello(
        connection,
        &validated_federation(&first, limits)?,
        now,
        &mut one_entry,
    )?;
    let second = federation_hello_variant(original, signing_key, 16, 2_000_000, 1);
    assert!(matches!(
        registry.authenticate_hello(
            connection,
            &validated_federation(&second, limits)?,
            now,
            &mut one_entry,
        ),
        Err(TransportError::FederationReplayCapacity)
    ));
    let Some(FederationMessage::Hello(hello)) = original.message.as_ref() else {
        unreachable!("fixture hello")
    };
    let certificate = CertificateDer::from(hello.public_identity_chain.clone());
    prove_signed_authority_fetch(registry, connection, &certificate, signing_key, limits)?;
    federation_branch_page::prove_signed_branch_fetch(
        registry,
        connection,
        &certificate,
        signing_key,
        limits,
    )?;
    federation_content_layout::prove_signed_content_layout_fetch(
        registry,
        connection,
        &certificate,
        signing_key,
        limits,
    )?;
    federation_storage::prove_signed_storage_capability_request(
        registry,
        connection,
        &certificate,
        signing_key,
        limits,
    )?;
    Ok(())
}

fn prove_hostile_federation_welcomes(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    expectation: &FederationHelloExpectation,
    original: &FederationEnvelope,
    signing_key: &SigningKey,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let now = UnixMicros::new(1_500_000);
    let mut replay = FederationReplayGuard::new(8, DurationMicros::new(1_000_000))?;
    let mut variants = Vec::new();

    let mut wrong_challenge = original.clone();
    welcome_mut(&mut wrong_challenge).request_challenge_nonce = vec![31; 32];
    variants.push(welcome_variant(wrong_challenge, signing_key, 31));

    let mut wrong_generation = original.clone();
    welcome_mut(&mut wrong_generation).identity_generation = 5;
    variants.push(welcome_variant(wrong_generation, signing_key, 32));

    let mut excessive_limit = original.clone();
    welcome_mut(&mut excessive_limit).maximum_control_bytes = 64 * 1_024 + 1;
    variants.push(welcome_variant(excessive_limit, signing_key, 33));

    let mut unsupported_version = original.clone();
    let unsupported = version(1, 9);
    let Some(header) = unsupported_version.header.as_mut() else {
        unreachable!("fixture header")
    };
    header.version = Some(unsupported);
    welcome_mut(&mut unsupported_version).selected_version = Some(unsupported);
    variants.push(welcome_variant(unsupported_version, signing_key, 34));

    let mut mismatched_header_version = original.clone();
    let Some(header) = mismatched_header_version.header.as_mut() else {
        unreachable!("fixture header")
    };
    header.version = Some(version(1, 0));
    variants.push(welcome_variant(mismatched_header_version, signing_key, 36));

    for variant in variants {
        assert!(matches!(
            registry.authenticate_welcome(
                connection,
                &validated_federation(&variant, limits)?,
                expectation,
                now,
                &mut replay,
            ),
            Err(TransportError::UntrustedFederationPeer)
        ));
    }

    let mut bad_signature = welcome_variant(original.clone(), signing_key, 35);
    welcome_mut(&mut bad_signature).signature[0] ^= 1;
    assert!(matches!(
        registry.authenticate_welcome(
            connection,
            &validated_federation(&bad_signature, limits)?,
            expectation,
            now,
            &mut replay,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    Ok(())
}

struct Certificates {
    authority_certificate: CertificateDer<'static>,
    server_certificate: CertificateDer<'static>,
    server_private_key: Vec<u8>,
    client_certificate: CertificateDer<'static>,
    client_private_key: Vec<u8>,
}

impl Certificates {
    fn server_credentials(&self) -> Result<NodeCredentials, TransportError> {
        NodeCredentials::new(
            vec![self.server_certificate.clone()],
            PrivatePkcs8KeyDer::from(self.server_private_key.clone()).into(),
        )
    }

    fn client_credentials(&self) -> Result<NodeCredentials, TransportError> {
        NodeCredentials::new(
            vec![self.client_certificate.clone()],
            PrivatePkcs8KeyDer::from(self.client_private_key.clone()).into(),
        )
    }
}

fn certificates() -> Result<Certificates, Box<dyn Error>> {
    let mut authority_parameters = CertificateParams::new(Vec::<String>::new())?;
    authority_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority_parameters
        .key_usages
        .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
    let authority_key = KeyPair::generate()?;
    let authority_certificate = authority_parameters.self_signed(&authority_key)?;
    let authority_der = authority_certificate.der().clone();
    let issuer = Issuer::new(authority_parameters, authority_key);
    let (server_certificate, server_private_key) = leaf(&issuer)?;
    let (client_certificate, client_private_key) = leaf(&issuer)?;
    Ok(Certificates {
        authority_certificate: authority_der,
        server_certificate,
        server_private_key,
        client_certificate,
        client_private_key,
    })
}

fn leaf(
    issuer: &Issuer<'_, KeyPair>,
) -> Result<(CertificateDer<'static>, Vec<u8>), Box<dyn Error>> {
    let mut parameters = CertificateParams::new(vec![CERTIFICATE_NAME.to_owned()])?;
    parameters
        .key_usages
        .push(KeyUsagePurpose::DigitalSignature);
    parameters.extended_key_usages.extend([
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ]);
    let key = KeyPair::generate()?;
    let certificate: Certificate = parameters.signed_by(&key, issuer)?;
    Ok((certificate.der().clone(), key.serialize_der()))
}

fn roots(certificate: &CertificateDer<'static>) -> Result<RootCertStore, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone())?;
    Ok(roots)
}

fn limits() -> Result<TransportLimits, Box<dyn Error>> {
    let wire = meshspan_protocol::WireLimits::new(64 * 1_024, 64 * 1_024, 256, 4_096)?;
    Ok(TransportLimits::new(
        wire,
        128,
        64 * 1_024,
        4 * 1_024 * 1_024,
    )?)
}

fn hello(mesh_id: MeshId, node_id: NodeId, incarnation: u64) -> NodeHello {
    NodeHello {
        versions: Vec::new(),
        mesh_id: mesh_id.as_bytes().to_vec(),
        node_id: node_id.as_bytes().to_vec(),
        incarnation,
        roles: Vec::new(),
        components: Vec::new(),
        feature_bits: Vec::new(),
        maximum_control_bytes: 1,
        maximum_data_frame_bytes: 1,
        maximum_streams: 1,
    }
}

fn federation_hello_variant(
    original: &FederationEnvelope,
    signing_key: &SigningKey,
    nonce: u8,
    deadline: i64,
    authority_epoch: u64,
) -> FederationEnvelope {
    let mut envelope = original.clone();
    let Some(header) = envelope.header.as_mut() else {
        unreachable!("fixture header")
    };
    header.replay_nonce = vec![nonce; 32];
    header.deadline_unix_micros = deadline;
    header.authority_epoch = authority_epoch;
    let Some(header) = envelope.header.as_ref() else {
        unreachable!("fixture header")
    };
    let Some(FederationMessage::Hello(hello)) = envelope.message.as_ref() else {
        unreachable!("fixture hello")
    };
    let signature = signing_key
        .sign(&federation_hello_signing_payload(header, hello))
        .to_bytes()
        .to_vec();
    let Some(FederationMessage::Hello(hello)) = envelope.message.as_mut() else {
        unreachable!("fixture hello")
    };
    hello.signature = signature;
    envelope
}

fn validated_federation(
    envelope: &FederationEnvelope,
    limits: WireLimits,
) -> Result<ValidatedFederationEnvelope, meshspan_protocol::WireContractError> {
    decode_federation_frame(&encode_federation_frame(envelope, limits)?, limits)
}

fn welcome_variant(
    mut envelope: FederationEnvelope,
    signing_key: &SigningKey,
    nonce: u8,
) -> FederationEnvelope {
    let Some(header) = envelope.header.as_mut() else {
        unreachable!("fixture header")
    };
    header.replay_nonce = vec![nonce; 32];
    let Some(header) = envelope.header.as_ref() else {
        unreachable!("fixture header")
    };
    let Some(FederationMessage::Welcome(welcome)) = envelope.message.as_ref() else {
        unreachable!("fixture welcome")
    };
    let signature = signing_key
        .sign(&federation_welcome_signing_payload(header, welcome))
        .to_bytes()
        .to_vec();
    welcome_mut(&mut envelope).signature = signature;
    envelope
}

fn welcome_mut(envelope: &mut FederationEnvelope) -> &mut meshspan_protocol::v1::FederationWelcome {
    let Some(FederationMessage::Welcome(welcome)) = envelope.message.as_mut() else {
        unreachable!("fixture welcome")
    };
    welcome
}

const fn version(major: u32, minor: u32) -> ProtocolVersion {
    ProtocolVersion { major, minor }
}

const fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn node(value: u8) -> Result<NodeId, Box<dyn Error>> {
    NodeId::from_bytes([value; 16]).map_err(|_| io::Error::other("invalid fixture node").into())
}
