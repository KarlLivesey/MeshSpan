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
    ControlEnvelope, DataControlEnvelope, DataFrame, FederationEnvelope, FederationHeader,
    FederationHello, NodeHello, Ping, ProtocolVersion, PutShardFinish,
};
use meshspan_protocol::{
    ValidatedFederationEnvelope, WireLimits, decode_federation_frame, encode_federation_frame,
    federation_hello_signing_payload,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::identity::certificate_fingerprint;
use super::{
    FederationPeerBinding, FederationPeerRegistry, FederationReplayGuard, NegotiationConfig,
    NodeCredentials, PeerBinding, PeerRegistry, StreamKind, TransportError, TransportLimits,
    accept_stream, client_endpoint, connect, open_stream, receive_control, receive_data_control,
    receive_data_frame, receive_federation, send_control, send_data_control, send_data_frame,
    send_federation, server_endpoint,
};

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
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let envelope = federation_hello(&certificates.client_certificate, &signing_key);
    let (mut send, _receive) = open_stream(&client_connection, StreamKind::Federation).await?;
    let mut accepted = accept_stream(&server_connection).await?;
    assert_eq!(accepted.kind, StreamKind::Federation);
    send_federation(&mut send, &envelope, limits.wire).await?;
    let received = receive_federation(&mut accepted.receive, limits.wire).await?;
    assert_eq!(received.as_inner(), &envelope);
    let relationship_id = FederationRelationshipId::from_bytes([1; 16])?;
    let remote_mesh_id = MeshId::from_bytes([2; 16])?;
    let local_mesh_id = MeshId::from_bytes([3; 16])?;
    let registry = FederationPeerRegistry::new([FederationPeerBinding {
        relationship_id,
        local_mesh_id,
        remote_mesh_id,
        authority_epoch: 1,
        identity_generation: 1,
        certificate_fingerprint: certificate_fingerprint(&certificates.client_certificate),
        verifying_key: signing_key.verifying_key().to_bytes(),
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
        &signing_key,
        limits.wire,
    )?;
    client_connection.close(0_u32.into(), b"test complete");
    server_connection.close(0_u32.into(), b"test complete");
    client.wait_idle().await;
    server.wait_idle().await;
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

fn federation_hello(
    certificate: &CertificateDer<'_>,
    signing_key: &SigningKey,
) -> FederationEnvelope {
    let mut envelope = FederationEnvelope {
        header: Some(FederationHeader {
            version: Some(version(1, 0)),
            relationship_id: vec![1; 16],
            sender_mesh_id: vec![2; 16],
            recipient_mesh_id: vec![3; 16],
            request_id: vec![4; 16],
            operation_id: vec![5; 16],
            authority_epoch: 1,
            deadline_unix_micros: 2_000_000,
            trace_id: vec![6; 16],
            replay_nonce: vec![7; 32],
        }),
        message: Some(FederationMessage::Hello(FederationHello {
            versions: vec![version(1, 0)],
            identity_generation: 1,
            public_identity_chain: certificate.as_ref().to_vec(),
            challenge_nonce: vec![9; 32],
            feature_bits: vec![1],
            maximum_control_bytes: 64 * 1_024,
            maximum_data_frame_bytes: 64 * 1_024,
            maximum_streams: 128,
            signature: vec![0; 64],
        })),
    };
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

const fn version(major: u32, minor: u32) -> ProtocolVersion {
    ProtocolVersion { major, minor }
}

const fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn node(value: u8) -> Result<NodeId, Box<dyn Error>> {
    NodeId::from_bytes([value; 16]).map_err(|_| io::Error::other("invalid fixture node").into())
}
