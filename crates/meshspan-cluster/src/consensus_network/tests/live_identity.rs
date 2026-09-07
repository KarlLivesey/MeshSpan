// SPDX-License-Identifier: GPL-2.0-only

use meshspan_test_certificates::{NodeIdentityKey, NodePublicIdentity};

use super::*;

#[tokio::test]
async fn network_selects_a_new_local_certificate_without_restarting_its_listener()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = CertificateAuthority::new()?;
    let first_identity = authority.issue_node("meshspan.internal")?;
    let second_identity = authority.issue_node("meshspan.internal")?;
    let first_node = NodeId::from_bytes([51; 16])?;
    let second_node = NodeId::from_bytes([52; 16])?;
    let first_address = unused_udp_address()?;
    let second_address = unused_udp_address()?;
    let mesh = MeshId::from_bytes([53; 16])?;
    let partition = PartitionId::from_bytes([54; 16])?;
    let (first_messages, _first_received) = mpsc::channel(2);
    let (second_messages, _second_received) = mpsc::channel(2);
    let (controls, mut received) = mpsc::channel(2);
    let first = ConsensusNetwork::start(
        config(
            first_node,
            first_address,
            &first_identity,
            authority.certificate_der().to_vec(),
            peer(
                second_node,
                second_address,
                second_identity.certificate_der(),
            ),
            mesh,
            partition,
        ),
        first_messages,
    )?;
    let second = ConsensusNetwork::start_with_control(
        config(
            second_node,
            second_address,
            &second_identity,
            authority.certificate_der().to_vec(),
            peer(first_node, first_address, first_identity.certificate_der()),
            mesh,
            partition,
        ),
        second_messages,
        controls,
    )?;
    assert_eq!(first.local_certificate()?.generation, 1);
    let identity = NodeIdentityKey::from_pkcs8(first_identity.private_key())?;
    let online = authority.issue_online_authority()?;
    let leaf = online.sign_node_public_identity(
        &NodePublicIdentity::from_sec1(identity.public_key_sec1())?,
        "meshspan.internal",
    )?;
    // Stage the new fingerprint while the routed/current certificate is still the old leaf.
    let current_peer = peer(first_node, first_address, first_identity.certificate_der());
    second.upsert_peer_with_overlap(&current_peer, Some(&leaf))?;
    let selected = first.install_local_certificate(
        2,
        NodeCredentials::new(
            vec![
                CertificateDer::from(leaf.clone()),
                CertificateDer::from(online.certificate_der().to_vec()),
            ],
            PrivatePkcs8KeyDer::from(identity.private_key_pkcs8().to_vec()).into(),
        )?,
    )?;
    assert_eq!(selected.generation, 2);
    assert_eq!(
        selected.certificate_fingerprint,
        <[u8; 32]>::from(Sha256::digest(&leaf))
    );
    assert_eq!(
        first.transport.server_endpoint().local_addr()?,
        first_address
    );
    let connection = first.connect_data_peer(second_node).await?;
    let operation = OperationId::from_bytes([55; 16])?;
    let request = control_request(&first, operation, 55)?;
    let call = first.request_control_on_connection(second_node, &request, &connection);
    let respond = async {
        let incoming = received.recv().await.ok_or("missing rotated request")?;
        assert_eq!(
            incoming.certificate_fingerprint,
            selected.certificate_fingerprint
        );
        assert_eq!(incoming.from, first_node);
        incoming
            .respond
            .send(control_response(&second, operation, 55)?)
            .map_err(|_| "response closed")?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (response, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::try_join!(async { call.await.map_err(Into::into) }, respond)
    })
    .await??;
    assert_eq!(
        response.as_inner().message,
        Some(Message::Pong(Pong {
            nonce: 55,
            sent_monotonic_micros: 55,
            received_monotonic_micros: 55,
        }))
    );
    Ok(())
}
