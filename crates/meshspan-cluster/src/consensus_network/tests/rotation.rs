// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[tokio::test]
async fn committed_overlap_keeps_old_connection_until_explicit_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    let (client, server, mut received) = cancellation::control_pair()?;
    confirm_control(&client, &server, &mut received, 61).await?;
    let original_connection = cached_connection(&client, &server)?.stable_id();
    let original = server.peer_routes()?.pop().ok_or("missing peer")?;
    let mut replacement = original.clone();
    replacement.certificate_der = CertificateAuthority::new()?
        .issue_node("meshspan.internal")?
        .certificate_der()
        .to_vec();
    server.upsert_peer_with_overlap(&replacement, Some(&original.certificate_der))?;
    confirm_control(&client, &server, &mut received, 62).await?;
    assert_eq!(
        cached_connection(&client, &server)?.stable_id(),
        original_connection
    );
    server.upsert_peer(&replacement)?;
    reject_retired_control(&client, &server, &mut received).await
}

#[tokio::test]
async fn replaced_certificate_cannot_reuse_an_admitted_control_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let (client, server, mut received) = cancellation::control_pair()?;
    confirm_control(&client, &server, &mut received, 41).await?;
    let mut replacement = server.peer_routes()?.pop().ok_or("missing peer")?;
    let authority = CertificateAuthority::new()?;
    replacement.certificate_der = authority
        .issue_node("meshspan.internal")?
        .certificate_der()
        .to_vec();
    server.upsert_peer(&replacement)?;
    reject_retired_control(&client, &server, &mut received).await
}

#[tokio::test]
async fn replaced_incarnation_cannot_reuse_an_admitted_control_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let (client, server, mut received) = cancellation::control_pair()?;
    confirm_control(&client, &server, &mut received, 42).await?;
    let mut replacement = server.peer_routes()?.pop().ok_or("missing peer")?;
    replacement.incarnation = 2;
    server.upsert_peer(&replacement)?;
    reject_retired_control(&client, &server, &mut received).await
}

#[tokio::test]
async fn unchanged_binding_keeps_an_admitted_control_connection_usable()
-> Result<(), Box<dyn std::error::Error>> {
    let (client, server, mut received) = cancellation::control_pair()?;
    confirm_control(&client, &server, &mut received, 43).await?;
    let original = cached_connection(&client, &server)?.stable_id();
    let unchanged = server.peer_routes()?.pop().ok_or("missing peer")?;
    server.upsert_peer(&unchanged)?;
    confirm_control(&client, &server, &mut received, 44).await?;
    assert_eq!(cached_connection(&client, &server)?.stable_id(), original);
    Ok(())
}

#[tokio::test]
async fn queued_admission_rechecks_identity_after_backpressure()
-> Result<(), Box<dyn std::error::Error>> {
    let (client, server, mut received) = cancellation::control_pair()?;
    confirm_control(&client, &server, &mut received, 46).await?;
    let connection = cached_connection(&client, &server)?;
    let authenticated = client
        .peers
        .read()
        .map_err(|_| "poisoned peers")?
        .registry
        .authenticate_connection(&connection)?;
    let (sender, mut queue) = mpsc::channel(1);
    sender.send(1_u8).await?;
    let admission = client.admit_peer_message(authenticated, &sender, 2_u8);
    tokio::pin!(admission);
    std::future::poll_fn(|context| {
        assert!(std::future::Future::poll(admission.as_mut(), context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let mut replacement = client.peer_routes()?.pop().ok_or("missing peer")?;
    replacement.incarnation = 2;
    client.upsert_peer(&replacement)?;
    assert_eq!(queue.recv().await, Some(1));
    assert!(matches!(
        admission.await,
        Err(ConsensusNetworkError::Transport(
            meshspan_transport::TransportError::UntrustedPeer
        ))
    ));
    assert!(
        queue.try_recv().is_err(),
        "retired work consumed the released slot"
    );
    Ok(())
}

async fn confirm_control(
    client: &ConsensusNetwork,
    server: &ConsensusNetwork,
    received: &mut mpsc::Receiver<PeerControlRequest>,
    identifier: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let operation = OperationId::from_bytes([identifier; 16])?;
    let request = control_request(client, operation, u64::from(identifier))?;
    let caller = client.clone();
    let peer = server.local_node_id();
    let call = tokio::spawn(async move { caller.request_control(peer, &request).await });
    let incoming = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await?
        .ok_or("control request missing")?;
    incoming
        .respond
        .send(control_response(server, operation, u64::from(identifier))?)
        .map_err(|_| "control response closed")?;
    let response = tokio::time::timeout(Duration::from_secs(5), call).await???;
    assert_eq!(
        response.as_inner().message,
        Some(Message::Pong(Pong {
            nonce: u64::from(identifier),
            sent_monotonic_micros: u64::from(identifier),
            received_monotonic_micros: u64::from(identifier),
        }))
    );
    Ok(())
}

async fn reject_retired_control(
    client: &ConsensusNetwork,
    server: &ConsensusNetwork,
    received: &mut mpsc::Receiver<PeerControlRequest>,
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = cached_connection(client, server)?;
    let request = control_request(client, OperationId::from_bytes([45; 16])?, 45)?;
    let call = client.request_control(server.local_node_id(), &request);
    tokio::pin!(call);
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut call => assert!(result.is_err(), "retired identity was accepted"),
            request = received.recv() => {
                assert!(request.is_none(), "retired identity reached control authority");
                return Err("control authority unexpectedly closed".into());
            }
        }
        connection.closed().await;
        assert!(received.try_recv().is_err(), "retired request was queued");
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    Ok(())
}

fn cached_connection(
    client: &ConsensusNetwork,
    server: &ConsensusNetwork,
) -> Result<quinn::Connection, Box<dyn std::error::Error>> {
    Ok(client
        .control_connections
        .lock()
        .map_err(|_| "poisoned cache")?
        .get(&server.local_node_id())
        .cloned()
        .ok_or("connection was not cached")?)
}
