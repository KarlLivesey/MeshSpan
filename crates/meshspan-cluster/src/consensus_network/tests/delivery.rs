// SPDX-License-Identifier: GPL-2.0-only

//! Real UDP loss distinguishes delivery deadlines from slow authority execution.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn control_request_is_not_admitted_before_its_end_marker()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = cancellation::control_pair()?;
    let connection = first.connect_peer(second.local_node_id()).await?;
    let operation = OperationId::from_bytes([48; 16])?;
    let request = control_request(&first, operation, 1)?;
    let (mut send, mut receive) = open_stream(&connection, StreamKind::Metadata).await?;
    send_control(&mut send, &request, first.wire_limits).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), received.recv())
            .await
            .is_err(),
        "an unfinished request reached its application handler"
    );
    send.finish()?;
    let request = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await?
        .ok_or("finished request missing")?;
    let expected = control_response(&second, operation, 1)?;
    request
        .respond
        .send(expected.clone())
        .map_err(|_| "response closed")?;
    let actual = tokio::time::timeout(
        Duration::from_secs(5),
        receive_control(&mut receive, first.wire_limits),
    )
    .await??;
    assert_eq!(actual.as_inner(), &expected);
    Ok(())
}

#[tokio::test]
async fn control_request_with_trailing_bytes_never_reaches_the_handler()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = cancellation::control_pair()?;
    let connection = first.connect_peer(second.local_node_id()).await?;
    let request = control_request(&first, OperationId::from_bytes([49; 16])?, 1)?;
    let (mut send, _receive) = open_stream(&connection, StreamKind::Metadata).await?;
    send_control(&mut send, &request, first.wire_limits).await?;
    send.write_all(&[1]).await?;
    send.finish()?;
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            _closed = connection.closed() => {},
            request = received.recv() => assert!(request.is_none(), "trailing input reached the handler"),
        }
    }).await?;
    assert!(
        received.try_recv().is_err(),
        "trailing input reached the handler"
    );
    Ok(())
}

#[tokio::test]
async fn lost_cached_control_path_is_evicted_before_the_authority_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = cancellation::control_pair()?;
    let peer = second.local_node_id();
    let mut route = first.peers.read().map_err(|_| "peer lock")?.routes[&peer].clone();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let server = route.address;
    route.address = socket.local_addr()?;
    first.upsert_peer(&route)?;
    let blocked = Arc::new(AtomicBool::new(false));
    let relay_blocked = Arc::clone(&blocked);
    let relay = tokio::spawn(relay_packets(socket, server, relay_blocked));
    let proof = tokio::time::timeout(Duration::from_secs(10), async {
        let operation = OperationId::from_bytes([41; 16])?;
        let request = control_request(&first, operation, 1)?;
        let initial = first.request_control(peer, &request);
        let answer = async {
            let request = received.recv().await.ok_or("initial request absent")?;
            request
                .respond
                .send(control_response(&second, operation, 1)?)
                .map_err(|_| "initial response closed")?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let (result, answered) = tokio::join!(initial, answer);
        result?;
        answered?;
        blocked.store(true, Ordering::SeqCst);
        let request = control_request(&first, OperationId::from_bytes([42; 16])?, 2)?;
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            first.request_control(peer, &request),
        )
        .await;
        if !matches!(
            result,
            Ok(Err(ConsensusNetworkError::ControlDeliveryUnconfirmed))
        ) {
            return Err("undelivered request waited for the authority response deadline".into());
        }
        assert!(
            !first
                .control_connections
                .lock()
                .map_err(|_| "cache lock")?
                .contains_key(&peer),
            "failed delivery retained its stale connection"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await;
    relay.abort();
    match relay.await {
        Err(error) if error.is_cancelled() => {}
        Err(error) => return Err(error.into()),
        Ok(result) => result?,
    }
    proof?
}

#[tokio::test]
async fn delivered_control_request_can_wait_for_slow_authority_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = cancellation::control_pair()?;
    let operation = OperationId::from_bytes([43; 16])?;
    let request = control_request(&first, operation, 3)?;
    let client = first.request_control(second.local_node_id(), &request);
    let server = async {
        let received = received.recv().await.ok_or("request absent")?;
        tokio::time::sleep(PEER_OPERATION_TIMEOUT + Duration::from_millis(250)).await;
        received
            .respond
            .send(control_response(&second, operation, 3)?)
            .map_err(|_| "delivered request was cancelled during authority work")?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (response, answered) = tokio::join!(client, server);
    response?;
    answered
}

async fn relay_packets(
    socket: tokio::net::UdpSocket,
    server: SocketAddr,
    blocked: Arc<AtomicBool>,
) -> Result<(), std::io::Error> {
    let mut bytes = vec![0; 65_535];
    let mut client = None;
    loop {
        let (length, source) = socket.recv_from(&mut bytes).await?;
        if blocked.load(Ordering::SeqCst) {
            continue;
        }
        let destination = if source == server {
            client
        } else {
            client = Some(source);
            Some(server)
        };
        if let Some(destination) = destination {
            socket.send_to(&bytes[..length], destination).await?;
        }
    }
}
