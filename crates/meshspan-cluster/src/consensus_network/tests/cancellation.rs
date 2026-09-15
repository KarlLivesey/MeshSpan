// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[tokio::test]
async fn missing_kind_prefix_does_not_block_or_cancel_other_control_streams()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = control_pair()?;
    let peer = second.local_node_id();
    let connection = first.control_connection(peer).await?;
    let (mut delayed_send, mut delayed_receive) = connection.open_bi().await?;
    let delayed_operation = OperationId::from_bytes([48; 16])?;
    let immediate_operation = OperationId::from_bytes([49; 16])?;
    let request = control_request(&first, immediate_operation, 2)?;
    let client = first.clone();
    let immediate = tokio::spawn(async move { client.request_control(peer, &request).await });
    // Opening the later stream makes the preceding empty stream visible to the peer.
    // Its absent kind byte must not block this complete request or lose the earlier stream
    // when the complete request's worker is reaped.
    let held = tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await?
        .ok_or("complete request was blocked behind an absent stream kind")?;
    let expected = control_response(&second, immediate_operation, 2)?;
    held.respond
        .send(expected.clone())
        .map_err(|_| "response cancelled")?;
    assert_eq!(immediate.await??.as_inner(), &expected);

    delayed_send
        .write_all(&[StreamKind::Metadata as u8])
        .await?;
    send_control(
        &mut delayed_send,
        &control_request(&first, delayed_operation, 1)?,
        first.wire_limits,
    )
    .await?;
    delayed_send.finish()?;
    let held = tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await?
        .ok_or("delayed request was cancelled by another stream completing")?;
    let expected = control_response(&second, delayed_operation, 1)?;
    held.respond
        .send(expected.clone())
        .map_err(|_| "delayed response cancelled")?;
    let response = tokio::time::timeout(
        Duration::from_secs(2),
        receive_control(&mut delayed_receive, first.wire_limits),
    )
    .await??;
    assert_eq!(response.as_inner(), &expected);
    assert!(connection.close_reason().is_none());
    first.shutdown().await?;
    second.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn missing_kind_prefix_expires_without_closing_shared_transport()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = control_pair()?;
    let peer = second.local_node_id();
    let connection = first.control_connection(peer).await?;
    let (_delayed_send, mut delayed_receive) = connection.open_bi().await?;
    let operation = OperationId::from_bytes([50; 16])?;
    let request = control_request(&first, operation, 3)?;
    let client = first.clone();
    let immediate = tokio::spawn(async move { client.request_control(peer, &request).await });
    let held = tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await?
        .ok_or("complete request was blocked")?;
    let expected = control_response(&second, operation, 3)?;
    held.respond
        .send(expected.clone())
        .map_err(|_| "response cancelled")?;
    assert_eq!(immediate.await??.as_inner(), &expected);
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), delayed_receive.read(&mut byte)).await??,
        None,
        "expired stream unexpectedly returned a success response",
    );
    assert!(connection.close_reason().is_none());
    let request = control_request(&first, operation, 3)?;
    let client = first.clone();
    let later = tokio::spawn(async move { client.request_control(peer, &request).await });
    let held = tokio::time::timeout(Duration::from_secs(2), received.recv())
        .await?
        .ok_or("expired prefix stopped later requests")?;
    held.respond
        .send(expected.clone())
        .map_err(|_| "later response cancelled")?;
    assert_eq!(later.await??.as_inner(), &expected);
    first.shutdown().await?;
    second.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn failed_control_handler_does_not_cancel_another_request_on_the_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = control_pair()?;
    let peer = second.local_node_id();
    let operation = OperationId::from_bytes([45; 16])?;
    let request = control_request(&first, operation, 1)?;
    let client = first.clone();
    let failing = tokio::spawn(async move { client.request_control(peer, &request).await });
    let failed_request = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await?
        .ok_or("first request missing")?;
    let connection = first
        .control_connections
        .lock()
        .map_err(|_| "cache lock")?
        .get(&peer)
        .ok_or("connection missing")?
        .clone();
    let operation = OperationId::from_bytes([46; 16])?;
    let request = control_request(&first, operation, 2)?;
    let client = first.clone();
    let surviving = tokio::spawn(async move { client.request_control(peer, &request).await });
    let surviving_request = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await?
        .ok_or("second request missing")?;
    // Both requests are authenticated and fully decoded. Only one application
    // handler fails; it is not evidence that this peer's other streams are bad.
    drop(failed_request.respond);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), failing)
            .await??
            .is_err()
    );
    let expected = control_response(&second, operation, 2)?;
    let sent = surviving_request.respond.send(expected.clone());
    let response = tokio::time::timeout(Duration::from_secs(5), surviving).await??;
    assert!(
        sent.is_ok(),
        "failed handler cancelled the other response producer"
    );
    assert_eq!(response?.as_inner(), &expected);
    assert!(
        connection.close_reason().is_none(),
        "application failure closed shared transport"
    );
    Ok(())
}

#[tokio::test]
async fn late_response_to_cancelled_call_does_not_close_shared_transport()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = control_pair()?;
    let peer = second.local_node_id();
    let operation = OperationId::from_bytes([47; 16])?;
    let request = control_request(&first, operation, 1)?;
    let client = first.clone();
    let cancelled = tokio::spawn(async move { client.request_control(peer, &request).await });
    let held = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await?
        .ok_or("control request missing")?;
    let connection = first
        .control_connections
        .lock()
        .map_err(|_| "cache lock")?
        .get(&peer)
        .ok_or("connection missing")?
        .clone();
    cancelled.abort();
    assert!(cancelled.await.is_err_and(|error| error.is_cancelled()));
    // Cancellation itself must leave the connection alive. This also allows
    // STOP_SENDING to reach the server before its delayed application response.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), connection.closed())
            .await
            .is_err()
    );
    held.respond
        .send(control_response(&second, operation, 1)?)
        .map_err(|_| "application response producer was cancelled")?;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), connection.closed())
            .await
            .is_err(),
        "responding to a cancelled request closed shared transport"
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_control_call_evicts_only_its_cached_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = control_pair()?;
    let peer = second.local_node_id();
    let operation = OperationId::from_bytes([35; 16])?;
    let request = control_request(&first, operation, 1)?;
    let client = first.clone();
    let cancelled = tokio::spawn(async move { client.request_control(peer, &request).await });
    let held = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await?
        .ok_or("control request missing")?;
    let original = first
        .control_connections
        .lock()
        .map_err(|_| "poisoned cache")?
        .get(&peer)
        .ok_or("connection was not cached")?
        .stable_id();
    cancelled.abort();
    assert!(cancelled.await.is_err_and(|error| error.is_cancelled()));
    assert!(
        !first
            .control_connections
            .lock()
            .map_err(|_| "poisoned cache")?
            .contains_key(&peer),
        "cancellation left a potentially dead connection cached"
    );

    // A retry gets a new connection while the old server-side operation remains unresolved.
    // Eviction is not a claim that the old operation was undone, nor an automatic retry.
    let operation = OperationId::from_bytes([36; 16])?;
    let request = control_request(&first, operation, 2)?;
    let client = first.clone();
    let retried = tokio::spawn(async move { client.request_control(peer, &request).await });
    let next = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await?
        .ok_or("fresh control request missing")?;
    let replacement = first
        .control_connections
        .lock()
        .map_err(|_| "poisoned cache")?
        .get(&peer)
        .ok_or("replacement was not cached")?
        .stable_id();
    assert_ne!(original, replacement);
    next.respond
        .send(control_response(&second, operation, 2)?)
        .map_err(|_| "response closed")?;
    assert!(retried.await?.is_ok());
    drop(held);
    Ok(())
}

#[tokio::test]
async fn cancelled_old_call_cannot_evict_a_newer_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, mut received) = control_pair()?;
    let peer = second.local_node_id();
    let request = control_request(&first, OperationId::from_bytes([37; 16])?, 3)?;
    let client = first.clone();
    let old_call = tokio::spawn(async move { client.request_control(peer, &request).await });
    let held = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await?
        .ok_or("old request missing")?;
    // Model another failed stream removing the original cache entry while this call waits.
    first
        .control_connections
        .lock()
        .map_err(|_| "poisoned cache")?
        .remove(&peer);
    let operation = OperationId::from_bytes([38; 16])?;
    let request = control_request(&first, operation, 4)?;
    let client = first.clone();
    let new_call = tokio::spawn(async move { client.request_control(peer, &request).await });
    let next = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await?
        .ok_or("new request missing")?;
    let replacement = first
        .control_connections
        .lock()
        .map_err(|_| "poisoned cache")?
        .get(&peer)
        .ok_or("replacement missing")?
        .stable_id();
    old_call.abort();
    assert!(old_call.await.is_err_and(|error| error.is_cancelled()));
    assert_eq!(
        first
            .control_connections
            .lock()
            .map_err(|_| "poisoned cache")?
            .get(&peer)
            .ok_or("old call evicted replacement")?
            .stable_id(),
        replacement
    );
    next.respond
        .send(control_response(&second, operation, 4)?)
        .map_err(|_| "response closed")?;
    assert!(new_call.await?.is_ok());
    drop(held);
    Ok(())
}

pub(super) fn control_pair() -> Result<
    (
        ConsensusNetwork,
        ConsensusNetwork,
        mpsc::Receiver<PeerControlRequest>,
    ),
    Box<dyn std::error::Error>,
> {
    let authority = CertificateAuthority::new()?;
    let first_identity = authority.issue_node("meshspan.internal")?;
    let second_identity = authority.issue_node("meshspan.internal")?;
    let first_node = NodeId::from_bytes([31; 16])?;
    let second_node = NodeId::from_bytes([32; 16])?;
    let bind_address = SocketAddr::from(([127, 0, 0, 1], 0));
    let mesh_id = MeshId::from_bytes([33; 16])?;
    let partition_id = PartitionId::from_bytes([34; 16])?;
    let anchor = authority.certificate_der().to_vec();
    let (first_messages, _first_received) = mpsc::channel(8);
    let (second_messages, _second_received) = mpsc::channel(8);
    let (controls, received_controls) = mpsc::channel(4);
    let mut first_config = config(
        first_node,
        bind_address,
        &first_identity,
        anchor.clone(),
        peer(second_node, bind_address, second_identity.certificate_der()),
        mesh_id,
        partition_id,
    );
    first_config.peers.clear();
    // Discover addresses from live sockets rather than releasing an ephemeral
    // reservation before binding, which races concurrent network/process tests.
    let first = ConsensusNetwork::start(first_config, first_messages)?;
    let first_address = first.transport.server_endpoint()?.local_addr()?;
    let second = ConsensusNetwork::start_with_control(
        config(
            second_node,
            bind_address,
            &second_identity,
            anchor,
            peer(first_node, first_address, first_identity.certificate_der()),
            mesh_id,
            partition_id,
        ),
        second_messages,
        controls,
    )?;
    first.upsert_peer(&peer(
        second_node,
        second.transport.server_endpoint()?.local_addr()?,
        second_identity.certificate_der(),
    ))?;
    Ok((first, second, received_controls))
}
