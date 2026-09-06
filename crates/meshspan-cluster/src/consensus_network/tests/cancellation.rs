// SPDX-License-Identifier: GPL-2.0-only

use super::*;

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

fn control_pair() -> Result<
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
    let first_address = unused_udp_address()?;
    let second_address = unused_udp_address()?;
    let mesh_id = MeshId::from_bytes([33; 16])?;
    let partition_id = PartitionId::from_bytes([34; 16])?;
    let anchor = authority.certificate_der().to_vec();
    let (first_messages, _first_received) = mpsc::channel(8);
    let (second_messages, _second_received) = mpsc::channel(8);
    let (controls, received_controls) = mpsc::channel(4);
    let first = ConsensusNetwork::start(
        config(
            first_node,
            first_address,
            &first_identity,
            anchor.clone(),
            peer(
                second_node,
                second_address,
                second_identity.certificate_der(),
            ),
            mesh_id,
            partition_id,
        ),
        first_messages,
    )?;
    let second = ConsensusNetwork::start_with_control(
        config(
            second_node,
            second_address,
            &second_identity,
            anchor,
            peer(first_node, first_address, first_identity.certificate_der()),
            mesh_id,
            partition_id,
        ),
        second_messages,
        controls,
    )?;
    Ok((first, second, received_controls))
}
