// SPDX-License-Identifier: GPL-2.0-only

//! Closing transport admission must not masquerade as completion of owned network work.

use super::*;

#[tokio::test]
async fn shutdown_waits_for_admitted_bulk_worker() -> Result<(), Box<dyn std::error::Error>> {
    let (first, second, _incoming) = bulk::pair()?;
    let blocked = Arc::clone(&first.bulk_codecs).acquire_many_owned(2).await?;
    let retained = Arc::downgrade(&first.bulk_budgets);
    first.send(
        second.local_node_id(),
        bulk::append(first.local_node_id(), 70 * 1024)?,
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while first.next_request.load(Ordering::Relaxed) == 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let (started, received) = oneshot::channel();
    let waiter = tokio::spawn(async move {
        started
            .send(())
            .map_err(|()| ConsensusNetworkError::AuthorityStopped)?;
        shutdown_network(&first).await
    });
    received.await?;
    let completed_before_worker_release = waiter.is_finished();
    let descendants_retained_network = retained.upgrade().is_some();
    drop(blocked);
    tokio::time::timeout(Duration::from_secs(5), waiter).await???;
    second.close()?;
    assert!(
        !completed_before_worker_release,
        "shutdown returned before the admitted worker was released; descendant retains network: {descendants_retained_network}"
    );
    assert!(
        retained.upgrade().is_none(),
        "shutdown retained owned network descendants"
    );
    Ok(())
}

async fn shutdown_network(network: &ConsensusNetwork) -> Result<(), ConsensusNetworkError> {
    network
        .shutdown()
        .await
        .map_err(|_| ConsensusNetworkError::AuthorityStopped)
}

#[tokio::test]
async fn canceled_shutdown_waiter_does_not_cancel_shared_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, _incoming) = bulk::pair()?;
    let blocked = Arc::clone(&first.bulk_codecs).acquire_many_owned(2).await?;
    first.send(
        second.local_node_id(),
        bulk::append(first.local_node_id(), 70 * 1024)?,
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while first.next_request.load(Ordering::Relaxed) == 1 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let (started, received) = oneshot::channel();
    let clone = first.clone();
    let canceled = tokio::spawn(async move {
        started.send(()).map_err(|()| "waiter signal closed")?;
        clone.shutdown().await.map_err(|_| "shutdown failed")
    });
    received.await?;
    assert!(
        !canceled.is_finished(),
        "first waiter bypassed owned worker"
    );
    let (started, received) = oneshot::channel();
    let clone = first.clone();
    let remaining = tokio::spawn(async move {
        started.send(()).map_err(|()| "waiter signal closed")?;
        clone.shutdown().await.map_err(|_| "shutdown failed")
    });
    received.await?;
    assert!(
        !remaining.is_finished(),
        "second waiter bypassed the shared supervisor"
    );
    canceled.abort();
    assert!(canceled.await.is_err_and(|error| error.is_cancelled()));
    assert!(
        !remaining.is_finished(),
        "cancellation discarded the shared supervisor"
    );
    drop(blocked);
    tokio::time::timeout(Duration::from_secs(5), remaining).await???;
    assert_eq!(first.shutdown().await, Ok(()));
    second.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn exhausted_worker_admission_preserves_previous_peer_route_and_queue()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, _incoming) = bulk::pair()?;
    let previous = first
        .peer_routes()?
        .into_iter()
        .next()
        .ok_or("peer route")?;
    let capacity = first.owner.outbound_slots();
    let held = Arc::clone(&capacity)
        .try_acquire_many_owned(u32::try_from(capacity.available_permits())?)?;
    let mut changed = previous.clone();
    changed.address = unused_udp_address()?;
    assert!(matches!(
        first.upsert_peer(&changed),
        Err(ConsensusNetworkError::NetworkBusy)
    ));
    assert!(
        first.peer_routes()? == vec![previous],
        "failed admission replaced the route"
    );
    let queue_alive = first
        .peers
        .read()
        .map_err(|_| "peer lock")?
        .outbound
        .get(&second.local_node_id())
        .is_some_and(|sender| !sender.is_closed());
    assert!(
        queue_alive,
        "failed admission closed the old outbound queue"
    );
    drop(held);
    first.shutdown().await?;
    second.shutdown().await?;
    assert_eq!(
        capacity.available_permits(),
        super::super::owned::MAXIMUM_OUTBOUND_WORKERS
    );
    Ok(())
}

#[tokio::test]
async fn unnegotiated_private_connection_is_drained_on_shutdown()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, _incoming) = bulk::pair()?;
    let route = first
        .peer_routes()?
        .into_iter()
        .next()
        .ok_or("peer route")?;
    // Complete TLS but deliberately never send NodeHello. The accepted connection remains owned.
    let connection = first
        .transport
        .connect(route.address, &route.certificate_name)
        .await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        while second.owner.connection_jobs() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    tokio::time::timeout(Duration::from_secs(2), second.shutdown()).await??;
    assert_eq!(second.owner.connection_jobs(), 0);
    tokio::time::timeout(Duration::from_secs(2), connection.closed()).await?;
    first.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn peer_registration_racing_close_is_owned_or_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let (first, second, _incoming) = bulk::pair()?;
    let mut changed = first
        .peer_routes()?
        .into_iter()
        .next()
        .ok_or("peer route")?;
    changed.address = unused_udp_address()?;
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let updating = first.clone();
    let updating_barrier = Arc::clone(&barrier);
    let update = tokio::task::spawn_blocking(move || {
        updating_barrier.wait();
        updating.upsert_peer(&changed)
    });
    let closing = first.clone();
    let close = tokio::task::spawn_blocking(move || {
        barrier.wait();
        closing.close()
    });
    let result = update.await?;
    close.await??;
    assert!(matches!(
        result,
        Ok(()) | Err(ConsensusNetworkError::AuthorityStopped)
    ));
    first.shutdown().await?;
    assert!(
        first
            .peers
            .read()
            .map_err(|_| "peer lock")?
            .outbound
            .is_empty()
    );
    assert_eq!(
        first.owner.outbound_slots().available_permits(),
        super::super::owned::MAXIMUM_OUTBOUND_WORKERS
    );
    second.shutdown().await?;
    Ok(())
}
