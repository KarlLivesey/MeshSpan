// SPDX-License-Identifier: GPL-2.0-only

//! Byte reservations survive network cancellation and ownership transfer into the authority queue.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use meshspan_domain::NodeId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAXIMUM_BODY_BYTES: usize = meshspan_protocol::MAXIMUM_CONSENSUS_BULK_BODY_BYTES;
const MAXIMUM_PEER_BYTES: usize = 64 * 1024 * 1024;
const MAXIMUM_AGGREGATE_BYTES: usize = 128 * 1024 * 1024;
const FRAME_SCRATCH_BYTES: usize = 2 * 64 * 1024;
const ENTRY_ALLOCATION_BYTES: usize = 64
    * (std::mem::size_of::<meshspan_consensus::LogEntry>()
        + std::mem::size_of::<meshspan_protocol::v1::LogEntry>());

pub(crate) struct ConsensusByteBudgets {
    aggregate: Arc<Semaphore>,
    peers: Mutex<BTreeMap<NodeId, Weak<Semaphore>>>,
}

impl ConsensusByteBudgets {
    pub(crate) fn new() -> Self {
        Self {
            aggregate: Arc::new(Semaphore::new(MAXIMUM_AGGREGATE_BYTES)),
            peers: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn reserve(
        &self,
        peer: NodeId,
        body_bytes: usize,
    ) -> Result<Arc<ConsensusByteReservation>, ByteBudgetError> {
        let charge = allocation_charge(body_bytes).ok_or(ByteBudgetError::InvalidLength)?;
        // Weak entries retain one semaphore while a reservation is alive, including across
        // route removal/re-enrolment. Dead peer keys are collected before every acquisition.
        let mut peers = self
            .peers
            .lock()
            .map_err(|_| ByteBudgetError::Unavailable)?;
        peers.retain(|_, value| value.strong_count() > 0);
        let peer = peers.get(&peer).and_then(Weak::upgrade).unwrap_or_else(|| {
            let budget = Arc::new(Semaphore::new(MAXIMUM_PEER_BYTES));
            peers.insert(peer, Arc::downgrade(&budget));
            budget
        });
        let aggregate = Arc::clone(&self.aggregate)
            .try_acquire_many_owned(charge)
            .map_err(|_| ByteBudgetError::Unavailable)?;
        let peer = peer
            .try_acquire_many_owned(charge)
            .map_err(|_| ByteBudgetError::Unavailable)?;
        Ok(Arc::new(ConsensusByteReservation {
            _aggregate: aggregate,
            _peer: peer,
        }))
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ByteBudgetError {
    #[error("invalid consensus transfer size")]
    InvalidLength,
    #[error("consensus transfer allocation budget unavailable")]
    Unavailable,
}

/// Memory ownership, not replication evidence. The outer peer message retains this reservation.
#[derive(Debug)]
pub(crate) struct ConsensusByteReservation {
    _aggregate: OwnedSemaphorePermit,
    _peer: OwnedSemaphorePermit,
}

fn allocation_charge(body_bytes: usize) -> Option<u32> {
    if body_bytes == 0 || body_bytes > MAXIMUM_BODY_BYTES {
        return None;
    }
    // The input body, decoded Protobuf commands and rebuilt core commands can coexist.
    // Frame scratch and both entry vectors are charged in addition to their byte payloads.
    let bytes = body_bytes
        .checked_mul(3)?
        .checked_add(FRAME_SCRATCH_BYTES)?
        .checked_add(ENTRY_ALLOCATION_BYTES)?;
    u32::try_from(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_clone_keeps_capacity_until_last_owner_releases()
    -> Result<(), Box<dyn std::error::Error>> {
        let budgets = ConsensusByteBudgets::new();
        let peer = NodeId::from_bytes([1; 16])?;
        let reservation = budgets
            .reserve(peer, MAXIMUM_BODY_BYTES)
            .map_err(|_| "reservation failed")?;
        let queued = Arc::clone(&reservation);
        drop(reservation);
        assert!(budgets.reserve(peer, MAXIMUM_BODY_BYTES).is_err());
        drop(queued);
        assert!(budgets.reserve(peer, MAXIMUM_BODY_BYTES).is_ok());
        Ok(())
    }

    #[test]
    fn aggregate_limit_and_failed_peer_reservation_do_not_leak_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let budgets = ConsensusByteBudgets::new();
        let peers = [
            NodeId::from_bytes([1; 16])?,
            NodeId::from_bytes([2; 16])?,
            NodeId::from_bytes([3; 16])?,
        ];
        let first = budgets
            .reserve(peers[0], MAXIMUM_BODY_BYTES)
            .map_err(|_| "first reservation failed")?;
        assert!(budgets.reserve(peers[0], MAXIMUM_BODY_BYTES).is_err());
        let second = budgets
            .reserve(peers[1], MAXIMUM_BODY_BYTES)
            .map_err(|_| "second reservation failed")?;
        assert!(budgets.reserve(peers[2], MAXIMUM_BODY_BYTES).is_err());
        drop(first);
        assert!(budgets.reserve(peers[2], MAXIMUM_BODY_BYTES).is_ok());
        drop(second);
        assert_eq!(
            budgets.aggregate.available_permits(),
            MAXIMUM_AGGREGATE_BYTES
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_a_blocked_queue_send_releases_its_owned_reservation()
    -> Result<(), Box<dyn std::error::Error>> {
        let budgets = ConsensusByteBudgets::new();
        let peer = NodeId::from_bytes([1; 16])?;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        sender.send(None).await?;
        let reservation = budgets.reserve(peer, MAXIMUM_BODY_BYTES)?;
        let sending = tokio::spawn(async move { sender.send(Some(reservation)).await });
        assert!(budgets.reserve(peer, MAXIMUM_BODY_BYTES).is_err());
        sending.abort();
        assert!(sending.await.is_err_and(|error| error.is_cancelled()));
        assert!(budgets.reserve(peer, MAXIMUM_BODY_BYTES).is_ok());
        assert!(receiver.recv().await.is_some_and(|item| item.is_none()));
        Ok(())
    }

    #[test]
    fn malformed_body_sizes_are_rejected_before_reservation() {
        assert_eq!(allocation_charge(0), None);
        assert_eq!(allocation_charge(MAXIMUM_BODY_BYTES + 1), None);
        assert_eq!(allocation_charge(usize::MAX), None);
        assert!(allocation_charge(MAXIMUM_BODY_BYTES).is_some());
    }
}
