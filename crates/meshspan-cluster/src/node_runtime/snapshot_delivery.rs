// SPDX-License-Identifier: GPL-2.0-only

//! Single-owner retry state retaining one immutable image until the learner catches up.

use std::sync::Arc;
use std::time::{Duration, Instant};

use meshspan_domain::NodeId;
use tokio::sync::oneshot;

use super::NodeRuntimeError;
use super::network::{OutboundSnapshot, PeerNetwork};

const RETRY_BACKOFF: Duration = Duration::from_millis(200);

pub(super) struct SnapshotDelivery {
    snapshot: Arc<OutboundSnapshot>,
    outstanding: Option<oneshot::Receiver<bool>>,
    retry_after: Instant,
    complete: bool,
}

impl SnapshotDelivery {
    pub(super) fn new(snapshot: OutboundSnapshot) -> Self {
        Self {
            snapshot: Arc::new(snapshot),
            outstanding: None,
            retry_after: Instant::now(),
            complete: false,
        }
    }

    pub(super) fn advance(
        &mut self,
        network: &PeerNetwork,
        learner: NodeId,
        matched_index: Option<u64>,
    ) -> Result<(), NodeRuntimeError> {
        if self.complete {
            return Ok(());
        }
        let now = Instant::now();
        let delivered = self.poll_delivery(now);
        // A verified append response proves catch-up even if the snapshot reply was lost.
        // This cancels obsolete transfer IO; it never reapplies an installed snapshot.
        let caught_up = matched_index
            .is_some_and(|index| index >= self.snapshot.manifest.backup.applied_position.index);
        if delivered || caught_up {
            self.finish()?;
        } else if self.outstanding.is_none() && now >= self.retry_after {
            self.outstanding = network.send_snapshot(learner, Arc::clone(&self.snapshot));
            self.retry_after = now + RETRY_BACKOFF;
        }
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<(), NodeRuntimeError> {
        if !self.complete {
            self.outstanding = None;
            std::fs::remove_file(&self.snapshot.path)?;
            self.complete = true;
        }
        Ok(())
    }

    fn poll_delivery(&mut self, now: Instant) -> bool {
        let Some(mut response) = self.outstanding.take() else {
            return false;
        };
        match response.try_recv() {
            Ok(true) => true,
            Ok(false) | Err(oneshot::error::TryRecvError::Closed) => {
                self.retry_after = now + RETRY_BACKOFF;
                false
            }
            Err(oneshot::error::TryRecvError::Empty) => {
                self.outstanding = Some(response);
                false
            }
        }
    }
}
