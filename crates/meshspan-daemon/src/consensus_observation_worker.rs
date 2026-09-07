// SPDX-License-Identifier: GPL-2.0-only

//! Independently scheduled, bounded local reactor reads. Never part of write admission.

use std::{future::Future, time::Duration};

use meshspan_cluster::MetadataAuthorityHandle;
use meshspan_domain::Clock as _;

use crate::{OperatingSystemClock, runtime_observations::RuntimeObservations};

pub(crate) struct ConsensusObservationWorker {
    authority: MetadataAuthorityHandle,
    observations: RuntimeObservations,
}

impl ConsensusObservationWorker {
    pub(crate) const fn new(
        authority: MetadataAuthorityHandle,
        observations: RuntimeObservations,
    ) -> Self {
        Self {
            authority,
            observations,
        }
    }

    pub(crate) async fn run_until<F>(self, shutdown: F)
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        let mut ticks = tokio::time::interval(Duration::from_secs(1));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = &mut shutdown => return,
                _tick = ticks.tick() => {}
            }
            let observation = tokio::select! {
                () = &mut shutdown => return,
                result = tokio::time::timeout(Duration::from_millis(500), self.authority.observe()) => result,
            };
            let now = OperatingSystemClock.now();
            match observation {
                Ok(Ok(value)) => self.observations.record_consensus(value, now),
                Ok(Err(_)) | Err(_) => self.observations.record_consensus_unavailable(now),
            }
        }
    }
}
