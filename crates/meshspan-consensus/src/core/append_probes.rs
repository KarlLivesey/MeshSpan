// SPDX-License-Identifier: GPL-2.0-only

//! Bounded request correlation; only an exact outstanding probe supplies replication evidence.

use std::collections::BTreeMap;

use super::types::{
    AppendProbeId, AppendRequest, AppendResponse, CoreError, LogPosition, ReadBarrierId,
};

const MAXIMUM_OUTSTANDING_PROBES: usize = 64;

#[derive(Default)]
pub(super) struct AppendProbes {
    outstanding: BTreeMap<AppendProbeId, AppendProbe>,
    latest: Option<AppendProbeId>,
}

struct AppendProbe {
    previous: LogPosition,
    through: LogPosition,
    digest: [u8; 32],
    read_barrier_id: Option<ReadBarrierId>,
}

pub(super) enum ProbeResult {
    Matched(u64),
    Conflict { previous_index: u64, latest: bool },
}

impl AppendProbes {
    pub(super) fn sent(&mut self, request: &AppendRequest) {
        let (through, digest) = request
            .entries
            .last()
            .map_or((request.previous, request.previous_digest), |entry| {
                (entry.position, entry.entry_digest())
            });
        self.outstanding.insert(
            request.probe_id,
            AppendProbe {
                previous: request.previous,
                through,
                digest,
                read_barrier_id: request.read_barrier_id,
            },
        );
        self.latest = Some(request.probe_id);
        if self.outstanding.len() > MAXIMUM_OUTSTANDING_PROBES {
            self.outstanding.pop_first();
        }
    }

    pub(super) fn receive(
        &mut self,
        response: &AppendResponse,
    ) -> Result<Option<ProbeResult>, CoreError> {
        let Some(id) = response.probe_id else {
            return Ok(None);
        };
        let Some(probe) = self.outstanding.get(&id) else {
            return Ok(None);
        };
        if response.read_barrier_id != probe.read_barrier_id {
            return Err(CoreError::InvalidInput);
        }
        let result = if response.accepted {
            if response.matched_index != probe.through.index
                || response.matched_digest != probe.digest
            {
                return Err(CoreError::InvalidInput);
            }
            ProbeResult::Matched(probe.through.index)
        } else {
            if response.matched_index != 0 || response.matched_digest != [0; 32] {
                return Err(CoreError::InvalidInput);
            }
            ProbeResult::Conflict {
                previous_index: probe.previous.index,
                latest: self.latest == Some(id),
            }
        };
        self.outstanding.remove(&id);
        Ok(Some(result))
    }
}
