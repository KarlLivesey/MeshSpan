// SPDX-License-Identifier: GPL-2.0-only

//! Separately bounded replication and leader-contact evidence with exact request correlation.

use std::collections::BTreeMap;

use super::types::{
    AppendProbeId, AppendRequest, AppendResponse, CoreError, LogPosition, ReadBarrierId,
};

const MAXIMUM_PROBES_PER_LANE: usize = 64;

#[derive(Clone, Copy)]
pub(super) enum ProbeKind {
    Replication,
    Contact,
}

#[derive(Default)]
pub(super) struct AppendProbes {
    replication: BTreeMap<AppendProbeId, AppendProbe>,
    contacts: BTreeMap<AppendProbeId, AppendProbe>,
    latest_replication: Option<AppendProbeId>,
}

#[derive(Eq, PartialEq)]
struct AppendProbe {
    previous: LogPosition,
    previous_digest: [u8; 32],
    through: LogPosition,
    digest: [u8; 32],
    read_barrier_id: Option<ReadBarrierId>,
}

pub(super) enum ProbeResult {
    Matched(u64),
    Conflict { previous_index: u64, latest: bool },
    Contact,
}

impl AppendProbes {
    pub(super) fn replication_id(&self, request: &AppendRequest) -> Option<AppendProbeId> {
        let proof = AppendProbe::from_request(request);
        self.replication
            .iter()
            .find_map(|(id, existing)| (*existing == proof).then_some(*id))
    }

    pub(super) fn sent(&mut self, request: &AppendRequest, kind: ProbeKind) {
        let outstanding = match kind {
            ProbeKind::Replication => {
                self.latest_replication = Some(request.probe_id);
                &mut self.replication
            }
            ProbeKind::Contact => &mut self.contacts,
        };
        outstanding.insert(request.probe_id, AppendProbe::from_request(request));
        if outstanding.len() > MAXIMUM_PROBES_PER_LANE {
            outstanding.pop_first();
        }
    }

    pub(super) fn receive(
        &mut self,
        response: &AppendResponse,
    ) -> Result<Option<ProbeResult>, CoreError> {
        let Some(id) = response.probe_id else {
            return Ok(None);
        };
        let (kind, probe) = if let Some(probe) = self.replication.get(&id) {
            (ProbeKind::Replication, probe)
        } else if let Some(probe) = self.contacts.get(&id) {
            (ProbeKind::Contact, probe)
        } else {
            return Ok(None);
        };
        if response.read_barrier_id != probe.read_barrier_id {
            return Err(CoreError::InvalidInput);
        }
        if response.accepted {
            if response.matched_index != probe.through.index
                || response.matched_digest != probe.digest
            {
                return Err(CoreError::InvalidInput);
            }
        } else if response.matched_index != 0 || response.matched_digest != [0; 32] {
            return Err(CoreError::InvalidInput);
        }
        let result = match kind {
            ProbeKind::Contact => ProbeResult::Contact,
            ProbeKind::Replication if response.accepted => {
                ProbeResult::Matched(probe.through.index)
            }
            ProbeKind::Replication => ProbeResult::Conflict {
                previous_index: probe.previous.index,
                latest: self.latest_replication == Some(id),
            },
        };
        match kind {
            ProbeKind::Replication => {
                self.replication.remove(&id);
            }
            ProbeKind::Contact => {
                self.contacts.remove(&id);
            }
        }
        Ok(Some(result))
    }
}

impl AppendProbe {
    fn from_request(request: &AppendRequest) -> Self {
        let (through, digest) = request
            .entries
            .last()
            .map_or((request.previous, request.previous_digest), |entry| {
                (entry.position, entry.entry_digest())
            });
        Self {
            previous: request.previous,
            previous_digest: request.previous_digest,
            through,
            digest,
            read_barrier_id: request.read_barrier_id,
        }
    }
}
