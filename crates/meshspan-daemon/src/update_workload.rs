// SPDX-License-Identifier: GPL-2.0-only

//! Owned local-content preparation, not a restart grant or a mesh-wide availability claim.

use super::{UpdateError, UpdateWorkloadStatus, identifier};
use crate::{NativeFilesystemRuntime, NativeStorageTarget, protected_file};
use meshspan_domain::{
    Clock as _, NodeId, OperationId, Revision, TargetId, UnixMicros, VolumeId, WorkId,
};
use meshspan_filesystem::{
    StripeReadRequest, VolumeReadAvailabilityProbe, VolumeReadAvailabilityProgress,
};
use meshspan_metadata::{
    AuthoritativeRepository, PageLimit, TopologyTargetCursor, UpdateNodePhase, UpdateRolloutRecord,
    UpdateRolloutState,
};
use meshspan_protocol::v1::{UpdateWorkloadObservation, UpdateWorkloadState};
use serde_json::json;
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};

pub(super) struct UpdateWorkloadPreparation {
    filesystem: NativeFilesystemRuntime,
    pass: Option<Box<Pass>>,
    status: UpdateWorkloadStatus,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Binding {
    rollout: WorkId,
    node: NodeId,
    incarnation: u64,
    sequence: u64,
    barrier: u64,
    revision: Revision,
}

struct Pass {
    binding: Binding,
    target_cursor: Option<TopologyTargetCursor>,
    targets_complete: bool,
    excluded: BTreeSet<TargetId>,
    volume: Option<VolumeId>,
    probe: Option<VolumeReadAvailabilityProbe>,
    volumes: u64,
    publications: u64,
    stripes: u64,
    complete: bool,
    observed_at: UnixMicros,
}

impl UpdateWorkloadPreparation {
    pub(super) const fn new(
        filesystem: NativeFilesystemRuntime,
        status: UpdateWorkloadStatus,
    ) -> Self {
        Self {
            filesystem,
            pass: None,
            status,
        }
    }

    /// Runs only in the updater's owned blocking job. A failed observation is replaced, never
    /// reused as restart evidence. Fresh process startup always starts a new scan.
    pub(super) fn tick(
        &mut self,
        reader: &AuthoritativeRepository,
        rollout: &UpdateRolloutRecord,
        directory: &Path,
    ) -> Result<(), UpdateError> {
        self.status
            .replace(None)
            .map_err(|()| UpdateError::Unavailable)?;
        let Some(binding) = preparation_binding(reader, rollout)? else {
            self.pass = None;
            return Ok(());
        };
        if self
            .pass
            .as_ref()
            .is_none_or(|pass| pass.binding != binding)
        {
            self.pass = Some(Box::new(Pass::new(binding)));
        }
        let pass = self.pass.as_mut().ok_or(UpdateError::Failed)?;
        let result = pass.advance(&self.filesystem, reader);
        let state = match &result {
            Ok(()) if pass.complete => UpdateWorkloadState::LocalContentChecked,
            Ok(()) => UpdateWorkloadState::Checking,
            Err(_) => UpdateWorkloadState::Unavailable,
        };
        let observation = pass.observation(state)?;
        pass.retain(directory, &observation)?;
        self.status
            .replace(Some((binding.rollout, observation)))
            .map_err(|()| UpdateError::Unavailable)?;
        if result.is_err() {
            self.pass = None;
        }
        result
    }
}

impl Pass {
    fn new(binding: Binding) -> Self {
        Self {
            binding,
            target_cursor: None,
            targets_complete: false,
            excluded: BTreeSet::new(),
            volume: None,
            probe: None,
            volumes: 0,
            publications: 0,
            stripes: 0,
            complete: false,
            observed_at: crate::OperatingSystemClock.now(),
        }
    }

    fn advance(
        &mut self,
        filesystem: &NativeFilesystemRuntime,
        reader: &AuthoritativeRepository,
    ) -> Result<(), UpdateError> {
        self.check_revision(reader)?;
        if self.complete {
            if let Some(probe) = &self.probe {
                probe.progress().map_err(|_| UpdateError::Unavailable)?;
            }
            return Ok(());
        }
        self.observed_at = crate::OperatingSystemClock.now();
        if !self.targets_complete {
            self.collect_exclusions(reader)?;
            return self.check_revision(reader);
        }
        // Provider handles are refreshed each tick, not retained across a target reopen.
        let targets = filesystem
            .update_provider_targets()
            .map_err(|_| UpdateError::Unavailable)?;
        let now = crate::OperatingSystemClock.now();
        let repairer = filesystem
            .maintenance_repairer(&targets, now)
            .map_err(|_| UpdateError::Unavailable)?;
        let request = StripeReadRequest {
            operation_id: OperationId::from_bytes(self.binding.rollout.as_bytes())
                .map_err(|_| UpdateError::Failed)?,
            authorization_revision: self.binding.revision,
            observed_at: now,
            deadline: UnixMicros::new(
                now.get()
                    .checked_add(2_000_000)
                    .ok_or(UpdateError::Failed)?,
            ),
        };
        let started = Instant::now();
        // One bounded quantum per worker tick; no long read transaction spans provider IO.
        for _ in 0..16 {
            self.select_volume(filesystem, reader, &targets, now)?;
            if self.complete {
                break;
            }
            self.probe
                .as_mut()
                .ok_or(UpdateError::Failed)?
                .advance(&repairer, request)
                .map_err(|_| UpdateError::Unavailable)?;
            if started.elapsed() >= Duration::from_millis(200) {
                break;
            }
        }
        self.check_revision(reader)
    }

    fn collect_exclusions(&mut self, reader: &AuthoritativeRepository) -> Result<(), UpdateError> {
        let page = reader
            .topology_targets(
                self.target_cursor.as_ref(),
                PageLimit::new(128).map_err(|_| UpdateError::Failed)?,
            )
            .map_err(|_| UpdateError::Unavailable)?;
        self.excluded.extend(
            page.items
                .iter()
                .filter(|target| target.node_id == self.binding.node)
                .map(|target| target.target_id),
        );
        self.target_cursor = page.next;
        self.targets_complete = self.target_cursor.is_none();
        Ok(())
    }

    fn select_volume(
        &mut self,
        filesystem: &NativeFilesystemRuntime,
        reader: &AuthoritativeRepository,
        targets: &[NativeStorageTarget],
        now: UnixMicros,
    ) -> Result<(), UpdateError> {
        if let Some(probe) = &self.probe {
            let progress = probe.progress().map_err(|_| UpdateError::Unavailable)?;
            if self.complete || !progress.complete {
                return Ok(());
            }
        } else if self.complete {
            return Ok(());
        }
        let page = reader
            .volume_identity_page(
                self.volume,
                PageLimit::new(1).map_err(|_| UpdateError::Failed)?,
            )
            .map_err(|_| UpdateError::Unavailable)?;
        let Some(volume) = page.items.first().copied() else {
            self.complete = true;
            return Ok(());
        };
        let scopes = filesystem
            .maintenance_protection_configuration(targets, volume, now)
            .map_err(|_| UpdateError::Unavailable)?
            .read_availability_scopes(&self.excluded);
        if let Some(probe) = &mut self.probe {
            let progress = probe.progress().map_err(|_| UpdateError::Unavailable)?;
            self.volumes = self.volumes.checked_add(1).ok_or(UpdateError::Failed)?;
            self.publications = self
                .publications
                .checked_add(progress.publications)
                .ok_or(UpdateError::Failed)?;
            self.stripes = self
                .stripes
                .checked_add(progress.stripes)
                .ok_or(UpdateError::Failed)?;
            probe
                .next_volume(volume, scopes.targets, scopes.required_cells)
                .map_err(|_| UpdateError::Unavailable)?;
        } else {
            self.probe = Some(
                filesystem
                    .maintenance_catalogue(now)
                    .map_err(|_| UpdateError::Unavailable)?
                    .into_read_availability(volume, scopes.targets, scopes.required_cells)
                    .map_err(|_| UpdateError::Unavailable)?,
            );
        }
        self.volume = Some(volume);
        Ok(())
    }

    fn check_revision(&self, reader: &AuthoritativeRepository) -> Result<(), UpdateError> {
        if reader
            .current_revision()
            .map_err(|_| UpdateError::Unavailable)?
            != self.binding.revision
        {
            return Err(UpdateError::Unavailable);
        }
        Ok(())
    }

    fn observation(
        &self,
        state: UpdateWorkloadState,
    ) -> Result<UpdateWorkloadObservation, UpdateError> {
        let (state, progress) = match self
            .probe
            .as_ref()
            .map(VolumeReadAvailabilityProbe::progress)
        {
            Some(Ok(progress)) => (state, progress),
            Some(Err(_)) => (
                UpdateWorkloadState::Unavailable,
                VolumeReadAvailabilityProgress::default(),
            ),
            None => (state, VolumeReadAvailabilityProgress::default()),
        };
        let volumes = self
            .volumes
            .checked_add(u64::from(progress.complete))
            .ok_or(UpdateError::Failed)?;
        let publications = self
            .publications
            .checked_add(progress.publications)
            .ok_or(UpdateError::Failed)?;
        let stripes = self
            .stripes
            .checked_add(progress.stripes)
            .ok_or(UpdateError::Failed)?;
        Ok(UpdateWorkloadObservation {
            excluded_node_id: self.binding.node.as_bytes().to_vec(),
            excluded_node_incarnation: self.binding.incarnation,
            preparation_sequence: self.binding.sequence,
            preparation_log_index: self.binding.barrier,
            metadata_revision: self.binding.revision.get(),
            state: state.into(),
            observed_at_unix_micros: if state == UpdateWorkloadState::Unavailable {
                crate::OperatingSystemClock.now().get()
            } else {
                self.observed_at.get()
            },
            volumes_checked: volumes,
            publications_checked: publications,
            stripes_checked: stripes,
            current_volume_id: self.volume.map(|volume| volume.as_bytes().to_vec()),
            excluded_targets: u64::try_from(self.excluded.len())
                .map_err(|_| UpdateError::Failed)?,
        })
    }

    fn retain(
        &self,
        directory: &Path,
        observation: &UpdateWorkloadObservation,
    ) -> Result<(), UpdateError> {
        let state = match UpdateWorkloadState::try_from(observation.state)
            .map_err(|_| UpdateError::Failed)?
        {
            UpdateWorkloadState::Checking => "checking_local_content",
            UpdateWorkloadState::LocalContentChecked => "local_content_checked",
            UpdateWorkloadState::Unavailable => "local_content_unavailable",
            UpdateWorkloadState::Unspecified => return Err(UpdateError::Failed),
        };
        let bytes = serde_json::to_vec(&json!({
            "scope": "local_committed_content_catalogue", "restart_authorised": false,
            "state": state, "rollout_id": identifier(self.binding.rollout.as_bytes()),
            "excluded_node_id": identifier(self.binding.node.as_bytes()),
            "incarnation": self.binding.incarnation, "preparation_sequence": self.binding.sequence,
            "preparation_log_index": self.binding.barrier, "metadata_revision": self.binding.revision.get(),
            "observed_at": observation.observed_at_unix_micros,
            "current_volume_id": self.volume.map(|volume| identifier(volume.as_bytes())),
            "excluded_targets": self.excluded.len(),
            "volumes_checked": observation.volumes_checked,
            "publications_checked": observation.publications_checked,
            "stripes_checked": observation.stripes_checked,
        })).map_err(|_| UpdateError::Failed)?;
        protected_file::publish(
            &directory.join("update-workload.json"),
            &bytes,
            protected_file::PublishMode::Replace,
        )
        .map_err(|_| UpdateError::Failed)
    }
}

fn preparation_binding(
    reader: &AuthoritativeRepository,
    rollout: &UpdateRolloutRecord,
) -> Result<Option<Binding>, UpdateError> {
    if rollout.state != UpdateRolloutState::Running || rollout.allow_service_interruption {
        return Ok(None);
    }
    let Some(node) = reader
        .update_restart_candidate(rollout.rollout_id)
        .map_err(|_| UpdateError::Unavailable)?
    else {
        return Ok(None);
    };
    if node.phase != UpdateNodePhase::Preparing {
        return Ok(None);
    }
    Ok(Some(Binding {
        rollout: rollout.rollout_id,
        node: node.node_id,
        incarnation: node.incarnation,
        sequence: node.sequence,
        barrier: node.preparation_log_index.ok_or(UpdateError::Unavailable)?,
        revision: reader
            .current_revision()
            .map_err(|_| UpdateError::Unavailable)?,
    }))
}
