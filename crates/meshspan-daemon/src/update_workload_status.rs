// SPDX-License-Identifier: GPL-2.0-only

//! A small immutable observation shared between the update IO owner and authenticated control.

use meshspan_domain::{Revision, WorkId};
use meshspan_metadata::{UpdateNodePhase, UpdateNodeRecord};
use meshspan_protocol::v1::UpdateWorkloadObservation;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(crate) struct UpdateWorkloadStatus {
    current: Arc<Mutex<Option<(WorkId, UpdateWorkloadObservation)>>>,
}

impl UpdateWorkloadStatus {
    /// Never holds the observation lock while doing SQL, provider IO or network work.
    pub(super) fn replace(
        &self,
        value: Option<(WorkId, UpdateWorkloadObservation)>,
    ) -> Result<(), ()> {
        *self.current.lock().map_err(|_| ())? = value;
        Ok(())
    }

    /// Returns historical progress only for the exact currently preparing reservation.
    /// Matching this binding does not prove unchanged content or authorise a restart.
    pub(crate) fn for_preparation(
        &self,
        rollout: WorkId,
        node: &UpdateNodeRecord,
        revision: Revision,
    ) -> Result<Option<UpdateWorkloadObservation>, ()> {
        let current = self.current.lock().map_err(|_| ())?;
        let Some((observed_rollout, observed)) = current.as_ref() else {
            return Ok(None);
        };
        if *observed_rollout != rollout
            || node.phase != UpdateNodePhase::Preparing
            || observed.excluded_node_id != node.node_id.as_bytes()
            || observed.excluded_node_incarnation != node.incarnation
            || observed.preparation_sequence != node.sequence
            || Some(observed.preparation_log_index) != node.preparation_log_index
            || observed.metadata_revision != revision.get()
        {
            return Ok(None);
        }
        Ok(Some(observed.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_domain::NodeId;
    use meshspan_protocol::v1::UpdateWorkloadState;

    #[test]
    fn observation_requires_the_exact_active_preparation_and_is_not_restored()
    -> Result<(), Box<dyn std::error::Error>> {
        let status = UpdateWorkloadStatus::default();
        let rollout = WorkId::from_bytes([1; 16])?;
        let node = UpdateNodeRecord {
            node_id: NodeId::from_bytes([2; 16])?,
            incarnation: 1,
            sequence: 3,
            phase: UpdateNodePhase::Preparing,
            restart_pending: false,
            target: None,
            evidence_digest: None,
            observed_at: None,
            preparation_log_index: Some(7),
        };
        let observed = UpdateWorkloadObservation {
            excluded_node_id: node.node_id.as_bytes().to_vec(),
            excluded_node_incarnation: 1,
            preparation_sequence: 3,
            preparation_log_index: 7,
            metadata_revision: 5,
            state: UpdateWorkloadState::LocalContentChecked.into(),
            observed_at_unix_micros: 900,
            volumes_checked: 1,
            publications_checked: 2,
            stripes_checked: 3,
            current_volume_id: None,
            excluded_targets: 2,
        };
        status
            .replace(Some((rollout, observed.clone())))
            .map_err(|()| "status lock")?;
        let shared = status.clone();
        assert_eq!(
            shared
                .for_preparation(rollout, &node, Revision::new(5))
                .map_err(|()| "status lock")?,
            Some(observed)
        );
        let mutations: [fn(&mut UpdateNodeRecord); 4] = [
            |node| node.incarnation += 1,
            |node| node.sequence += 1,
            |node| node.preparation_log_index = Some(8),
            |node| node.phase = UpdateNodePhase::Restarting,
        ];
        for change in mutations {
            let mut changed = node.clone();
            change(&mut changed);
            assert!(
                shared
                    .for_preparation(rollout, &changed, Revision::new(5))
                    .map_err(|()| "status lock")?
                    .is_none()
            );
        }
        let other = UpdateNodeRecord {
            node_id: NodeId::from_bytes([3; 16])?,
            ..node.clone()
        };
        assert!(
            shared
                .for_preparation(rollout, &other, Revision::new(5))
                .map_err(|()| "status lock")?
                .is_none()
        );
        assert!(
            shared
                .for_preparation(WorkId::from_bytes([4; 16])?, &node, Revision::new(5))
                .map_err(|()| "status lock")?
                .is_none()
        );
        assert!(
            shared
                .for_preparation(rollout, &node, Revision::new(6))
                .map_err(|()| "status lock")?
                .is_none()
        );
        status.replace(None).map_err(|()| "status lock")?;
        assert!(
            shared
                .for_preparation(rollout, &node, Revision::new(5))
                .map_err(|()| "status lock")?
                .is_none()
        );
        assert!(
            UpdateWorkloadStatus::default()
                .for_preparation(rollout, &node, Revision::new(5))
                .map_err(|()| "status lock")?
                .is_none()
        );
        Ok(())
    }
}
