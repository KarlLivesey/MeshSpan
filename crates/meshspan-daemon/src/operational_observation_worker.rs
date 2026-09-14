// SPDX-License-Identifier: GPL-2.0-only

//! Bounded independent certificate, backup and update reads on the existing storage worker.

use crate::runtime_observations::{
    CertificateInventory, InventoryKind, InventorySample, RuntimeObservations, UpdateInventory,
};
use meshspan_domain::{UnixMicros, WorkId};
use meshspan_metadata::{
    AuthoritativeRepository, MetadataBackupRunState, PageLimit, PublicCertificateStatusRecord,
    UpdateRolloutState,
};
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(15);

pub(crate) struct OperationalObservationWorker {
    observations: RuntimeObservations,
    certificate_after: Option<Instant>,
    backup_after: Option<Instant>,
    update_after: Option<Instant>,
    backup: Option<BackupPass>,
    update: Option<UpdatePass>,
}

struct BackupPass {
    started: Instant,
    after: Option<u64>,
    states: [u64; 5],
}
struct UpdatePass {
    started: Instant,
    after: Option<WorkId>,
    states: [u64; 4],
}

impl OperationalObservationWorker {
    pub(crate) fn new(observations: RuntimeObservations) -> Self {
        Self {
            observations,
            certificate_after: None,
            backup_after: None,
            update_after: None,
            backup: None,
            update: None,
        }
    }

    pub(crate) fn tick(&mut self, repository: &AuthoritativeRepository, now: UnixMicros) {
        let started = Instant::now();
        if self.certificate_after.is_none_or(|next| next <= started) {
            match repository
                .public_certificate_status()
                .map_err(|_| ())
                .and_then(|status| status.map(|value| certificate(value, now)).transpose())
            {
                Ok(value) => self
                    .observations
                    .record_inventory(started, InventorySample::Certificate(value)),
                Err(()) => self
                    .observations
                    .record_inventory_failure(InventoryKind::Certificate),
            }
            self.certificate_after = Some(started + INTERVAL);
        }
        if self.backup_after.is_none_or(|next| next <= started) {
            self.backup_tick(repository, started);
        }
        if self.update_after.is_none_or(|next| next <= started) {
            self.update_tick(repository, started);
        }
    }

    fn backup_tick(&mut self, repository: &AuthoritativeRepository, started: Instant) {
        let pass = self.backup.get_or_insert(BackupPass {
            started,
            after: None,
            states: [0; 5],
        });
        match pass.advance(repository) {
            Ok(false) => return,
            Ok(true) => self
                .observations
                .record_inventory(pass.started, InventorySample::Backups(pass.states)),
            Err(()) => self
                .observations
                .record_inventory_failure(InventoryKind::Backups),
        }
        self.backup = None;
        self.backup_after = Some(started + INTERVAL);
    }

    fn update_tick(&mut self, repository: &AuthoritativeRepository, started: Instant) {
        let pass = self.update.get_or_insert(UpdatePass {
            started,
            after: None,
            states: [0; 4],
        });
        match pass.advance(repository) {
            Ok(None) => return,
            Ok(Some(value)) => self
                .observations
                .record_inventory(pass.started, InventorySample::Updates(value)),
            Err(()) => self
                .observations
                .record_inventory_failure(InventoryKind::Updates),
        }
        self.update = None;
        self.update_after = Some(started + INTERVAL);
    }
}

fn certificate(
    value: PublicCertificateStatusRecord,
    now: UnixMicros,
) -> Result<CertificateInventory, ()> {
    if now.get() < 0
        || value.not_before.get() < 0
        || value.required_gateway_count == 0
        || value.not_after <= value.not_before
        || value.installed_gateway_count > value.required_gateway_count
    {
        return Err(());
    }
    let remaining = value
        .not_after
        .get()
        .checked_sub(now.get())
        .ok_or(())?
        .max(0);
    Ok(CertificateInventory {
        remaining: Duration::from_micros(u64::try_from(remaining).map_err(|_| ())?),
        not_yet_valid: now < value.not_before,
        expired: now >= value.not_after,
        required: value.required_gateway_count,
        installed: value.installed_gateway_count,
    })
}

impl BackupPass {
    fn advance(&mut self, repository: &AuthoritativeRepository) -> Result<bool, ()> {
        let page = repository
            .metadata_backup_runs(self.after, PageLimit::new(16).map_err(|_| ())?)
            .map_err(|_| ())?;
        for run in page.items {
            let index = match run.state {
                MetadataBackupRunState::Queued => 0,
                MetadataBackupRunState::Claimed => 1,
                MetadataBackupRunState::Recorded => 2,
                MetadataBackupRunState::Protected => 3,
                MetadataBackupRunState::Incomplete => 4,
            };
            self.states[index] = self.states[index].checked_add(1).ok_or(())?;
        }
        self.after = page.next;
        Ok(self.after.is_none())
    }
}

impl UpdatePass {
    fn advance(
        &mut self,
        repository: &AuthoritativeRepository,
    ) -> Result<Option<UpdateInventory>, ()> {
        let page = repository
            .update_rollout_state_page(self.after, PageLimit::new(16).map_err(|_| ())?)
            .map_err(|_| ())?;
        for state in page.items {
            let index = match state {
                UpdateRolloutState::Running => 0,
                UpdateRolloutState::Paused => 1,
                UpdateRolloutState::Completed => 2,
                UpdateRolloutState::Cancelled => 3,
            };
            self.states[index] = self.states[index].checked_add(1).ok_or(())?;
        }
        self.after = page.next;
        if self.after.is_some() {
            return Ok(None);
        }
        let active = repository
            .update_administration_snapshot(None)
            .map_err(|_| ())?
            .rollout
            .map(|(_, counts)| counts);
        Ok(Some(UpdateInventory {
            states: self.states,
            active,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_domain::{CertificateOrderId, PrincipalId, Revision};
    use meshspan_metadata::{
        PublicCertificateSelection, PublicCertificateSource, SecretGenerationReference,
    };

    #[test]
    fn certificate_inventory_classifies_exact_validity_boundaries_and_delivery_counts()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = CertificateOrderId::from_bytes([1; 16])?;
        let status = PublicCertificateStatusRecord {
            selection: PublicCertificateSelection {
                source: PublicCertificateSource::AcmeOrder(id),
                certificate: SecretGenerationReference {
                    secret_id: id.as_bytes(),
                    generation: 1,
                },
                bundle_digest: [2; 32],
                configured_by: PrincipalId::from_bytes([3; 16])?,
                completed_at: UnixMicros::new(10),
                source_revision: Revision::new(1),
            },
            not_before: UnixMicros::new(20),
            not_after: UnixMicros::new(100),
            required_gateway_count: 3,
            installed_gateway_count: 2,
        };
        for (now, remaining, not_yet, expired) in [
            (10, 90, true, false),
            (20, 80, false, false),
            (99, 1, false, false),
            (100, 0, false, true),
            (101, 0, false, true),
        ] {
            let sample =
                certificate(status, UnixMicros::new(now)).map_err(|()| "classification")?;
            assert_eq!(sample.remaining, Duration::from_micros(remaining));
            assert_eq!((sample.not_yet_valid, sample.expired), (not_yet, expired));
            assert_eq!((sample.required, sample.installed), (3, 2));
        }
        assert!(certificate(status, UnixMicros::new(-1)).is_err());
        assert!(
            certificate(
                PublicCertificateStatusRecord {
                    installed_gateway_count: 4,
                    ..status
                },
                UnixMicros::new(50)
            )
            .is_err()
        );
        Ok(())
    }
}
