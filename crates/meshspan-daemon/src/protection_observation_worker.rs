// SPDX-License-Identifier: GPL-2.0-only

//! Incremental local-catalogue assessment on the existing storage IO worker, never on scrapes.

use crate::runtime_observations::{ProtectionCounts, RuntimeObservations};
use crate::{NativeFilesystemRuntime, NativeStorageTarget};
use meshspan_domain::{UnixMicros, VolumeId};
use meshspan_filesystem::VolumeStripeCursor;
use meshspan_metadata::{AuthoritativeRepository, PageLimit};
use std::time::{Duration, Instant};

const PAGE_ITEMS: usize = 16;
const PASS_INTERVAL: Duration = Duration::from_secs(60);

pub(crate) struct ProtectionObservationWorker {
    filesystem: NativeFilesystemRuntime,
    observations: RuntimeObservations,
    pass: Option<Pass>,
    next_pass: Option<Instant>,
}

struct Pass {
    started: Instant,
    after_volume: Option<VolumeId>,
    volume: Option<(VolumeId, Option<VolumeStripeCursor>)>,
    counts: ProtectionCounts,
}

impl ProtectionObservationWorker {
    pub(crate) fn new(
        filesystem: NativeFilesystemRuntime,
        observations: RuntimeObservations,
    ) -> Self {
        Self {
            filesystem,
            observations,
            pass: None,
            next_pass: None,
        }
    }

    pub(crate) fn tick(
        &mut self,
        authority: &AuthoritativeRepository,
        targets: &[NativeStorageTarget],
        now: UnixMicros,
    ) {
        if self.next_pass.is_some_and(|next| next > Instant::now()) {
            return;
        }
        let pass = self.pass.get_or_insert_with(|| Pass {
            started: Instant::now(),
            after_volume: None,
            volume: None,
            counts: ProtectionCounts::default(),
        });
        match pass.advance(&self.filesystem, authority, targets, now) {
            Ok(false) => return,
            Ok(true) => self
                .observations
                .record_protection(pass.started, pass.counts),
            Err(()) => self.observations.record_protection_unavailable(),
        }
        self.pass = None;
        self.next_pass = Some(Instant::now() + PASS_INTERVAL);
    }
}

impl Pass {
    fn advance(
        &mut self,
        filesystem: &NativeFilesystemRuntime,
        authority: &AuthoritativeRepository,
        targets: &[NativeStorageTarget],
        now: UnixMicros,
    ) -> Result<bool, ()> {
        if self.volume.is_none() {
            let page = authority
                .volume_identity_page(self.after_volume, PageLimit::new(1).map_err(|_| ())?)
                .map_err(|_| ())?;
            let Some(volume) = page.items.first() else {
                return Ok(true);
            };
            self.after_volume = Some(*volume);
            self.volume = Some((*volume, None));
        }
        let (volume, after) = self.volume.ok_or(())?;
        let catalogue = filesystem.maintenance_catalogue(now).map_err(|_| ())?;
        let page = catalogue
            .committed_volume_stripes(volume, after, PAGE_ITEMS)
            .map_err(|_| ())?;
        let configuration = filesystem
            .maintenance_protection_configuration(targets, volume, now)
            .ok();
        let placement = meshspan_placement::FaultAwarePlacement::new();
        for record in page.stripes.as_slice() {
            let missing = u64::from(record.stripe.stripe.coding_layout().total_slices())
                .checked_sub(u64::try_from(record.stripe.receipts.len()).map_err(|_| ())?)
                .ok_or(())?;
            let assessment = configuration.as_ref().and_then(|configuration| {
                configuration
                    .assess_recorded(&placement, &record.stripe)
                    .ok()
            });
            self.counts.observe(missing, assessment)?;
        }
        self.volume = page.next.map(|next| (volume, Some(next)));
        Ok(false)
    }
}
