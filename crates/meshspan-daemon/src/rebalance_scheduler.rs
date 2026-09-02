// SPDX-License-Identifier: GPL-2.0-only

//! Bounded admission of one rebalance scan per active volume and configuration revision.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, EntropyError, OperationId, PrincipalId, RandomSource, Revision, UnixMicros,
    WorkId, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, EntityKind, Page, PageLimit, QueueMaintenanceWork,
    RepositoryError, VolumeInventoryCursor, VolumeInventoryRecord,
};
use meshspan_work::{WorkDemand, WorkSignals, WorkSubject};
use thiserror::Error;

use crate::{ConsensusAuthenticationAuthority, MaintenanceMetadataAuthority};

/// Replicated reads required to admit current volume rebalance scans.
pub trait RebalanceSchedulingAuthority: MaintenanceMetadataAuthority {
    /// Returns the current mesh-wide placement configuration revision after bootstrap.
    ///
    /// # Errors
    ///
    /// Fails closed for missing, multiple or malformed mesh state.
    fn configuration_revision(&self) -> Result<Revision, RepositoryError>;

    /// Returns one stable page of logical volumes without permission filtering.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed cursor or volume state.
    fn volume_candidates(
        &self,
        after: Option<&VolumeInventoryCursor>,
        limit: PageLimit,
    ) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, RepositoryError>;
}

impl RebalanceSchedulingAuthority for ConsensusAuthenticationAuthority {
    fn configuration_revision(&self) -> Result<Revision, RepositoryError> {
        self.reader()
            .mesh_configuration_revision()?
            .ok_or(RepositoryError::CorruptState)
    }

    fn volume_candidates(
        &self,
        after: Option<&VolumeInventoryCursor>,
        limit: PageLimit,
    ) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, RepositoryError> {
        self.reader().volume_inventory_candidates(after, limit)
    }
}

/// Continuation returned from one bounded admission pass.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebalanceAdmissionPage {
    /// Exact configuration revision bound into every admitted scan.
    pub configuration_revision: Revision,
    /// Number of active volumes admitted or coalesced.
    pub admitted: usize,
    /// Next stable volume position, when another page remains.
    pub next: Option<VolumeInventoryCursor>,
}

/// Failures which prevent a complete admission page from being processed.
#[derive(Debug, Error)]
pub enum RebalanceSchedulingError {
    /// Current configuration or volume inventory could not be read safely.
    #[error("rebalance candidates could not be read")]
    Repository(#[from] RepositoryError),
    /// Consensus could not commit or resolve an admitted job.
    #[error("rebalance work could not be admitted")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Unique operation, audit and work identities could not be generated.
    #[error("rebalance identities could not be generated")]
    Entropy(#[from] EntropyError),
    /// Configuration or authority output contradicted the request.
    #[error("rebalance admission input or receipt was invalid")]
    Invalid,
}

/// Stateless admission planner; caller-owned cursors make scheduling cadence explicit.
pub struct RebalanceScheduler<'a, Authority, Random> {
    authority: &'a Authority,
    random: &'a mut Random,
    actor_principal_id: PrincipalId,
}

impl<'a, Authority, Random> RebalanceScheduler<'a, Authority, Random> {
    /// Binds current replicated authority and cryptographic entropy.
    #[must_use]
    pub const fn new(
        authority: &'a Authority,
        random: &'a mut Random,
        actor_principal_id: PrincipalId,
    ) -> Self {
        Self {
            authority,
            random,
            actor_principal_id,
        }
    }
}

impl<Authority, Random> RebalanceScheduler<'_, Authority, Random>
where
    Authority: RebalanceSchedulingAuthority,
    Random: RandomSource,
{
    /// Admits one bounded page under one exact configuration revision.
    ///
    /// A cursor from another revision is ignored and the new revision restarts at the first
    /// volume. Stable deduplication then coalesces any repeated admission after a crash.
    ///
    /// # Errors
    ///
    /// Rejects zero demand, invalid bounds, entropy failure, unavailable consensus or an
    /// authority receipt that does not exactly bind the request.
    pub fn admit_page(
        &mut self,
        now: UnixMicros,
        cursor_revision: Option<Revision>,
        after: Option<&VolumeInventoryCursor>,
        page_items: usize,
        maximum_in_flight_bytes: u64,
    ) -> Result<RebalanceAdmissionPage, RebalanceSchedulingError> {
        if maximum_in_flight_bytes == 0 || (after.is_some() && cursor_revision.is_none()) {
            return Err(RebalanceSchedulingError::Invalid);
        }
        let configuration_revision = self.authority.configuration_revision()?;
        let after = (cursor_revision == Some(configuration_revision))
            .then_some(after)
            .flatten();
        let page = self
            .authority
            .volume_candidates(after, PageLimit::new(page_items)?)?;
        let mut admitted = 0_usize;
        for volume in &page.items {
            if volume.state != 1 {
                continue;
            }
            self.admit_volume(volume, configuration_revision, now, maximum_in_flight_bytes)?;
            admitted = admitted
                .checked_add(1)
                .ok_or(RebalanceSchedulingError::Invalid)?;
        }
        Ok(RebalanceAdmissionPage {
            configuration_revision,
            admitted,
            next: page.next,
        })
    }

    fn admit_volume(
        &mut self,
        volume: &VolumeInventoryRecord,
        configuration_revision: Revision,
        now: UnixMicros,
        maximum_in_flight_bytes: u64,
    ) -> Result<(), RebalanceSchedulingError> {
        let (operation_id, audit_event_id, work_id) = random_identities(self.random)?;
        let subject = WorkSubject::Rebalance {
            volume_id: volume.volume_id,
            topology_revision: configuration_revision,
        };
        let context = CommandContext {
            operation_id,
            actor_principal_id: self.actor_principal_id,
            audit_event_id,
            occurred_at: now,
            expected_revision: None,
        };
        let command = AuthoritativeCommand::QueueMaintenanceWork(QueueMaintenanceWork {
            work_id,
            deduplication_key: rebalance_key(subject),
            subject,
            signals: WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 1,
                protection_debt: 1,
                locality_debt: 1,
                instability: 0,
                access_heat: 0,
                created_at: now,
                due_at: None,
            },
            demand: WorkDemand {
                in_flight_bytes: maximum_in_flight_bytes,
            },
            next_attempt_at: now,
        });
        let receipt = self.authority.commit(context, &command)?;
        if receipt.operation_id != operation_id
            || receipt.request_digest != command.request_digest(context)
            || receipt.result_digest == [0; 32]
            || receipt.entity.kind != EntityKind::MaintenanceWork
        {
            return Err(RebalanceSchedulingError::Invalid);
        }
        Ok(())
    }
}

fn rebalance_key(subject: WorkSubject) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.rebalance-cycle.v1\0");
    digest.update(&subject.encode());
    digest.finalize().into()
}

fn random_identities(
    random: &mut impl RandomSource,
) -> Result<(OperationId, AuditEventId, WorkId), RebalanceSchedulingError> {
    let mut bytes = [0_u8; 48];
    random.fill_bytes(&mut bytes)?;
    let operation = uuid_v8(copy_identifier(&bytes[..16])?);
    let audit = uuid_v8(copy_identifier(&bytes[16..32])?);
    let work = uuid_v8(copy_identifier(&bytes[32..])?);
    if operation == audit || operation == work || audit == work {
        return Err(RebalanceSchedulingError::Invalid);
    }
    Ok((
        OperationId::from_bytes(operation).map_err(|_| RebalanceSchedulingError::Invalid)?,
        AuditEventId::from_bytes(audit).map_err(|_| RebalanceSchedulingError::Invalid)?,
        WorkId::from_bytes(work).map_err(|_| RebalanceSchedulingError::Invalid)?,
    ))
}

fn copy_identifier(bytes: &[u8]) -> Result<[u8; 16], RebalanceSchedulingError> {
    bytes
        .try_into()
        .map_err(|_| RebalanceSchedulingError::Invalid)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use meshspan_domain::{EntropyError, ObjectId, VolumeId};
    use meshspan_metadata::{ApplyDisposition, CommandReceipt, EntityReference, LogPosition};

    use super::*;

    #[test]
    fn repeated_revision_admission_uses_one_stable_semantic_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let volume_id = VolumeId::from_bytes([1; 16])?;
        let authority = RecordingAuthority {
            revision: Revision::new(5),
            page: Page {
                items: vec![VolumeInventoryRecord {
                    volume_id,
                    root_object_id: ObjectId::from_bytes([2; 16])?,
                    display_name: "Volume".to_owned(),
                    canonical_name: "volume".to_owned(),
                    state: 1,
                    created_at: UnixMicros::new(1),
                    revision: Revision::new(1),
                }],
                next: None,
            },
            commands: RefCell::new(Vec::new()),
        };
        let mut random = CounterRandom(10);
        let mut scheduler =
            RebalanceScheduler::new(&authority, &mut random, PrincipalId::from_bytes([3; 16])?);
        scheduler.admit_page(UnixMicros::new(10), None, None, 10, 4_096)?;
        scheduler.admit_page(UnixMicros::new(11), None, None, 10, 4_096)?;

        let commands = authority.commands.borrow();
        let AuthoritativeCommand::QueueMaintenanceWork(first) = commands[0] else {
            return Err("first command was not rebalance work".into());
        };
        let AuthoritativeCommand::QueueMaintenanceWork(second) = commands[1] else {
            return Err("second command was not rebalance work".into());
        };
        assert_ne!(first.work_id, second.work_id);
        assert_eq!(first.deduplication_key, second.deduplication_key);
        assert_eq!(
            first.subject,
            WorkSubject::Rebalance {
                volume_id,
                topology_revision: Revision::new(5),
            }
        );
        Ok(())
    }

    struct RecordingAuthority {
        revision: Revision,
        page: Page<VolumeInventoryRecord, VolumeInventoryCursor>,
        commands: RefCell<Vec<AuthoritativeCommand>>,
    }

    impl MaintenanceMetadataAuthority for RecordingAuthority {
        fn commit(
            &self,
            context: CommandContext,
            command: &AuthoritativeCommand,
        ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
            self.commands.borrow_mut().push(command.clone());
            Ok(CommandReceipt {
                disposition: ApplyDisposition::Applied,
                operation_id: context.operation_id,
                request_digest: command.request_digest(context),
                result_digest: [1; 32],
                committed_revision: Revision::new(1),
                committed_position: LogPosition { index: 1, term: 1 },
                applied_position: LogPosition { index: 1, term: 1 },
                entity: EntityReference {
                    kind: EntityKind::MaintenanceWork,
                    id: [4; 16],
                },
            })
        }
    }

    impl RebalanceSchedulingAuthority for RecordingAuthority {
        fn configuration_revision(&self) -> Result<Revision, RepositoryError> {
            Ok(self.revision)
        }

        fn volume_candidates(
            &self,
            _after: Option<&VolumeInventoryCursor>,
            _limit: PageLimit,
        ) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, RepositoryError> {
            Ok(self.page.clone())
        }
    }

    struct CounterRandom(u8);

    impl RandomSource for CounterRandom {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            for (offset, byte) in destination.iter_mut().enumerate() {
                *byte = self.0.wrapping_add(u8::try_from(offset).unwrap_or(u8::MAX));
            }
            self.0 = self.0.wrapping_add(53);
            Ok(())
        }
    }
}
