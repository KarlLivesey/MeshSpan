// SPDX-License-Identifier: GPL-2.0-only

//! Translation of validated scrub findings into deduplicated authoritative maintenance work.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_contracts::{ScrubObservation, ScrubOutcome, ShardIdentity};
use meshspan_domain::{
    AuditEventId, EntropyError, OperationId, PrincipalId, RandomSource, TargetId, UnixMicros,
    WorkId, uuid_v8,
};
use meshspan_filesystem::{ContentCatalogError, DurableContentCatalog, ShardRepairCandidate};
use meshspan_metadata::{AuthoritativeCommand, CommandContext, EntityKind, QueueMaintenanceWork};
use meshspan_work::{WorkDemand, WorkSignals, WorkSubject};
use thiserror::Error;

use crate::MaintenanceMetadataAuthority;

/// Receives each non-healthy observation after its complete provider page has been validated.
pub trait ScrubFindingSink {
    /// Records or coalesces the maintenance consequence of one exact finding.
    ///
    /// # Errors
    ///
    /// Rejects stale/contradictory catalogue evidence, unavailable authority or entropy failure.
    fn record(
        &mut self,
        target_id: TargetId,
        target_generation: u64,
        observation: ScrubObservation,
        observed_at: UnixMicros,
    ) -> Result<(), ScrubFindingSchedulingError>;
}

/// Exact current-route lookup needed to turn storage evidence into repair work.
pub trait RepairCandidateResolver {
    /// Resolves a currently active protected shard route, or `None` for stale/unknown evidence.
    ///
    /// # Errors
    ///
    /// Fails closed when local catalogue state contradicts itself.
    fn repair_candidate(
        &self,
        target_id: TargetId,
        target_generation: u64,
        shard: ShardIdentity,
    ) -> Result<Option<ShardRepairCandidate>, ContentCatalogError>;
}

impl RepairCandidateResolver for DurableContentCatalog {
    fn repair_candidate(
        &self,
        target_id: TargetId,
        target_generation: u64,
        shard: ShardIdentity,
    ) -> Result<Option<ShardRepairCandidate>, ContentCatalogError> {
        self.shard_repair_candidate(target_id, target_generation, shard)
    }
}

/// Failures before a finding has been safely admitted to authoritative work.
#[derive(Debug, Error)]
pub enum ScrubFindingSchedulingError {
    /// The local manifest/shard catalogue is unavailable or internally contradictory.
    #[error("scrub finding could not be resolved against the content catalogue")]
    Catalogue(#[from] ContentCatalogError),
    /// Consensus could not commit or resolve the deduplicated work request.
    #[error("scrub finding could not be admitted by metadata authority")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Unique operation, work and audit identities could not be generated.
    #[error("scrub finding identities could not be generated")]
    Entropy(#[from] EntropyError),
    /// The finding contradicts its current authoritative route or returned receipt.
    #[error("scrub finding contradicts current authoritative state")]
    InvalidFinding,
}

/// Automatic bounded bridge from scrub evidence to repair/reconcile/follow-up work.
pub struct AutomaticScrubFindingScheduler<'a, Authority, Catalogue, Random> {
    authority: &'a Authority,
    catalogue: &'a Catalogue,
    random: &'a mut Random,
    actor_principal_id: PrincipalId,
}

impl<'a, Authority, Catalogue, Random>
    AutomaticScrubFindingScheduler<'a, Authority, Catalogue, Random>
{
    /// Composes existing authority, catalogue and cryptographic entropy boundaries.
    #[must_use]
    pub const fn new(
        authority: &'a Authority,
        catalogue: &'a Catalogue,
        random: &'a mut Random,
        actor_principal_id: PrincipalId,
    ) -> Self {
        Self {
            authority,
            catalogue,
            random,
            actor_principal_id,
        }
    }
}

impl<Authority, Catalogue, Random> ScrubFindingSink
    for AutomaticScrubFindingScheduler<'_, Authority, Catalogue, Random>
where
    Authority: MaintenanceMetadataAuthority,
    Catalogue: RepairCandidateResolver,
    Random: RandomSource,
{
    fn record(
        &mut self,
        target_id: TargetId,
        target_generation: u64,
        observation: ScrubObservation,
        observed_at: UnixMicros,
    ) -> Result<(), ScrubFindingSchedulingError> {
        match observation.outcome {
            ScrubOutcome::Healthy => Ok(()),
            ScrubOutcome::Missing | ScrubOutcome::Corrupt | ScrubOutcome::Unreadable => {
                self.queue_repair(target_id, target_generation, observation, observed_at)
            }
            ScrubOutcome::Unexpected => self.queue_target_work(
                WorkSubject::Reconcile {
                    target_id,
                    target_generation,
                },
                observed_at,
                observed_at,
                observation.observed_length.unwrap_or(1).max(1),
                b"unexpected",
            ),
            ScrubOutcome::Deferred => self.queue_target_work(
                WorkSubject::Scrub {
                    target_id,
                    target_generation,
                },
                observed_at,
                observed_at,
                1,
                b"deferred",
            ),
        }
    }
}

impl<Authority, Catalogue, Random> AutomaticScrubFindingScheduler<'_, Authority, Catalogue, Random>
where
    Authority: MaintenanceMetadataAuthority,
    Catalogue: RepairCandidateResolver,
    Random: RandomSource,
{
    fn queue_repair(
        &mut self,
        target_id: TargetId,
        target_generation: u64,
        observation: ScrubObservation,
        observed_at: UnixMicros,
    ) -> Result<(), ScrubFindingSchedulingError> {
        let Some(candidate) =
            self.catalogue
                .repair_candidate(target_id, target_generation, observation.shard)?
        else {
            return Ok(());
        };
        if observation.expected_length != Some(candidate.source_receipt.length)
            || observation.expected_digest != Some(candidate.source_receipt.digest)
        {
            return Err(ScrubFindingSchedulingError::InvalidFinding);
        }
        let subject = WorkSubject::Repair {
            volume_id: candidate.volume_id,
            manifest_id: candidate.manifest_id,
            stripe_index: observation.shard.stripe_index,
            shard_index: observation.shard.shard_index,
            source_generation: candidate.source_layout_generation,
        };
        self.queue(
            subject,
            WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 0,
                protection_debt: 1,
                locality_debt: 0,
                instability: u16::from(observation.outcome == ScrubOutcome::Unreadable),
                access_heat: 0,
                created_at: observed_at,
                due_at: Some(observed_at),
            },
            WorkDemand {
                in_flight_bytes: candidate.source_receipt.length,
            },
            observed_at,
            None,
        )
    }

    fn queue_target_work(
        &mut self,
        subject: WorkSubject,
        created_at: UnixMicros,
        next_attempt_at: UnixMicros,
        in_flight_bytes: u64,
        cycle_domain: &[u8],
    ) -> Result<(), ScrubFindingSchedulingError> {
        self.queue(
            subject,
            WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 1,
                protection_debt: 0,
                locality_debt: 0,
                instability: 1,
                access_heat: 0,
                created_at,
                due_at: None,
            },
            WorkDemand { in_flight_bytes },
            next_attempt_at,
            Some(cycle_domain),
        )
    }

    fn queue(
        &mut self,
        subject: WorkSubject,
        signals: WorkSignals,
        demand: WorkDemand,
        next_attempt_at: UnixMicros,
        cycle_domain: Option<&[u8]>,
    ) -> Result<(), ScrubFindingSchedulingError> {
        let (operation_id, audit_event_id, work_id) = random_identities(self.random)?;
        let context = CommandContext {
            operation_id,
            actor_principal_id: self.actor_principal_id,
            audit_event_id,
            occurred_at: signals.created_at,
            expected_revision: None,
        };
        let command = AuthoritativeCommand::QueueMaintenanceWork(QueueMaintenanceWork {
            work_id,
            deduplication_key: deduplication_key(subject, cycle_domain, signals.created_at),
            subject,
            signals,
            demand,
            next_attempt_at,
        });
        let receipt = self.authority.commit(context, &command)?;
        if receipt.operation_id != operation_id
            || receipt.request_digest != command.request_digest(context)
            || receipt.result_digest == [0; 32]
            || receipt.entity.kind != EntityKind::MaintenanceWork
        {
            return Err(ScrubFindingSchedulingError::InvalidFinding);
        }
        Ok(())
    }
}

pub(crate) fn deduplication_key(
    subject: WorkSubject,
    cycle_domain: Option<&[u8]>,
    observed_at: UnixMicros,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.maintenance-work.deduplication.v1\0");
    digest.update(&subject.encode());
    if let Some(domain) = cycle_domain {
        digest.update(domain);
        digest.update(&observed_at.get().to_be_bytes());
    }
    digest.finalize().into()
}

fn random_identities(
    random: &mut impl RandomSource,
) -> Result<(OperationId, AuditEventId, WorkId), ScrubFindingSchedulingError> {
    let mut bytes = [0_u8; 48];
    random.fill_bytes(&mut bytes)?;
    let operation = uuid_v8(copy_identifier(&bytes[0..16])?);
    let audit = uuid_v8(copy_identifier(&bytes[16..32])?);
    let work = uuid_v8(copy_identifier(&bytes[32..48])?);
    if operation == audit || operation == work || audit == work {
        return Err(ScrubFindingSchedulingError::InvalidFinding);
    }
    Ok((
        OperationId::from_bytes(operation)
            .map_err(|_| ScrubFindingSchedulingError::InvalidFinding)?,
        AuditEventId::from_bytes(audit).map_err(|_| ScrubFindingSchedulingError::InvalidFinding)?,
        WorkId::from_bytes(work).map_err(|_| ScrubFindingSchedulingError::InvalidFinding)?,
    ))
}

fn copy_identifier(bytes: &[u8]) -> Result<[u8; 16], ScrubFindingSchedulingError> {
    bytes
        .try_into()
        .map_err(|_| ScrubFindingSchedulingError::InvalidFinding)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use meshspan_contracts::ShardReceipt;
    use meshspan_domain::{ContentManifestId, Revision, VolumeId};
    use meshspan_metadata::{ApplyDisposition, CommandReceipt, EntityReference, LogPosition};

    use super::*;

    #[test]
    fn damaged_current_shard_is_deduplicated_into_exact_repair_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let receipt = shard_receipt()?;
        let resolver = FixedResolver {
            candidate: Some(ShardRepairCandidate {
                volume_id: VolumeId::from_bytes([1; 16])?,
                manifest_id: ContentManifestId::from_bytes([2; 16])?,
                source_layout_generation: 3,
                source_receipt: receipt,
            }),
        };
        let authority = RecordingAuthority::default();
        let mut random = CounterRandom(10);
        let mut scheduler = AutomaticScrubFindingScheduler::new(
            &authority,
            &resolver,
            &mut random,
            PrincipalId::from_bytes([3; 16])?,
        );
        let finding = missing(receipt);
        scheduler.record(
            receipt.target_id,
            receipt.target_generation,
            finding,
            UnixMicros::new(10),
        )?;
        scheduler.record(
            receipt.target_id,
            receipt.target_generation,
            finding,
            UnixMicros::new(11),
        )?;

        let commands = authority.commands.borrow();
        let AuthoritativeCommand::QueueMaintenanceWork(first) = commands[0] else {
            return Err("first command was not repair work".into());
        };
        let AuthoritativeCommand::QueueMaintenanceWork(second) = commands[1] else {
            return Err("second command was not repair work".into());
        };
        assert_ne!(first.work_id, second.work_id);
        assert_eq!(first.deduplication_key, second.deduplication_key);
        assert_eq!(
            first.subject,
            WorkSubject::Repair {
                volume_id: resolver.candidate.ok_or("candidate missing")?.volume_id,
                manifest_id: resolver.candidate.ok_or("candidate missing")?.manifest_id,
                stripe_index: receipt.shard.stripe_index,
                shard_index: receipt.shard.shard_index,
                source_generation: 3,
            }
        );
        assert_eq!(first.demand.in_flight_bytes, receipt.length);
        assert_eq!(first.signals.remaining_recovery_margin, 0);
        assert_eq!(first.next_attempt_at, UnixMicros::new(10));
        Ok(())
    }

    #[test]
    fn stale_and_contradictory_findings_cannot_create_repair_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let receipt = shard_receipt()?;
        let authority = RecordingAuthority::default();
        let mut random = CounterRandom(20);
        let stale = FixedResolver { candidate: None };
        AutomaticScrubFindingScheduler::new(
            &authority,
            &stale,
            &mut random,
            PrincipalId::from_bytes([3; 16])?,
        )
        .record(
            receipt.target_id,
            receipt.target_generation,
            missing(receipt),
            UnixMicros::new(10),
        )?;
        assert!(authority.commands.borrow().is_empty());

        let resolver = FixedResolver {
            candidate: Some(ShardRepairCandidate {
                volume_id: VolumeId::from_bytes([1; 16])?,
                manifest_id: ContentManifestId::from_bytes([2; 16])?,
                source_layout_generation: 1,
                source_receipt: receipt,
            }),
        };
        let mut contradictory = missing(receipt);
        contradictory.expected_digest = Some([99; 32]);
        let error = AutomaticScrubFindingScheduler::new(
            &authority,
            &resolver,
            &mut random,
            PrincipalId::from_bytes([3; 16])?,
        )
        .record(
            receipt.target_id,
            receipt.target_generation,
            contradictory,
            UnixMicros::new(11),
        );
        assert!(matches!(
            error,
            Err(ScrubFindingSchedulingError::InvalidFinding)
        ));
        assert!(authority.commands.borrow().is_empty());
        Ok(())
    }

    #[derive(Default)]
    struct RecordingAuthority {
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

    #[derive(Clone, Copy)]
    struct FixedResolver {
        candidate: Option<ShardRepairCandidate>,
    }

    impl RepairCandidateResolver for FixedResolver {
        fn repair_candidate(
            &self,
            _target_id: TargetId,
            _target_generation: u64,
            _shard: ShardIdentity,
        ) -> Result<Option<ShardRepairCandidate>, ContentCatalogError> {
            Ok(self.candidate)
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

    fn shard_receipt() -> Result<ShardReceipt, meshspan_domain::IdentifierError> {
        Ok(ShardReceipt {
            operation_id: OperationId::from_bytes([5; 16])?,
            shard: ShardIdentity {
                manifest_digest: [6; 32],
                stripe_index: 7,
                shard_index: 2,
                generation: 1,
            },
            length: 4_096,
            digest: [8; 32],
            target_id: TargetId::from_bytes([9; 16])?,
            target_generation: 2,
        })
    }

    fn missing(receipt: ShardReceipt) -> ScrubObservation {
        ScrubObservation {
            shard: receipt.shard,
            expected_length: Some(receipt.length),
            expected_digest: Some(receipt.digest),
            observed_length: None,
            observed_digest: None,
            outcome: ScrubOutcome::Missing,
        }
    }
}
