// SPDX-License-Identifier: GPL-2.0-only

//! Bounded admission of overdue local target generations into authoritative scrub work.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AuditEventId, DurationMicros, EntropyError, NodeId, OperationId, PrincipalId, RandomSource,
    UnixMicros, WorkId, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, DueStorageScrub, DueStorageScrubCursor,
    DueStorageScrubPage, EntityKind, QueueMaintenanceWork, RepositoryError,
};
use meshspan_work::{WorkDemand, WorkSignals, WorkSubject};
use thiserror::Error;

use crate::{ConsensusAuthenticationAuthority, MaintenanceMetadataAuthority};

/// Read and mutation authority required by the periodic scrub planner.
pub trait PeriodicScrubAuthority: MaintenanceMetadataAuthority {
    /// Returns one stable bounded page of overdue local target generations.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid bounds, corrupt authoritative state or database failure.
    fn due_storage_scrubs(
        &self,
        node_id: NodeId,
        now: UnixMicros,
        maximum_verification_age: DurationMicros,
        after: Option<DueStorageScrubCursor>,
        limit: usize,
    ) -> Result<DueStorageScrubPage, RepositoryError>;
}

impl PeriodicScrubAuthority for ConsensusAuthenticationAuthority {
    fn due_storage_scrubs(
        &self,
        node_id: NodeId,
        now: UnixMicros,
        maximum_verification_age: DurationMicros,
        after: Option<DueStorageScrubCursor>,
        limit: usize,
    ) -> Result<DueStorageScrubPage, RepositoryError> {
        self.reader()
            .due_storage_scrubs(node_id, now, maximum_verification_age, after, limit)
    }
}

/// Result of one bounded admission page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeriodicScrubAdmissionPage {
    /// Number of due candidates committed or resolved as deduplicated jobs.
    pub admitted: usize,
    /// Stable target cursor for the next scheduler tick, when present.
    pub next: Option<DueStorageScrubCursor>,
}

/// Failures which prevent one complete admission page from being processed.
#[derive(Debug, Error)]
pub enum PeriodicScrubSchedulingError {
    /// The due-target read failed closed.
    #[error("periodic scrub candidates could not be read")]
    Repository(#[from] RepositoryError),
    /// Consensus could not commit or resolve a deduplicated work request.
    #[error("periodic scrub work could not be admitted")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// Unique command, audit and work identities could not be generated.
    #[error("periodic scrub identities could not be generated")]
    Entropy(#[from] EntropyError),
    /// Configuration or authority output contradicted the request.
    #[error("periodic scrub admission input or receipt was invalid")]
    Invalid,
}

/// Stateless planner whose continuation is explicit and safe to restart from the beginning.
pub struct PeriodicScrubScheduler<'a, Authority, Random> {
    authority: &'a Authority,
    random: &'a mut Random,
    node_id: NodeId,
    actor_principal_id: PrincipalId,
}

impl<'a, Authority, Random> PeriodicScrubScheduler<'a, Authority, Random> {
    /// Binds one local worker identity to current replicated authority.
    #[must_use]
    pub const fn new(
        authority: &'a Authority,
        random: &'a mut Random,
        node_id: NodeId,
        actor_principal_id: PrincipalId,
    ) -> Self {
        Self {
            authority,
            random,
            node_id,
            actor_principal_id,
        }
    }
}

impl<Authority, Random> PeriodicScrubScheduler<'_, Authority, Random>
where
    Authority: PeriodicScrubAuthority,
    Random: RandomSource,
{
    /// Admits one bounded page using a stable due-cycle deduplication key.
    ///
    /// Restarting without the returned cursor is safe: already admitted targets coalesce onto
    /// their existing jobs. Supplying the cursor avoids repeatedly scanning the first page.
    ///
    /// # Errors
    ///
    /// Rejects zero demand, invalid query bounds, entropy failure, unavailable consensus and
    /// contradictory authority receipts.
    pub fn admit_page(
        &mut self,
        now: UnixMicros,
        maximum_verification_age: DurationMicros,
        after: Option<DueStorageScrubCursor>,
        page_items: usize,
        maximum_in_flight_bytes: u64,
    ) -> Result<PeriodicScrubAdmissionPage, PeriodicScrubSchedulingError> {
        if maximum_in_flight_bytes == 0 {
            return Err(PeriodicScrubSchedulingError::Invalid);
        }
        let page = self.authority.due_storage_scrubs(
            self.node_id,
            now,
            maximum_verification_age,
            after,
            page_items,
        )?;
        for candidate in &page.targets {
            self.admit_candidate(*candidate, now, maximum_in_flight_bytes)?;
        }
        Ok(PeriodicScrubAdmissionPage {
            admitted: page.targets.len(),
            next: page.next,
        })
    }

    /// Immediately admits one exact target generation after its focused return probes pass.
    ///
    /// The supplied return instant defines a distinct, restart-safe verification cycle. Replays
    /// at that instant coalesce through the same semantic key; a later disappearance and return
    /// produces a new cycle.
    ///
    /// # Errors
    ///
    /// Rejects a zero generation or budget, unavailable consensus, entropy failure and
    /// contradictory authority output.
    pub fn admit_returned_target(
        &mut self,
        target_id: meshspan_domain::TargetId,
        target_generation: u64,
        returned_at: UnixMicros,
        maximum_in_flight_bytes: u64,
    ) -> Result<(), PeriodicScrubSchedulingError> {
        self.admit_candidate(
            DueStorageScrub {
                target_id,
                target_generation,
                due_at: returned_at,
                last_completed_at: None,
            },
            returned_at,
            maximum_in_flight_bytes,
        )
    }

    fn admit_candidate(
        &mut self,
        candidate: DueStorageScrub,
        now: UnixMicros,
        maximum_in_flight_bytes: u64,
    ) -> Result<(), PeriodicScrubSchedulingError> {
        if candidate.due_at > now || candidate.target_generation == 0 {
            return Err(PeriodicScrubSchedulingError::Invalid);
        }
        let (operation_id, audit_event_id, work_id) = random_identities(self.random)?;
        let context = CommandContext {
            operation_id,
            actor_principal_id: self.actor_principal_id,
            audit_event_id,
            occurred_at: now,
            expected_revision: None,
        };
        let subject = WorkSubject::Scrub {
            target_id: candidate.target_id,
            target_generation: candidate.target_generation,
        };
        let command = AuthoritativeCommand::QueueMaintenanceWork(QueueMaintenanceWork {
            work_id,
            deduplication_key: scrub_cycle_key(subject, candidate.due_at),
            subject,
            signals: WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 1,
                protection_debt: 0,
                locality_debt: 0,
                instability: 0,
                access_heat: 0,
                created_at: now,
                due_at: Some(candidate.due_at),
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
            return Err(PeriodicScrubSchedulingError::Invalid);
        }
        Ok(())
    }
}

fn scrub_cycle_key(subject: WorkSubject, due_at: UnixMicros) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.periodic-scrub-cycle.v1\0");
    digest.update(&subject.encode());
    digest.update(&due_at.get().to_be_bytes());
    digest.finalize().into()
}

fn random_identities(
    random: &mut impl RandomSource,
) -> Result<(OperationId, AuditEventId, WorkId), PeriodicScrubSchedulingError> {
    let mut bytes = [0_u8; 48];
    random.fill_bytes(&mut bytes)?;
    let operation = uuid_v8(copy_identifier(&bytes[0..16])?);
    let audit = uuid_v8(copy_identifier(&bytes[16..32])?);
    let work = uuid_v8(copy_identifier(&bytes[32..48])?);
    if operation == audit || operation == work || audit == work {
        return Err(PeriodicScrubSchedulingError::Invalid);
    }
    Ok((
        OperationId::from_bytes(operation).map_err(|_| PeriodicScrubSchedulingError::Invalid)?,
        AuditEventId::from_bytes(audit).map_err(|_| PeriodicScrubSchedulingError::Invalid)?,
        WorkId::from_bytes(work).map_err(|_| PeriodicScrubSchedulingError::Invalid)?,
    ))
}

fn copy_identifier(bytes: &[u8]) -> Result<[u8; 16], PeriodicScrubSchedulingError> {
    bytes
        .try_into()
        .map_err(|_| PeriodicScrubSchedulingError::Invalid)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use meshspan_domain::{EntropyError, Revision, TargetId};
    use meshspan_metadata::{ApplyDisposition, CommandReceipt, EntityReference, LogPosition};

    use super::*;

    #[test]
    fn repeated_due_cycle_uses_one_stable_deduplication_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let target_id = TargetId::from_bytes([1; 16])?;
        let authority = RecordingAuthority {
            due: DueStorageScrubPage {
                targets: vec![DueStorageScrub {
                    target_id,
                    target_generation: 2,
                    due_at: UnixMicros::new(50),
                    last_completed_at: Some(UnixMicros::new(40)),
                }],
                next: Some(DueStorageScrubCursor::new(target_id)),
            },
            commands: RefCell::new(Vec::new()),
        };
        let mut random = CounterRandom(10);
        let mut scheduler = PeriodicScrubScheduler::new(
            &authority,
            &mut random,
            NodeId::from_bytes([2; 16])?,
            PrincipalId::from_bytes([3; 16])?,
        );
        let first = scheduler.admit_page(
            UnixMicros::new(60),
            DurationMicros::new(10),
            None,
            10,
            4_096,
        )?;
        let second = scheduler.admit_page(
            UnixMicros::new(61),
            DurationMicros::new(10),
            None,
            10,
            4_096,
        )?;
        assert_eq!(first.admitted, 1);
        assert_eq!(first.next, authority.due.next);
        assert_eq!(second.admitted, 1);
        let commands = authority.commands.borrow();
        let AuthoritativeCommand::QueueMaintenanceWork(first) = commands[0] else {
            return Err("first command was not scrub work".into());
        };
        let AuthoritativeCommand::QueueMaintenanceWork(second) = commands[1] else {
            return Err("second command was not scrub work".into());
        };
        assert_ne!(first.work_id, second.work_id);
        assert_eq!(first.deduplication_key, second.deduplication_key);
        assert_eq!(first.subject, second.subject);
        assert_eq!(first.signals.due_at, Some(UnixMicros::new(50)));
        assert_eq!(first.demand.in_flight_bytes, 4_096);
        Ok(())
    }

    #[test]
    fn returned_target_is_admitted_immediately_with_exact_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let target_id = TargetId::from_bytes([7; 16])?;
        let authority = RecordingAuthority {
            due: DueStorageScrubPage {
                targets: Vec::new(),
                next: None,
            },
            commands: RefCell::new(Vec::new()),
        };
        let mut random = CounterRandom(80);
        PeriodicScrubScheduler::new(
            &authority,
            &mut random,
            NodeId::from_bytes([8; 16])?,
            PrincipalId::from_bytes([9; 16])?,
        )
        .admit_returned_target(target_id, 4, UnixMicros::new(500), 8_192)?;

        let commands = authority.commands.borrow();
        let AuthoritativeCommand::QueueMaintenanceWork(work) = commands[0] else {
            return Err("return admission was not scrub work".into());
        };
        assert_eq!(
            work.subject,
            WorkSubject::Scrub {
                target_id,
                target_generation: 4,
            }
        );
        assert_eq!(work.signals.created_at, UnixMicros::new(500));
        assert_eq!(work.signals.due_at, Some(UnixMicros::new(500)));
        assert_eq!(work.next_attempt_at, UnixMicros::new(500));
        assert_eq!(work.demand.in_flight_bytes, 8_192);
        Ok(())
    }

    struct RecordingAuthority {
        due: DueStorageScrubPage,
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

    impl PeriodicScrubAuthority for RecordingAuthority {
        fn due_storage_scrubs(
            &self,
            _node_id: NodeId,
            _now: UnixMicros,
            _maximum_verification_age: DurationMicros,
            _after: Option<DueStorageScrubCursor>,
            _limit: usize,
        ) -> Result<DueStorageScrubPage, RepositoryError> {
            Ok(self.due.clone())
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
