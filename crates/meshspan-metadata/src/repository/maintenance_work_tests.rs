// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::{ShardIdentity, ShardReceipt};
use meshspan_domain::{
    AuditEventId, ComponentInstanceId, ContentManifestId, DurationMicros, HostId, MeshId, NodeId,
    OperationId, PartitionId, PrincipalId, Revision, RoleId, TargetId, UnixMicros, VolumeId,
    WorkId,
};
use meshspan_work::{WorkBudget, WorkSignals, WorkSubject, WorkUsage};
use sha2::{Digest, Sha256};

use super::{
    AuthoritativeRepository, EntityKind, LogPosition, MaintenanceWorkState, RepositoryError,
};
use crate::{
    AuthoritativeCommand, BootstrapMesh, ClaimMaintenanceWork, CommandContext,
    CommitRebalanceScanPage, CommitScrubPass, CommitShardRepair, CompleteMaintenanceWork,
    CreateComponent, MaintenanceWorkCompletion, PartitionDatabase, QueueMaintenanceWork,
    RebalanceScanCursor, RecordName, RegisterStorageTarget, RenewMaintenanceWork,
    StorageUsageLimit,
};

#[test]
fn work_is_deduplicated_leased_retried_and_fenced() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let work_id = WorkId::from_bytes([20; 16])?;
    let queued = fixture.apply(
        2,
        10,
        &AuthoritativeCommand::QueueMaintenanceWork(fixture.queue(work_id, 1, false)),
    )?;
    assert_eq!(queued.entity.kind, EntityKind::MaintenanceWork);
    assert_eq!(queued.entity.id, work_id.as_bytes());

    let coalesced = fixture.apply(
        3,
        11,
        &AuthoritativeCommand::QueueMaintenanceWork(fixture.queue(
            WorkId::from_bytes([21; 16])?,
            0,
            true,
        )),
    )?;
    assert_eq!(coalesced.entity.id, work_id.as_bytes());
    let record = fixture.record(work_id)?;
    assert!(record.signals.data_unavailable);
    assert_eq!(record.signals.remaining_recovery_margin, 0);
    assert_eq!(record.demand.in_flight_bytes, 4_096);
    assert_eq!(record.state, MaintenanceWorkState::Queued);

    fixture.apply(
        4,
        60,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work_id, 1, 101, 100)),
    )?;
    fixture.apply(
        5,
        30,
        &AuthoritativeCommand::RenewMaintenanceWork(fixture.renew(work_id, 1, 101, 150)),
    )?;
    fixture.apply(
        6,
        40,
        &AuthoritativeCommand::CompleteMaintenanceWork(fixture.continue_at(work_id, 1, 101, 200)),
    )?;
    let record = fixture.record(work_id)?;
    assert_eq!(record.state, MaintenanceWorkState::Queued);
    assert_eq!(record.next_attempt_at, UnixMicros::new(200));
    assert_eq!(record.attempt_count, 1);
    assert!(record.claim.is_none());

    fixture.apply(
        7,
        200,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work_id, 2, 202, 250)),
    )?;
    fixture.apply(
        8,
        251,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work_id, 3, 303, 350)),
    )?;
    let record = fixture.record(work_id)?;
    assert_eq!(record.state, MaintenanceWorkState::Claimed);
    assert_eq!(record.attempt_count, 3);
    assert_eq!(record.claim.ok_or("active claim missing")?.generation, 3);

    let stale = fixture.apply(
        9,
        252,
        &AuthoritativeCommand::CompleteMaintenanceWork(fixture.retry(work_id, 2, 202, 400)),
    );
    assert!(matches!(stale, Err(RepositoryError::InvalidCommand)));
    let fabricated_success = fixture.apply(
        9,
        252,
        &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
            work_id,
            claim_generation: 3,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 303,
            outcome: MaintenanceWorkCompletion::Succeeded {
                effect_operation_id: OperationId::from_bytes([99; 16])?,
                effect_revision: Revision::new(1),
                effect_result_digest: [98; 32],
            },
        }),
    );
    if !matches!(fabricated_success, Err(RepositoryError::InvalidCommand)) {
        return Err(format!("fabricated success returned {fabricated_success:?}").into());
    }
    assert_eq!(fixture.repository.current_revision()?, Revision::new(8));
    Ok(())
}

#[test]
fn ready_work_is_priority_ordered_budgeted_and_keyset_paged()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let low_id = WorkId::from_bytes([30; 16])?;
    let urgent_id = WorkId::from_bytes([31; 16])?;
    let fitting_id = WorkId::from_bytes([32; 16])?;

    let mut low = fixture.queue(low_id, 4, false);
    low.deduplication_key = [30; 32];
    low.demand.in_flight_bytes = 100;
    low.signals.protection_debt = 0;
    let mut urgent = fixture.queue(urgent_id, 0, true);
    urgent.deduplication_key = [31; 32];
    urgent.demand.in_flight_bytes = 4_000;
    let mut fitting = fixture.queue(fitting_id, 1, false);
    fitting.deduplication_key = [32; 32];
    fitting.demand.in_flight_bytes = 1_000;
    fixture.apply(2, 10, &AuthoritativeCommand::QueueMaintenanceWork(low))?;
    fixture.apply(3, 11, &AuthoritativeCommand::QueueMaintenanceWork(urgent))?;
    fixture.apply(4, 12, &AuthoritativeCommand::QueueMaintenanceWork(fitting))?;

    let budget = WorkBudget::new(2, 5_000, None)?;
    let usage = WorkUsage {
        active_jobs: 1,
        in_flight_bytes: 2_000,
    };
    let first =
        fixture
            .repository
            .ready_maintenance_work(UnixMicros::new(20), budget, usage, None, 1)?;
    assert_eq!(first.work.len(), 1);
    assert_eq!(first.work[0].work_id, fitting_id);
    let second = fixture.repository.ready_maintenance_work(
        UnixMicros::new(20),
        budget,
        usage,
        first.next,
        1,
    )?;
    assert_eq!(second.work.len(), 1);
    assert_eq!(second.work[0].work_id, low_id);
    assert!(second.next.is_none());

    fixture.apply(
        5,
        20,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(fitting_id, 1, 77, 100)),
    )?;
    let before_expiry =
        fixture
            .repository
            .ready_maintenance_work(UnixMicros::new(99), budget, usage, None, 10)?;
    assert_eq!(before_expiry.work[0].work_id, low_id);
    let after_expiry =
        fixture
            .repository
            .ready_maintenance_work(UnixMicros::new(100), budget, usage, None, 10)?;
    assert_eq!(after_expiry.work[0].work_id, fitting_id);

    let saturated = fixture.repository.ready_maintenance_work(
        UnixMicros::new(20),
        budget,
        WorkUsage {
            active_jobs: 2,
            in_flight_bytes: 0,
        },
        None,
        10,
    )?;
    assert!(saturated.work.is_empty());
    Ok(())
}

#[test]
fn repair_effect_advances_one_cow_route_then_completes_exact_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let source_target = TargetId::from_bytes([40; 16])?;
    let replacement_target = TargetId::from_bytes([41; 16])?;
    fixture.register_target(2, source_target, 50)?;
    fixture.register_target(3, replacement_target, 51)?;
    let work_id = WorkId::from_bytes([42; 16])?;
    let manifest_id = ContentManifestId::from_bytes([43; 16])?;
    let source = shard_receipt(44, source_target, 45)?;
    let replacement = shard_receipt(46, replacement_target, 45)?;
    fixture.apply(
        4,
        60,
        &AuthoritativeCommand::QueueMaintenanceWork(fixture.repair_queue(
            work_id,
            manifest_id,
            source.length,
        )),
    )?;
    fixture.apply(
        5,
        61,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work_id, 1, 777, 100)),
    )?;
    let repair = CommitShardRepair {
        work_id,
        claim_generation: 1,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence: 777,
        volume_id: fixture.volume,
        manifest_id,
        source_layout_generation: 1,
        source_receipt: source,
        replacement_receipt: replacement,
    };
    let effect = fixture.apply(6, 62, &AuthoritativeCommand::CommitShardRepair(repair))?;
    let stored = fixture
        .repository
        .shard_repair_effect(effect.operation_id)?
        .ok_or("repair effect missing")?;
    assert_eq!(stored.work_id, work_id);
    assert_eq!(stored.source_receipt, source);
    assert_eq!(stored.replacement_receipt, replacement);
    assert_eq!(
        (
            stored.source_layout_generation,
            stored.replacement_layout_generation
        ),
        (1, 2)
    );

    let stale = CommitShardRepair {
        replacement_receipt: ShardReceipt {
            operation_id: OperationId::from_bytes([47; 16])?,
            ..replacement
        },
        ..repair
    };
    assert!(matches!(
        fixture.apply(7, 63, &AuthoritativeCommand::CommitShardRepair(stale)),
        Err(RepositoryError::InvalidCommand)
    ));
    fixture.apply(
        7,
        64,
        &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
            work_id,
            claim_generation: 1,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 777,
            outcome: MaintenanceWorkCompletion::Succeeded {
                effect_operation_id: effect.operation_id,
                effect_revision: effect.committed_revision,
                effect_result_digest: effect.result_digest,
            },
        }),
    )?;
    assert_eq!(
        fixture.record(work_id)?.state,
        MaintenanceWorkState::Complete
    );
    Ok(())
}

#[test]
fn scrub_effect_requires_exact_classified_summary_then_completes_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let target_id = TargetId::from_bytes([60; 16])?;
    fixture.register_target(2, target_id, 61)?;
    let work_id = WorkId::from_bytes([62; 16])?;
    fixture.apply(
        3,
        70,
        &AuthoritativeCommand::QueueMaintenanceWork(Fixture::scrub_queue(work_id, target_id)),
    )?;
    fixture.apply(
        4,
        71,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work_id, 1, 801, 120)),
    )?;
    let scrub = CommitScrubPass {
        work_id,
        claim_generation: 1,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        fence: 801,
        target_id,
        target_generation: 1,
        observation_count: 6,
        verified_bytes: 12_288,
        healthy_count: 1,
        missing_count: 1,
        corrupt_count: 1,
        unreadable_count: 1,
        unexpected_count: 1,
        deferred_count: 1,
        evidence_digest: [63; 32],
    };
    let malformed = CommitScrubPass {
        observation_count: 7,
        ..scrub
    };
    assert!(matches!(
        fixture.apply(5, 72, &AuthoritativeCommand::CommitScrubPass(malformed)),
        Err(RepositoryError::InvalidCommand)
    ));

    let effect = fixture.apply(5, 72, &AuthoritativeCommand::CommitScrubPass(scrub))?;
    let stored = fixture
        .repository
        .scrub_pass_effect(effect.operation_id)?
        .ok_or("scrub effect missing")?;
    assert_eq!(stored.work_id, work_id);
    assert_eq!(stored.target_id, target_id);
    assert_eq!(stored.target_generation, 1);
    assert_eq!(stored.observation_count, 6);
    assert_eq!(stored.verified_bytes, 12_288);
    assert_eq!(stored.outcome_counts, [1; 6]);
    assert_eq!(stored.evidence_digest, [63; 32]);
    assert_eq!(
        fixture.repository.maintenance_effect_reference(work_id)?,
        Some(super::MaintenanceEffectReference {
            operation_id: effect.operation_id,
            revision: effect.committed_revision,
            result_digest: effect.result_digest,
        })
    );

    fixture.apply(
        6,
        73,
        &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
            work_id,
            claim_generation: 1,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 801,
            outcome: MaintenanceWorkCompletion::Succeeded {
                effect_operation_id: effect.operation_id,
                effect_revision: effect.committed_revision,
                effect_result_digest: effect.result_digest,
            },
        }),
    )?;
    assert_eq!(
        fixture.record(work_id)?.state,
        MaintenanceWorkState::Complete
    );
    Ok(())
}

#[test]
fn rebalance_scan_checkpoints_pages_then_completes_from_exact_effect()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let work_id = WorkId::from_bytes([80; 16])?;
    let cursor = RebalanceScanCursor {
        publication_operation_id: OperationId::from_bytes([81; 16])?,
        stripe_index: 3,
    };
    fixture.apply(
        2,
        10,
        &AuthoritativeCommand::QueueMaintenanceWork(fixture.queue(work_id, 2, false)),
    )?;
    fixture.apply(
        3,
        11,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work_id, 1, 901, 100)),
    )?;
    fixture.apply(
        4,
        12,
        &fixture.rebalance_page(
            work_id,
            RebalancePageSpec {
                claim_generation: 1,
                fence: 901,
                after: None,
                next: Some(cursor),
                scanned_stripes: 2,
                queued_repairs: 1,
                page_digest: [82; 32],
            },
        ),
    )?;
    let first = fixture
        .repository
        .rebalance_scan_progress(work_id)?
        .ok_or("rebalance progress missing")?;
    assert_eq!(first.cursor, Some(cursor));
    assert_eq!((first.scanned_stripes, first.queued_repairs), (2, 1));
    assert!(!first.complete);

    fixture.apply(
        5,
        13,
        &AuthoritativeCommand::CompleteMaintenanceWork(fixture.continue_at(work_id, 1, 901, 20)),
    )?;
    fixture.apply(
        6,
        20,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work_id, 2, 902, 100)),
    )?;
    let effect = fixture.apply(
        7,
        21,
        &fixture.rebalance_page(
            work_id,
            RebalancePageSpec {
                claim_generation: 2,
                fence: 902,
                after: Some(cursor),
                next: None,
                scanned_stripes: 1,
                queued_repairs: 0,
                page_digest: [83; 32],
            },
        ),
    )?;
    let complete = fixture
        .repository
        .rebalance_scan_progress(work_id)?
        .ok_or("complete rebalance progress missing")?;
    assert!(complete.complete);
    assert_eq!(complete.cursor, None);
    assert_eq!((complete.scanned_stripes, complete.queued_repairs), (3, 1));
    let reference = fixture
        .repository
        .maintenance_effect_reference(work_id)?
        .ok_or("rebalance effect missing")?;
    assert_eq!(reference.operation_id, effect.operation_id);

    fixture.apply(
        8,
        22,
        &AuthoritativeCommand::CompleteMaintenanceWork(CompleteMaintenanceWork {
            work_id,
            claim_generation: 2,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 902,
            outcome: MaintenanceWorkCompletion::Succeeded {
                effect_operation_id: reference.operation_id,
                effect_revision: reference.revision,
                effect_result_digest: reference.result_digest,
            },
        }),
    )?;
    assert_eq!(
        fixture.record(work_id)?.state,
        MaintenanceWorkState::Complete
    );
    Ok(())
}

#[test]
fn periodic_scrub_candidates_are_due_paged_and_advanced_by_complete_effects()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let first_target = TargetId::from_bytes([10; 16])?;
    let second_target = TargetId::from_bytes([20; 16])?;
    let later_target = TargetId::from_bytes([60; 16])?;
    fixture.register_target(2, first_target, 10)?;
    fixture.register_target(3, second_target, 20)?;
    fixture.register_target(4, later_target, 60)?;
    let age = DurationMicros::new(50);

    let first_page =
        fixture
            .repository
            .due_storage_scrubs(fixture.node, UnixMicros::new(100), age, None, 1)?;
    assert_eq!(first_page.targets.len(), 1);
    assert_eq!(first_page.targets[0].target_id, first_target);
    assert_eq!(first_page.targets[0].due_at, UnixMicros::new(60));
    assert!(first_page.targets[0].last_completed_at.is_none());
    let second_page = fixture.repository.due_storage_scrubs(
        fixture.node,
        UnixMicros::new(100),
        age,
        first_page.next,
        2,
    )?;
    assert_eq!(second_page.targets.len(), 1);
    assert_eq!(second_page.targets[0].target_id, second_target);
    assert!(second_page.next.is_none());

    let work_id = WorkId::from_bytes([70; 16])?;
    fixture.apply(
        5,
        101,
        &AuthoritativeCommand::QueueMaintenanceWork(Fixture::scrub_queue(work_id, first_target)),
    )?;
    fixture.apply(
        6,
        102,
        &AuthoritativeCommand::ClaimMaintenanceWork(fixture.claim(work_id, 1, 900, 150)),
    )?;
    fixture.apply(
        7,
        103,
        &AuthoritativeCommand::CommitScrubPass(CommitScrubPass {
            work_id,
            claim_generation: 1,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 900,
            target_id: first_target,
            target_generation: 1,
            observation_count: 1,
            verified_bytes: 1,
            healthy_count: 1,
            missing_count: 0,
            corrupt_count: 0,
            unreadable_count: 0,
            unexpected_count: 0,
            deferred_count: 0,
            evidence_digest: [71; 32],
        }),
    )?;
    let remaining =
        fixture
            .repository
            .due_storage_scrubs(fixture.node, UnixMicros::new(120), age, None, 10)?;
    assert_eq!(remaining.targets.len(), 2);
    assert_eq!(remaining.targets[0].target_id, second_target);
    assert_eq!(remaining.targets[1].target_id, later_target);
    assert!(
        remaining
            .targets
            .iter()
            .all(|target| target.target_id != first_target)
    );
    Ok(())
}

fn shard_receipt(
    operation: u8,
    target_id: TargetId,
    digest: u8,
) -> Result<ShardReceipt, meshspan_domain::IdentifierError> {
    Ok(ShardReceipt {
        operation_id: OperationId::from_bytes([operation; 16])?,
        shard: ShardIdentity {
            manifest_digest: [48; 32],
            stripe_index: 3,
            shard_index: 1,
            generation: 1,
        },
        length: 4_096,
        digest: [digest; 32],
        target_id,
        target_generation: 1,
    })
}

struct Fixture {
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    node: NodeId,
    host: HostId,
    volume: VolumeId,
}

#[derive(Clone, Copy)]
struct RebalancePageSpec {
    claim_generation: u64,
    fence: u64,
    after: Option<RebalanceScanCursor>,
    next: Option<RebalanceScanCursor>,
    scanned_stripes: u16,
    queued_repairs: u16,
    page_digest: [u8; 32],
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let administrator = PrincipalId::from_bytes([2; 16])?;
        let node = NodeId::from_bytes([6; 16])?;
        let host = HostId::from_bytes([5; 16])?;
        let volume = VolumeId::from_bytes([7; 16])?;
        let database = PartitionDatabase::open(
            std::path::Path::new(":memory:"),
            PartitionId::from_bytes([1; 16])?,
            UnixMicros::new(1),
        )?;
        let mut fixture = Self {
            repository: AuthoritativeRepository::new(database),
            administrator,
            node,
            host,
            volume,
        };
        fixture.apply(
            1,
            1,
            &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
                mesh_id: MeshId::from_bytes([3; 16])?,
                mesh_name: RecordName::new("Maintenance proof")?,
                administrator_id: administrator,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([4; 16])?,
                host_id: host,
                host_name: RecordName::new("Host")?,
                node_id: node,
                node_name: RecordName::new("Node")?,
                partition_name: RecordName::new("Authority")?,
            }),
        )?;
        fixture.repository.database.connection_mut().execute(
            "INSERT INTO volumes(
                volume_id, display_name, canonical_name, state, created_by, created_at, revision
             ) VALUES (?1, 'Work volume', 'work volume', 1, ?2, 1, 1)",
            rusqlite::params![
                volume.as_bytes().as_slice(),
                administrator.as_bytes().as_slice(),
            ],
        )?;
        Ok(fixture)
    }

    fn apply(
        &mut self,
        index: u64,
        occurred_at: i64,
        command: &AuthoritativeCommand,
    ) -> Result<super::CommandReceipt, RepositoryError> {
        self.repository.apply_committed(
            LogPosition { index, term: 1 },
            CommandContext {
                operation_id: OperationId::from_bytes([u8::try_from(index).unwrap_or(255); 16])
                    .map_err(|_| RepositoryError::InvalidCommand)?,
                actor_principal_id: self.administrator,
                audit_event_id: AuditEventId::from_bytes(
                    [u8::try_from(index + 100).unwrap_or(254); 16],
                )
                .map_err(|_| RepositoryError::InvalidCommand)?,
                occurred_at: UnixMicros::new(occurred_at),
                expected_revision: Some(Revision::new(index - 1)),
            },
            command,
        )
    }

    fn queue(&self, work_id: WorkId, margin: u16, unavailable: bool) -> QueueMaintenanceWork {
        QueueMaintenanceWork {
            work_id,
            deduplication_key: [42; 32],
            subject: WorkSubject::Rebalance {
                volume_id: self.volume,
                topology_revision: Revision::new(1),
            },
            signals: WorkSignals {
                data_unavailable: unavailable,
                remaining_recovery_margin: margin,
                protection_debt: u16::from(!unavailable),
                locality_debt: 0,
                instability: u16::from(unavailable),
                access_heat: 0,
                created_at: UnixMicros::new(10),
                due_at: None,
            },
            demand: meshspan_work::WorkDemand {
                in_flight_bytes: 4_096,
            },
            next_attempt_at: UnixMicros::new(10),
        }
    }

    fn repair_queue(
        &self,
        work_id: WorkId,
        manifest_id: ContentManifestId,
        in_flight_bytes: u64,
    ) -> QueueMaintenanceWork {
        QueueMaintenanceWork {
            work_id,
            deduplication_key: [work_id.as_bytes()[0]; 32],
            subject: WorkSubject::Repair {
                volume_id: self.volume,
                manifest_id,
                stripe_index: 3,
                shard_index: 1,
                source_generation: 1,
            },
            signals: WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 0,
                protection_debt: 1,
                locality_debt: 0,
                instability: 0,
                access_heat: 0,
                created_at: UnixMicros::new(20),
                due_at: None,
            },
            demand: meshspan_work::WorkDemand { in_flight_bytes },
            next_attempt_at: UnixMicros::new(20),
        }
    }

    fn rebalance_page(&self, work_id: WorkId, spec: RebalancePageSpec) -> AuthoritativeCommand {
        AuthoritativeCommand::CommitRebalanceScanPage(CommitRebalanceScanPage {
            work_id,
            claim_generation: spec.claim_generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence: spec.fence,
            volume_id: self.volume,
            topology_revision: Revision::new(1),
            after: spec.after,
            next: spec.next,
            scanned_stripes: spec.scanned_stripes,
            queued_repairs: spec.queued_repairs,
            superseded_by_revision: None,
            page_digest: spec.page_digest,
        })
    }

    fn scrub_queue(work_id: WorkId, target_id: TargetId) -> QueueMaintenanceWork {
        QueueMaintenanceWork {
            work_id,
            deduplication_key: [work_id.as_bytes()[0]; 32],
            subject: WorkSubject::Scrub {
                target_id,
                target_generation: 1,
            },
            signals: WorkSignals {
                data_unavailable: false,
                remaining_recovery_margin: 1,
                protection_debt: 0,
                locality_debt: 0,
                instability: 0,
                access_heat: 0,
                created_at: UnixMicros::new(70),
                due_at: None,
            },
            demand: meshspan_work::WorkDemand {
                in_flight_bytes: 4_096,
            },
            next_attempt_at: UnixMicros::new(70),
        }
    }

    fn register_target(
        &mut self,
        index: u64,
        target_id: TargetId,
        seed: u8,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let configuration = format!("{{\"target\":{seed}}}").into_bytes();
        self.apply(
            index,
            i64::from(seed),
            &AuthoritativeCommand::RegisterStorageTarget(RegisterStorageTarget {
                target_id,
                node_id: self.node,
                host_id: self.host,
                provider: CreateComponent {
                    instance_id: ComponentInstanceId::from_bytes([seed; 16])?,
                    component_kind: 1,
                    name: RecordName::new(&format!("Provider {seed}"))?,
                    implementation_id: "meshspan-folder".to_owned(),
                    contract_major: 1,
                    contract_minor: 0,
                    schema_version: 1,
                    configuration_digest: Sha256::digest(&configuration).into(),
                    canonical_configuration: configuration,
                },
                name: RecordName::new(&format!("Target {seed}"))?,
                generation: 1,
                marker_fingerprint: [seed; 32],
                backing_device_fingerprint: None,
                filesystem_fingerprint: None,
                usage_limit: StorageUsageLimit::Percent(95),
            }),
        )?;
        Ok(())
    }

    const fn claim(
        &self,
        work_id: WorkId,
        generation: u64,
        fence: u64,
        expires_at: i64,
    ) -> ClaimMaintenanceWork {
        ClaimMaintenanceWork {
            work_id,
            worker_node_id: self.node,
            worker_incarnation: 1,
            claim_generation: generation,
            fence,
            lease_expires_at: UnixMicros::new(expires_at),
        }
    }

    const fn renew(
        &self,
        work_id: WorkId,
        generation: u64,
        fence: u64,
        expires_at: i64,
    ) -> RenewMaintenanceWork {
        RenewMaintenanceWork {
            work_id,
            claim_generation: generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence,
            lease_expires_at: UnixMicros::new(expires_at),
        }
    }

    const fn retry(
        &self,
        work_id: WorkId,
        generation: u64,
        fence: u64,
        retry_at: i64,
    ) -> CompleteMaintenanceWork {
        CompleteMaintenanceWork {
            work_id,
            claim_generation: generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence,
            outcome: MaintenanceWorkCompletion::Retry {
                failure_digest: [55; 32],
                retry_at: UnixMicros::new(retry_at),
            },
        }
    }

    const fn continue_at(
        &self,
        work_id: WorkId,
        generation: u64,
        fence: u64,
        retry_at: i64,
    ) -> CompleteMaintenanceWork {
        CompleteMaintenanceWork {
            work_id,
            claim_generation: generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence,
            outcome: MaintenanceWorkCompletion::Continue {
                progress_digest: [56; 32],
                retry_at: UnixMicros::new(retry_at),
            },
        }
    }

    fn record(
        &self,
        work_id: WorkId,
    ) -> Result<super::MaintenanceWorkRecord, Box<dyn std::error::Error>> {
        Ok(self
            .repository
            .maintenance_work(work_id)?
            .ok_or("work record missing")?)
    }
}
