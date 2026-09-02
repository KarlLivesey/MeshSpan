// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    AuditEventId, HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId,
    UnixMicros, VolumeId, WorkId,
};
use meshspan_work::{WorkBudget, WorkSignals, WorkSubject, WorkUsage};

use super::{
    AuthoritativeRepository, EntityKind, LogPosition, MaintenanceWorkState, RepositoryError,
};
use crate::{
    AuthoritativeCommand, BootstrapMesh, ClaimMaintenanceWork, CommandContext,
    CompleteMaintenanceWork, MaintenanceWorkCompletion, PartitionDatabase, QueueMaintenanceWork,
    RecordName, RenewMaintenanceWork,
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
        20,
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
        &AuthoritativeCommand::CompleteMaintenanceWork(fixture.retry(work_id, 1, 101, 200)),
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

struct Fixture {
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    node: NodeId,
    volume: VolumeId,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let administrator = PrincipalId::from_bytes([2; 16])?;
        let node = NodeId::from_bytes([6; 16])?;
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
                host_id: HostId::from_bytes([5; 16])?,
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
