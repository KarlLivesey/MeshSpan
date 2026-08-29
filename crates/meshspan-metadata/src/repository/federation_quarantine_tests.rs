// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::{Signer, SigningKey};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, DurationMicros, FederatedMutationEvidence, FederatedPrincipal, FederationGrant,
    FederationGrantId, FederationPolicy, FederationRelationshipId, FederationRelationshipKind,
    FederationResourceScope, HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId,
    QuarantineId, QuarantineReason, Revision, Rights, RoleId, StorageFederationPolicy,
    StorageParticipation, UnixMicros,
};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault, read_current_revision};
use super::{
    AuthoritativeRepository, EntityKind, FederationQuarantineState, LogPosition, RepositoryError,
};
use crate::{
    ApproveFederationRelationship, AuthoritativeCommand, BootstrapMesh, CommandContext,
    FederationGovernanceDirection, FederationGrantRestriction, FederationQuarantineResolution,
    FederationTrustIdentity, IssueFederationGrant, PartitionDatabase,
    ProposeFederationRelationship, RecordName, ResolveFederatedMutationQuarantine,
    RetainFederatedMutationQuarantine, SurfaceFederatedMutationQuarantine,
};

#[test]
fn signed_quarantine_lifecycle_is_atomic_and_restart_safe() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fixture = Fixture::open("quarantine-lifecycle.sqlite3")?;
    fixture.prepare()?;

    let admitted = fixture.retain_command(31, 32, 50)?;
    fixture.assert_rejected(5, 33, &admitted)?;
    let forged = fixture.retain_command(34, 35, 51)?;
    let mut forged_signature = forged.signature;
    forged_signature[0] ^= 1;
    fixture.assert_rejected(
        5,
        36,
        &RetainFederatedMutationQuarantine {
            signature: forged_signature,
            ..forged
        },
    )?;

    let retained = fixture.retain_command(37, 38, 51)?;
    let quarantine_id = retained.quarantine_id;
    let source_operation_id = retained.source_operation_id;
    let receipt = fixture.apply(
        5,
        39,
        &AuthoritativeCommand::RetainFederatedMutationQuarantine(retained),
    )?;
    assert_eq!(receipt.entity.kind, EntityKind::FederationQuarantine);
    assert_eq!(receipt.entity.id, quarantine_id.as_bytes());
    fixture.assert_state(
        quarantine_id,
        FederationQuarantineState::Retained,
        None,
        QuarantineReason::OutsideStorageLimit,
    )?;

    fixture.assert_resolve_rejected_before_surface(quarantine_id, source_operation_id)?;
    fixture.apply(
        6,
        42,
        &AuthoritativeCommand::SurfaceFederatedMutationQuarantine(
            SurfaceFederatedMutationQuarantine {
                quarantine_id,
                source_operation_id,
            },
        ),
    )?;
    fixture.assert_state(
        quarantine_id,
        FederationQuarantineState::Surfaced,
        None,
        QuarantineReason::OutsideStorageLimit,
    )?;
    fixture.assert_surface_rejected_twice(quarantine_id, source_operation_id)?;

    fixture.apply(
        7,
        45,
        &AuthoritativeCommand::ResolveFederatedMutationQuarantine(
            ResolveFederatedMutationQuarantine {
                quarantine_id,
                source_operation_id,
                resolution: FederationQuarantineResolution::RestoreAsCopy,
                reason: "Authorised recovery as a separate copy".to_owned(),
            },
        ),
    )?;
    fixture.assert_state(
        quarantine_id,
        FederationQuarantineState::Restored,
        Some(FederationQuarantineResolution::RestoreAsCopy),
        QuarantineReason::OutsideStorageLimit,
    )?;

    let Fixture {
        _directory,
        file_path,
        repository,
        ids,
        local_signing_key: _,
    } = fixture;
    drop(repository);
    let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(50))?;
    let repository = AuthoritativeRepository::new(database);
    let recovered = repository
        .federation_quarantine(quarantine_id)?
        .ok_or("quarantine missing after restart")?;
    assert_eq!(recovered.state, FederationQuarantineState::Restored);
    assert_eq!(
        recovered.resolution,
        Some(FederationQuarantineResolution::RestoreAsCopy)
    );
    Ok(())
}

#[test]
fn quarantine_proofs_are_immutable_and_corruption_fails_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::open("quarantine-corruption.sqlite3")?;
    fixture.prepare()?;
    let command = fixture.retain_command(51, 52, 51)?;
    let quarantine_id = command.quarantine_id;
    let source_operation_id = command.source_operation_id;
    fixture.apply(
        5,
        53,
        &AuthoritativeCommand::RetainFederatedMutationQuarantine(command),
    )?;
    fixture.apply(
        6,
        54,
        &AuthoritativeCommand::SurfaceFederatedMutationQuarantine(
            SurfaceFederatedMutationQuarantine {
                quarantine_id,
                source_operation_id,
            },
        ),
    )?;
    fixture.apply(
        7,
        55,
        &AuthoritativeCommand::ResolveFederatedMutationQuarantine(
            ResolveFederatedMutationQuarantine {
                quarantine_id,
                source_operation_id,
                resolution: FederationQuarantineResolution::Discard,
                reason: "Explicitly discarded after authorised review".to_owned(),
            },
        ),
    )?;
    fixture.assert_state(
        quarantine_id,
        FederationQuarantineState::Discarded,
        Some(FederationQuarantineResolution::Discard),
        QuarantineReason::OutsideStorageLimit,
    )?;

    let database = fixture.repository.into_database();
    assert!(
        database
            .connection()
            .execute(
                "UPDATE federation_quarantine_acknowledgements
                 SET signer_generation = 2 WHERE quarantine_id = ?1",
                [quarantine_id.as_bytes().as_slice()],
            )
            .is_err()
    );
    assert!(
        database
            .connection()
            .execute(
                "DELETE FROM federation_quarantine_events WHERE quarantine_id = ?1",
                [quarantine_id.as_bytes().as_slice()],
            )
            .is_err()
    );

    database.connection().execute_batch(
        "DROP TRIGGER federation_quarantine_events_reject_update;
         UPDATE federation_quarantine_events
         SET event_kind = 3
         WHERE event_sequence = 3;",
    )?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.federation_quarantine(quarantine_id),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

#[test]
fn every_apply_boundary_rolls_back_the_complete_quarantine_proof()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::open("quarantine-atomicity.sqlite3")?;
    fixture.prepare()?;
    let command = AuthoritativeCommand::RetainFederatedMutationQuarantine(
        fixture.retain_command(61, 62, 51)?,
    );
    let mut database = fixture.repository.into_database();
    for (offset, fault) in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let seed = 63_u8.wrapping_add(u8::try_from(offset)?);
        assert!(matches!(
            apply_committed_with_fault(
                &mut database,
                LogPosition { index: 5, term: 1 },
                context(seed, fixture.ids.administrator, seed.wrapping_add(1), 63, 4)?,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        let counts: (i64, i64, i64) = database.connection().query_row(
            "SELECT
                (SELECT count(*) FROM federation_quarantine),
                (SELECT count(*) FROM federation_quarantine_acknowledgements),
                (SELECT count(*) FROM federation_quarantine_events)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(counts, (0, 0, 0));
        assert_eq!(read_current_revision(&database)?, Revision::new(4));
    }
    Ok(())
}

#[test]
fn missing_acknowledgement_is_corruption_not_absence() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::open("quarantine-missing-proof.sqlite3")?;
    fixture.prepare()?;
    let command = fixture.retain_command(71, 72, 51)?;
    let quarantine_id = command.quarantine_id;
    fixture.apply(
        5,
        73,
        &AuthoritativeCommand::RetainFederatedMutationQuarantine(command),
    )?;
    let database = fixture.repository.into_database();
    database.connection().execute_batch(
        "DROP TRIGGER federation_quarantine_acknowledgements_reject_delete;
         DELETE FROM federation_quarantine_acknowledgements;",
    )?;
    let repository = AuthoritativeRepository::new(database);
    assert!(matches!(
        repository.federation_quarantine(quarantine_id),
        Err(RepositoryError::CorruptState)
    ));
    Ok(())
}

struct Fixture {
    _directory: tempfile::TempDir,
    file_path: std::path::PathBuf,
    repository: AuthoritativeRepository,
    ids: FixtureIds,
    local_signing_key: SigningKey,
}

#[derive(Clone, Copy)]
struct FixtureIds {
    administrator: PrincipalId,
    partition: PartitionId,
    local_mesh: MeshId,
    remote_mesh: MeshId,
    relationship: FederationRelationshipId,
    grant: FederationGrantId,
}

impl Fixture {
    fn open(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let file_path = directory.path().join(name);
        let ids = FixtureIds {
            administrator: PrincipalId::from_bytes([1; 16])?,
            partition: PartitionId::from_bytes([2; 16])?,
            local_mesh: MeshId::from_bytes([20; 16])?,
            remote_mesh: MeshId::from_bytes([21; 16])?,
            relationship: FederationRelationshipId::from_bytes([22; 16])?,
            grant: FederationGrantId::from_bytes([23; 16])?,
        };
        let database = PartitionDatabase::open(&file_path, ids.partition, UnixMicros::new(0))?;
        Ok(Self {
            _directory: directory,
            file_path,
            repository: AuthoritativeRepository::new(database),
            ids,
            local_signing_key: SigningKey::from_bytes(&[13; 32]),
        })
    }

    fn prepare(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.apply(
            1,
            3,
            &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
                mesh_id: self.ids.local_mesh,
                mesh_name: RecordName::new("Local swarm")?,
                administrator_id: self.ids.administrator,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([5; 16])?,
                host_id: HostId::from_bytes([6; 16])?,
                host_name: RecordName::new("Host")?,
                node_id: NodeId::from_bytes([7; 16])?,
                node_name: RecordName::new("Node")?,
                partition_name: RecordName::new("Root authority")?,
            }),
        )?;
        self.apply(
            2,
            8,
            &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
                relationship_id: self.ids.relationship,
                remote_mesh_id: self.ids.remote_mesh,
                remote_name: RecordName::new("Storage partner")?,
                kind: FederationRelationshipKind::Horizontal,
                governance_direction: FederationGovernanceDirection::None,
            }),
        )?;
        self.apply(
            3,
            10,
            &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
                relationship_id: self.ids.relationship,
                expected_authority_epoch: 1,
                local_identity: identity(1, 12, &self.local_signing_key),
                remote_identity: identity(1, 14, &SigningKey::from_bytes(&[15; 32])),
                governance_proof: None,
            }),
        )?;
        let policy = storage_policy(50)?;
        self.apply(
            4,
            16,
            &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
                grant: FederationGrant::new(
                    self.ids.grant,
                    self.ids.relationship,
                    FederatedPrincipal::new(self.ids.local_mesh, self.ids.administrator),
                    FederationResourceScope::StorageCapacity {
                        provider_mesh_id: self.ids.remote_mesh,
                    },
                    policy,
                    1,
                    UnixMicros::new(4),
                    Some(UnixMicros::new(100)),
                )?,
                restrictions: BoundedItems::new(
                    vec![
                        FederationGrantRestriction {
                            imposing_mesh_id: self.ids.local_mesh,
                            policy,
                        },
                        FederationGrantRestriction {
                            imposing_mesh_id: self.ids.remote_mesh,
                            policy,
                        },
                    ],
                    2,
                )?,
            }),
        )?;
        Ok(())
    }

    fn retain_command(
        &self,
        quarantine: u8,
        source_operation: u8,
        storage_bytes: u64,
    ) -> Result<RetainFederatedMutationQuarantine, Box<dyn std::error::Error>> {
        let evidence = FederatedMutationEvidence::new(
            self.ids.grant,
            self.ids.relationship,
            FederatedPrincipal::new(self.ids.local_mesh, self.ids.administrator),
            FederationResourceScope::StorageCapacity {
                provider_mesh_id: self.ids.remote_mesh,
            },
            1,
            UnixMicros::new(5),
            Rights::default(),
            storage_bytes,
        );
        let mut command = RetainFederatedMutationQuarantine {
            quarantine_id: QuarantineId::from_bytes([quarantine; 16])?,
            source_operation_id: OperationId::from_bytes([source_operation; 16])?,
            evidence,
            payload_digest: [quarantine.wrapping_add(1); 32],
            signer_generation: 1,
            signature: [0; 64],
        };
        command.signature = self
            .local_signing_key
            .sign(&command.signing_payload())
            .to_bytes();
        Ok(command)
    }

    fn assert_rejected(
        &mut self,
        index: u64,
        context_seed: u8,
        command: &RetainFederatedMutationQuarantine,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let revision = self.repository.current_revision()?;
        assert!(matches!(
            self.repository.apply_committed(
                LogPosition { index, term: 1 },
                context(
                    context_seed,
                    self.ids.administrator,
                    context_seed.wrapping_add(1),
                    i64::from(context_seed),
                    revision.get(),
                )?,
                &AuthoritativeCommand::RetainFederatedMutationQuarantine(*command),
            ),
            Err(RepositoryError::InvalidCommand)
        ));
        assert_eq!(self.repository.current_revision()?, revision);
        assert!(
            self.repository
                .federation_quarantine(command.quarantine_id)?
                .is_none()
        );
        Ok(())
    }

    fn assert_resolve_rejected_before_surface(
        &mut self,
        quarantine_id: QuarantineId,
        source_operation_id: OperationId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let revision = self.repository.current_revision()?;
        assert!(matches!(
            self.repository.apply_committed(
                LogPosition { index: 6, term: 1 },
                context(40, self.ids.administrator, 41, 40, revision.get())?,
                &AuthoritativeCommand::ResolveFederatedMutationQuarantine(
                    ResolveFederatedMutationQuarantine {
                        quarantine_id,
                        source_operation_id,
                        resolution: FederationQuarantineResolution::Restore,
                        reason: "Premature restore".to_owned(),
                    },
                ),
            ),
            Err(RepositoryError::InvalidCommand)
        ));
        assert_eq!(self.repository.current_revision()?, revision);
        Ok(())
    }

    fn assert_surface_rejected_twice(
        &mut self,
        quarantine_id: QuarantineId,
        source_operation_id: OperationId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let revision = self.repository.current_revision()?;
        assert!(matches!(
            self.repository.apply_committed(
                LogPosition { index: 7, term: 1 },
                context(43, self.ids.administrator, 44, 43, revision.get())?,
                &AuthoritativeCommand::SurfaceFederatedMutationQuarantine(
                    SurfaceFederatedMutationQuarantine {
                        quarantine_id,
                        source_operation_id,
                    },
                ),
            ),
            Err(RepositoryError::InvalidCommand)
        ));
        assert_eq!(self.repository.current_revision()?, revision);
        Ok(())
    }

    fn apply(
        &mut self,
        index: u64,
        operation_seed: u8,
        command: &AuthoritativeCommand,
    ) -> Result<super::CommandReceipt, Box<dyn std::error::Error>> {
        let revision = self.repository.current_revision()?;
        Ok(self.repository.apply_committed(
            LogPosition { index, term: 1 },
            context(
                operation_seed,
                self.ids.administrator,
                operation_seed.wrapping_add(1),
                i64::from(operation_seed),
                revision.get(),
            )?,
            command,
        )?)
    }

    fn assert_state(
        &self,
        quarantine_id: QuarantineId,
        state: FederationQuarantineState,
        resolution: Option<FederationQuarantineResolution>,
        reason: QuarantineReason,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let record = self
            .repository
            .federation_quarantine(quarantine_id)?
            .ok_or("quarantine record missing")?;
        assert_eq!(record.state, state);
        assert_eq!(record.resolution, resolution);
        assert_eq!(record.reason, reason);
        Ok(())
    }
}

fn storage_policy(
    maximum_storage_bytes: u64,
) -> Result<FederationPolicy, Box<dyn std::error::Error>> {
    Ok(FederationPolicy::Storage(StorageFederationPolicy::new(
        maximum_storage_bytes,
        StorageParticipation::new(true, true),
        Some(DurationMicros::new(96)),
    )?))
}

fn identity(generation: u64, fingerprint: u8, signing_key: &SigningKey) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation,
        certificate_fingerprint: [fingerprint; 32],
        verifying_key: signing_key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(100),
    }
}

fn context(
    operation: u8,
    actor: PrincipalId,
    audit: u8,
    occurred_at: i64,
    expected_revision: u64,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation; 16])?,
        actor_principal_id: actor,
        audit_event_id: AuditEventId::from_bytes([audit; 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision: Some(Revision::new(expected_revision)),
    })
}
