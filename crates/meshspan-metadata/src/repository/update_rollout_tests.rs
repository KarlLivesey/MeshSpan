// SPDX-License-Identifier: GPL-2.0-only

use meshspan_certificates::{NodeIdentityKey, UPDATE_SIGNATURE_DOMAIN};
use meshspan_domain::{
    AuditEventId, ComponentInstanceId, HostId, MeshId, NodeId, OperationId, PartitionId,
    PrincipalId, Revision, RoleId, UnixMicros, WorkId,
};
use rusqlite::params;
use tempfile::{TempDir, tempdir};

use crate::{
    AdvanceUpdateNode, AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh,
    CommandContext, ConfigureUpdateSigner, ControlUpdateRollout, LogPosition, PageLimit,
    PartitionDatabase, RecordName, StartUpdateRollout, UpdateNodePhase, UpdateRolloutControl,
    UpdateRolloutState,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn artifact_source_is_bound_to_signed_bytes_and_current_node_incarnation() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.start()?;
    let source = crate::PublishUpdateArtifact {
        rollout_id: fixture.rollout,
        node_id: NodeId::from_bytes([6; 16])?,
        incarnation: 1,
        target: "aarch64-apple-darwin".to_owned(),
        byte_length: 47,
        sha256: "c".repeat(64),
    };
    let mut invalid = source.clone();
    invalid.sha256 = "d".repeat(64);
    assert!(
        fixture
            .commit(AuthoritativeCommand::PublishUpdateArtifact(invalid))
            .is_err()
    );
    let mut invalid = source.clone();
    invalid.incarnation = 2;
    assert!(
        fixture
            .commit(AuthoritativeCommand::PublishUpdateArtifact(invalid))
            .is_err()
    );
    fixture.commit(AuthoritativeCommand::PublishUpdateArtifact(source))?;
    fixture.reopen()?;
    let sources = fixture.repository.update_artifact_sources(
        fixture.rollout,
        "aarch64-apple-darwin",
        None,
        PageLimit::new(10)?,
    )?;
    assert_eq!(
        sources,
        vec![crate::UpdateArtifactSource {
            node_id: NodeId::from_bytes([6; 16])?,
            incarnation: 1
        }]
    );
    assert!(
        fixture
            .repository
            .update_artifact_sources(
                fixture.rollout,
                "aarch64-apple-darwin",
                Some(sources[0].node_id),
                PageLimit::new(10)?
            )?
            .is_empty()
    );
    assert!(
        fixture
            .nodes()?
            .iter()
            .all(|node| node.phase == UpdateNodePhase::Pending)
    );
    Ok(())
}

#[test]
fn rollout_requires_all_staged_and_resumes_exact_progress_after_database_restart() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.start()?;
    let pending = fixture.nodes()?;
    assert_eq!(pending.len(), 2);
    assert_eq!(
        fixture.repository.update_progress_counts(fixture.rollout)?,
        crate::UpdateProgressCounts {
            pending: 2,
            ..crate::UpdateProgressCounts::default()
        }
    );
    assert!(
        pending
            .iter()
            .all(|node| node.phase == UpdateNodePhase::Pending)
    );
    fixture.advance(6, UpdateNodePhase::Staged)?;
    assert!(fixture.advance(7, UpdateNodePhase::Restarting).is_err());
    assert!(fixture.advance(6, UpdateNodePhase::Restarting).is_err());
    fixture.advance(7, UpdateNodePhase::Staged)?;
    fixture.advance(6, UpdateNodePhase::Restarting)?;
    assert!(fixture.advance(7, UpdateNodePhase::Restarting).is_err());
    fixture.reopen()?;
    assert_eq!(fixture.nodes()?[0].phase, UpdateNodePhase::Restarting);
    assert!(fixture.nodes()?[0].restart_pending);
    assert_eq!(
        fixture.repository.update_progress_counts(fixture.rollout)?,
        crate::UpdateProgressCounts {
            staged: 1,
            restarting: 1,
            unresolved_restarts: 1,
            ..crate::UpdateProgressCounts::default()
        }
    );
    fixture.advance(6, UpdateNodePhase::Verified)?;
    fixture.advance(7, UpdateNodePhase::Restarting)?;
    fixture.advance(7, UpdateNodePhase::Verified)?;
    let complete = fixture
        .repository
        .update_rollout(fixture.rollout)?
        .ok_or("rollout absent")?;
    assert_eq!(complete.state, UpdateRolloutState::Completed);
    assert_eq!(
        fixture.repository.update_progress_counts(fixture.rollout)?,
        crate::UpdateProgressCounts {
            verified: 2,
            ..crate::UpdateProgressCounts::default()
        }
    );
    assert!(fixture.repository.active_update_rollout()?.is_none());
    assert!(
        fixture
            .nodes()?
            .iter()
            .all(|node| node.phase == UpdateNodePhase::Verified && !node.restart_pending)
    );
    Ok(())
}

#[test]
fn failed_restart_retains_exclusivity_and_resume_probes_instead_of_replacing_again() -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.start()?;
    fixture.advance(6, UpdateNodePhase::Staged)?;
    fixture.advance(7, UpdateNodePhase::Staged)?;
    fixture.advance(6, UpdateNodePhase::Restarting)?;
    fixture.advance(6, UpdateNodePhase::Failed)?;
    assert_eq!(fixture.active()?.state, UpdateRolloutState::Paused);
    assert!(fixture.nodes()?[0].restart_pending);
    assert!(fixture.control(UpdateRolloutControl::Cancel).is_err());
    fixture.reopen()?;
    fixture.control(UpdateRolloutControl::Resume)?;
    assert_eq!(fixture.nodes()?[0].phase, UpdateNodePhase::Restarting);
    assert!(fixture.advance(7, UpdateNodePhase::Restarting).is_err());
    fixture.advance(6, UpdateNodePhase::Verified)?;
    fixture.control(UpdateRolloutControl::Cancel)?;
    assert_eq!(
        fixture
            .repository
            .update_rollout(fixture.rollout)?
            .ok_or("rollout absent")?
            .state,
        UpdateRolloutState::Cancelled
    );
    assert_eq!(fixture.nodes()?[0].phase, UpdateNodePhase::Verified);
    Ok(())
}

#[test]
fn signer_revocation_pauses_and_untrusted_candidate_is_not_admitted() -> TestResult {
    let mut fixture = Fixture::new()?;
    let mut invalid = fixture.start_command()?;
    invalid.signature[4] ^= 1;
    assert!(
        fixture
            .commit(AuthoritativeCommand::StartUpdateRollout(invalid))
            .is_err()
    );
    assert!(fixture.repository.active_update_rollout()?.is_none());
    fixture.start()?;
    fixture.configure_signer(false)?;
    assert_eq!(fixture.active()?.state, UpdateRolloutState::Paused);
    assert!(fixture.control(UpdateRolloutControl::Resume).is_err());
    fixture.configure_signer(true)?;
    assert_eq!(fixture.active()?.state, UpdateRolloutState::Paused);
    fixture.control(UpdateRolloutControl::Resume)?;
    assert_eq!(fixture.active()?.state, UpdateRolloutState::Running);
    let mut changed = fixture.signer_command(true)?;
    changed
        .public_key
        .copy_from_slice(NodeIdentityKey::generate()?.public_key_sec1());
    assert!(
        fixture
            .commit(AuthoritativeCommand::ConfigureUpdateSigner(changed))
            .is_err()
    );
    let (context, command) = fixture.last.as_ref().ok_or("prior command absent")?;
    let index = fixture.repository.current_revision()?.get() + 1;
    let receipt =
        fixture
            .repository
            .apply_committed(LogPosition { index, term: 1 }, *context, command)?;
    assert_eq!(receipt.disposition, crate::ApplyDisposition::Replayed);
    assert_eq!(receipt.request_digest, command.request_digest(*context));
    assert_eq!(fixture.active()?.state, UpdateRolloutState::Running);
    Ok(())
}

struct Fixture {
    directory: TempDir,
    repository: AuthoritativeRepository,
    key: NodeIdentityKey,
    signer: ComponentInstanceId,
    rollout: WorkId,
    last: Option<(CommandContext, AuthoritativeCommand)>,
}

#[test]
fn restart_uses_real_quorum_predicates_and_requires_explicit_interruption_consent() -> TestResult {
    let mut insufficient = Fixture::with_nodes(2)?;
    let mut start = insufficient.start_command()?;
    start.allow_service_interruption = false;
    insufficient.commit(AuthoritativeCommand::StartUpdateRollout(start))?;
    insufficient.advance(6, UpdateNodePhase::Staged)?;
    insufficient.advance(7, UpdateNodePhase::Staged)?;
    assert!(
        insufficient
            .advance(6, UpdateNodePhase::Restarting)
            .is_err()
    );
    assert!(
        !insufficient
            .nodes()?
            .iter()
            .any(|node| node.restart_pending)
    );

    let mut redundant = Fixture::with_nodes(3)?;
    let mut start = redundant.start_command()?;
    start.allow_service_interruption = false;
    redundant.commit(AuthoritativeCommand::StartUpdateRollout(start))?;
    for node in 6..9 {
        redundant.advance(node, UpdateNodePhase::Staged)?;
    }
    redundant.advance(6, UpdateNodePhase::Restarting)?;
    assert!(redundant.nodes()?[0].restart_pending);
    Ok(())
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_nodes(2)
    }

    fn with_nodes(count: u8) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let database = PartitionDatabase::open(
            &directory.path().join("authority.sqlite3"),
            PartitionId::from_bytes([1; 16])?,
            UnixMicros::new(1),
        )?;
        let mut fixture = Self {
            directory,
            repository: AuthoritativeRepository::new(database),
            key: NodeIdentityKey::generate()?,
            signer: ComponentInstanceId::from_bytes([8; 16])?,
            rollout: WorkId::from_bytes([9; 16])?,
            last: None,
        };
        let bootstrap = super::tests::protected_bootstrap(BootstrapMesh {
            mesh_id: MeshId::from_bytes([3; 16])?,
            mesh_name: RecordName::new("Update proof")?,
            administrator_id: PrincipalId::from_bytes([2; 16])?,
            administrator_name: RecordName::new("Admin")?,
            administrator_role_id: RoleId::from_bytes([4; 16])?,
            host_id: HostId::from_bytes([5; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([6; 16])?,
            node_name: RecordName::new("First")?,
            partition_name: RecordName::new("Root")?,
        })?;
        fixture.commit(bootstrap)?;
        // Additional active members in this persistence fixture, not a process or HA proof.
        for number in 7..6 + count {
            fixture.repository.database.connection().execute("INSERT INTO nodes(node_id,host_id,display_name,canonical_name,state,current_incarnation,admitted_at,activated_at,retired_at,revision)
                VALUES (?1,?2,?3,?3,2,1,1,1,NULL,1)",params![[number;16].as_slice(),[5_u8;16].as_slice(),format!("Node {number}")])?;
            fixture.repository.database.connection().execute(
                "INSERT INTO node_roles(node_id,role_code,revision) VALUES (?1,2,1)",
                [[number; 16].as_slice()],
            )?;
        }
        let voters = (6..6 + count)
            .map(|number| NodeId::from_bytes([number; 16]))
            .collect::<Result<_, _>>()?;
        let plan = meshspan_consensus::compile_plan(meshspan_consensus::flat_plan(
            meshspan_domain::QuorumPlanId::from_bytes([50; 16])?,
            1,
            voters,
            std::collections::BTreeSet::default(),
        )?)?;
        fixture
            .repository
            .initialise_consensus_quorum_plan(&plan, UnixMicros::new(1))?;
        fixture.configure_signer(true)?;
        Ok(fixture)
    }

    fn commit(&mut self, command: AuthoritativeCommand) -> TestResult {
        let index = self.repository.current_revision()?.get() + 1;
        let context = CommandContext {
            operation_id: OperationId::from_bytes([u8::try_from(index + 10)?; 16])?,
            actor_principal_id: PrincipalId::from_bytes([2; 16])?,
            audit_event_id: AuditEventId::from_bytes([u8::try_from(index + 100)?; 16])?,
            occurred_at: UnixMicros::new(i64::try_from(index)?),
            expected_revision: Some(Revision::new(index - 1)),
        };
        let encoded = crate::encode_authoritative_command(context, &command)?;
        let decoded = crate::decode_authoritative_command(&encoded)?;
        assert_eq!(decoded.command, command);
        assert_eq!(decoded.context, context);
        self.repository
            .apply_committed(LogPosition { index, term: 1 }, context, &command)?;
        self.last = Some((context, command));
        Ok(())
    }

    fn signer_command(
        &self,
        enabled: bool,
    ) -> Result<ConfigureUpdateSigner, Box<dyn std::error::Error>> {
        let sequence = self
            .repository
            .update_signers()?
            .first()
            .map_or(0, |row| row.sequence);
        Ok(ConfigureUpdateSigner {
            signer_id: self.signer,
            expected_sequence: sequence,
            public_key: self.key.public_key_sec1().try_into()?,
            enabled,
        })
    }

    fn configure_signer(&mut self, enabled: bool) -> TestResult {
        self.commit(AuthoritativeCommand::ConfigureUpdateSigner(
            self.signer_command(enabled)?,
        ))
    }

    fn start_command(&self) -> Result<StartUpdateRollout, Box<dyn std::error::Error>> {
        let schema = crate::migration::PARTITION_SCHEMA_VERSION;
        let manifest = serde_json::to_vec(
            &serde_json::json!({"format":1,"licence":"GPL-2.0-only","version":"0.1.0","source_commit":"a".repeat(40),"api_sha256":"b".repeat(64),
            "compatibility":{"private_protocol_major":1,"partition_schema_min":schema,"partition_schema_max":schema,"partition_schema_target":schema,"rollback_supported":false},
            "artifacts":[{"target":"aarch64-apple-darwin","size":"47","sha256":"c".repeat(64)}]}),
        )?;
        let mut transcript = UPDATE_SIGNATURE_DOMAIN.to_vec();
        transcript.extend_from_slice(&manifest);
        let signature = self.key.sign_enrolment_transcript(&transcript)?;
        Ok(StartUpdateRollout {
            rollout_id: self.rollout,
            signer_id: self.signer,
            signer_sequence: self.repository.update_signers()?[0].sequence,
            manifest,
            signature,
            allow_service_interruption: true,
        })
    }

    fn start(&mut self) -> TestResult {
        self.commit(AuthoritativeCommand::StartUpdateRollout(
            self.start_command()?,
        ))
    }

    fn nodes(&self) -> Result<Vec<crate::UpdateNodeRecord>, crate::RepositoryError> {
        self.repository
            .update_rollout_nodes(self.rollout, None, PageLimit::new(10)?)
    }

    fn active(&self) -> Result<crate::UpdateRolloutRecord, Box<dyn std::error::Error>> {
        Ok(self
            .repository
            .active_update_rollout()?
            .ok_or("active rollout absent")?)
    }

    fn advance(&mut self, number: u8, phase: UpdateNodePhase) -> TestResult {
        let node_id = NodeId::from_bytes([number; 16])?;
        let sequence = self
            .nodes()?
            .into_iter()
            .find(|node| node.node_id == node_id)
            .ok_or("node absent")?
            .sequence;
        let restart_readiness = if phase == UpdateNodePhase::Restarting {
            let applied_index = self.repository.current_revision()?.get();
            Some(crate::UpdateRestartReadiness {
                quorum_plan_digest: self
                    .repository
                    .load_active_consensus_quorum_plan()?
                    .ok_or("plan missing")?
                    .proof_digest(),
                observed_at: UnixMicros::new(1),
                ready_nodes: self
                    .nodes()?
                    .into_iter()
                    .filter(|node| node.node_id != node_id && !node.restart_pending)
                    .map(|node| crate::UpdateReadyNode {
                        node_id: node.node_id,
                        incarnation: node.incarnation,
                        applied_index,
                    })
                    .collect(),
            })
        } else {
            None
        };
        self.commit(AuthoritativeCommand::AdvanceUpdateNode(AdvanceUpdateNode {
            rollout_id: self.rollout,
            node_id,
            incarnation: 1,
            expected_sequence: sequence,
            phase,
            target: "aarch64-apple-darwin".to_owned(),
            evidence_digest: [number; 32],
            restart_readiness,
        }))
    }

    fn control(&mut self, action: UpdateRolloutControl) -> TestResult {
        self.commit(AuthoritativeCommand::ControlUpdateRollout(
            ControlUpdateRollout {
                rollout_id: self.rollout,
                expected_sequence: self.active()?.sequence,
                action,
            },
        ))
    }

    fn reopen(&mut self) -> TestResult {
        let database = PartitionDatabase::open(
            &self.directory.path().join("authority.sqlite3"),
            PartitionId::from_bytes([1; 16])?,
            UnixMicros::new(30),
        )?;
        self.repository = AuthoritativeRepository::new(database);
        Ok(())
    }
}
