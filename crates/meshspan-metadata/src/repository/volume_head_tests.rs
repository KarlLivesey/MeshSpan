// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeSet;

use meshspan_contracts::BoundedItems;
use meshspan_contracts::namespace_reconciliation_result_digest;
use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, HostId, MeshId, NamespaceCommitId, NodeId,
    ObjectId, ObjectRevisionId, OperationId, OwnerSetId, PartitionId, PrincipalId, Revision,
    RoleId, UnixMicros, VolumeId,
};
use meshspan_secret_envelope::WrappingPublicKey;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::tests::{initial_test_volume_key, mark_test_recovery_verified};
use super::{ApplyDisposition, AuthoritativeRepository, LogPosition, RepositoryError};
use crate::{
    AuthoritativeCommand, BootstrapAppliance, BootstrapMesh, BootstrapRecoveryIdentity,
    CommandContext, CommitConvergedVolumeHead, ConvergedHeadEvidence, CreateAuthenticationMethod,
    CreateVolume, NewAuthenticationCredential, PartitionDatabase, RecordName,
};

pub(super) struct HeadFixture {
    pub(super) administrator: PrincipalId,
    pub(super) partition: PartitionId,
    pub(super) volume: VolumeId,
}

#[test]
fn converged_head_digest_binds_every_authority_and_evidence_field()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let context = context(90, fixture.administrator, 91, 500, None)?;
    let base = reconciliation_command(&fixture, commit(92)?, 93, 94, 95, 96, 97, 98)?;
    let mut commands = vec![base.clone()];
    let AuthoritativeCommand::CommitConvergedVolumeHead(base_value) = base else {
        return Err("wrong fixture command".into());
    };
    for value in [
        CommitConvergedVolumeHead {
            volume_id: VolumeId::from_bytes([100; 16])?,
            ..base_value
        },
        CommitConvergedVolumeHead {
            expected_namespace_commit_id: Some(commit(101)?),
            ..base_value
        },
        CommitConvergedVolumeHead {
            namespace_commit_id: commit(102)?,
            ..base_value
        },
        CommitConvergedVolumeHead {
            root_object_revision_id: object_revision(103)?,
            ..base_value
        },
    ] {
        commands.push(AuthoritativeCommand::CommitConvergedVolumeHead(value));
    }
    let ConvergedHeadEvidence::Reconciliation {
        operation_id,
        request_digest,
        causal_plan_digest,
        replay_plan_digest,
        result_digest,
    } = base_value.evidence
    else {
        return Err("wrong fixture evidence".into());
    };
    for evidence in [
        ConvergedHeadEvidence::Reconciliation {
            operation_id: OperationId::from_bytes([104; 16])?,
            request_digest,
            causal_plan_digest,
            replay_plan_digest,
            result_digest,
        },
        ConvergedHeadEvidence::Reconciliation {
            operation_id,
            request_digest: [105; 32],
            causal_plan_digest,
            replay_plan_digest,
            result_digest,
        },
        ConvergedHeadEvidence::Reconciliation {
            operation_id,
            request_digest,
            causal_plan_digest: [106; 32],
            replay_plan_digest,
            result_digest,
        },
        ConvergedHeadEvidence::Reconciliation {
            operation_id,
            request_digest,
            causal_plan_digest,
            replay_plan_digest: [107; 32],
            result_digest,
        },
        ConvergedHeadEvidence::Reconciliation {
            operation_id,
            request_digest,
            causal_plan_digest,
            replay_plan_digest,
            result_digest: [108; 32],
        },
    ] {
        commands.push(AuthoritativeCommand::CommitConvergedVolumeHead(
            CommitConvergedVolumeHead {
                evidence,
                ..base_value
            },
        ));
    }
    let digests = commands
        .iter()
        .map(|command| command.request_digest(context))
        .collect::<BTreeSet<_>>();
    assert_eq!(digests.len(), commands.len());
    Ok(())
}

#[test]
fn publication_then_reconciliation_advances_exact_head_and_survives_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("heads.sqlite3");
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&file_path, &fixture)?;
    let first = publication_command(&fixture, None, 30, 31, 32, 33, 34)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(35, fixture.administrator, 36, 102, Some(2))?,
        &first,
    )?;
    let first_head = repository
        .converged_volume_head(fixture.volume)?
        .ok_or("missing first volume head")?;
    assert_eq!(first_head.sequence, 1);
    assert_eq!(first_head.namespace_commit_id, commit(30)?);

    let second = reconciliation_command(&fixture, commit(30)?, 40, 41, 42, 43, 44, 45)?;
    let second_context = context(47, fixture.administrator, 48, 103, Some(3))?;
    let applied =
        repository.apply_committed(LogPosition { index: 4, term: 1 }, second_context, &second)?;
    assert_eq!(applied.disposition, ApplyDisposition::Applied);
    let replay =
        repository.apply_committed(LogPosition { index: 5, term: 1 }, second_context, &second)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.committed_revision, Revision::new(4));
    assert_eq!(repository.current_revision()?, Revision::new(4));
    drop(repository);

    let reopened = PartitionDatabase::open(&file_path, fixture.partition, UnixMicros::new(200))?;
    let repository = AuthoritativeRepository::new(reopened);
    let head = repository
        .converged_volume_head(fixture.volume)?
        .ok_or("missing reconciled volume head")?;
    assert_eq!(head.sequence, 2);
    assert_eq!(head.namespace_commit_id, commit(40)?);
    assert_eq!(head.root_object_revision_id, object_revision(41)?);
    assert_eq!(head.metadata_operation_id, second_context.operation_id);
    assert_eq!(
        head.evidence,
        ConvergedHeadEvidence::Reconciliation {
            operation_id: OperationId::from_bytes([42; 16])?,
            request_digest: [43; 32],
            causal_plan_digest: [44; 32],
            replay_plan_digest: [45; 32],
            result_digest: namespace_reconciliation_result_digest(
                OperationId::from_bytes([42; 16])?,
                commit(40)?,
                [43; 32],
                [44; 32],
                [45; 32],
                object_revision(41)?,
            ),
        }
    );
    Ok(())
}

#[test]
fn stale_or_substituted_head_evidence_fails_without_advancing()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&directory.path().join("stale.sqlite3"), &fixture)?;
    let first = publication_command(&fixture, None, 50, 51, 52, 53, 54)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(55, fixture.administrator, 56, 102, Some(2))?,
        &first,
    )?;
    let stale = publication_command(&fixture, Some(commit(57)?), 58, 59, 60, 61, 62)?;
    assert!(matches!(
        repository.apply_committed(
            LogPosition { index: 4, term: 1 },
            context(63, fixture.administrator, 64, 103, Some(3))?,
            &stale,
        ),
        Err(RepositoryError::StaleVolumeHead)
    ));
    assert_eq!(repository.current_revision()?, Revision::new(3));
    assert_eq!(
        repository
            .converged_volume_head(fixture.volume)?
            .ok_or("missing unchanged head")?
            .namespace_commit_id,
        commit(50)?
    );

    let context = context(65, fixture.administrator, 66, 104, Some(3))?;
    let valid = publication_command(&fixture, Some(commit(50)?), 67, 68, 69, 70, 71)?;
    repository.apply_committed(LogPosition { index: 4, term: 1 }, context, &valid)?;
    let substituted = publication_command(&fixture, Some(commit(50)?), 67, 68, 69, 70, 72)?;
    assert!(matches!(
        repository.apply_committed(LogPosition { index: 5, term: 1 }, context, &substituted),
        Err(RepositoryError::OperationConflict)
    ));
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_the_complete_head_transition()
-> Result<(), Box<dyn std::error::Error>> {
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        let directory = tempdir()?;
        let fixture = fixture()?;
        let mut repository = open_and_prepare(&directory.path().join("fault.sqlite3"), &fixture)?;
        let command = publication_command(&fixture, None, 80, 81, 82, 83, 84)?;
        let context = context(85, fixture.administrator, 86, 102, Some(2))?;
        let interrupted = apply_committed_with_fault(
            &mut repository.database,
            LogPosition { index: 3, term: 1 },
            context,
            &command,
            fault,
        );
        assert!(matches!(interrupted, Err(RepositoryError::InjectedFault)));
        assert_eq!(repository.current_revision()?, Revision::new(2));
        assert_eq!(repository.converged_volume_head(fixture.volume)?, None);
        repository.apply_committed(LogPosition { index: 3, term: 1 }, context, &command)?;
        assert_eq!(
            repository
                .converged_volume_head(fixture.volume)?
                .ok_or("missing retried head")?
                .sequence,
            1
        );
    }
    Ok(())
}

#[test]
fn broken_head_history_fails_closed_in_reads_and_invariant_checks()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&directory.path().join("corrupt.sqlite3"), &fixture)?;
    let first = publication_command(&fixture, None, 110, 111, 112, 113, 114)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(115, fixture.administrator, 116, 102, Some(2))?,
        &first,
    )?;
    let second = publication_command(&fixture, Some(commit(110)?), 117, 118, 119, 120, 121)?;
    repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(122, fixture.administrator, 123, 103, Some(3))?,
        &second,
    )?;
    repository.database.connection_mut().execute(
        "UPDATE volume_head_transitions SET previous_namespace_commit_id = ?1
         WHERE volume_id = ?2 AND head_sequence = 2",
        rusqlite::params![
            commit(124)?.as_bytes().as_slice(),
            fixture.volume.as_bytes().as_slice(),
        ],
    )?;
    assert!(matches!(
        repository.converged_volume_head(fixture.volume),
        Err(RepositoryError::CorruptState)
    ));
    let report = repository.check_invariants(super::PageLimit::new(100)?)?;
    assert!(report.findings.iter().any(|finding| {
        finding.kind == super::InvariantKind::InvalidVolumeHeadHistory
            && finding.subject_id == fixture.volume.as_bytes()
    }));
    Ok(())
}

pub(super) fn open_and_prepare(
    file_path: &std::path::Path,
    fixture: &HeadFixture,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    let database = PartitionDatabase::open(file_path, fixture.partition, UnixMicros::new(1))?;
    let mut repository = AuthoritativeRepository::new(database);
    repository.apply_committed(
        LogPosition { index: 1, term: 1 },
        context(10, fixture.administrator, 11, 100, Some(0))?,
        &head_bootstrap(fixture)?,
    )?;
    mark_test_recovery_verified(
        &mut repository,
        MeshId::from_bytes([12; 16])?,
        fixture.administrator,
    )?;
    repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context(16, fixture.administrator, 17, 101, Some(1))?,
        &AuthoritativeCommand::CreateVolume(CreateVolume {
            volume_id: fixture.volume,
            name: RecordName::new("Head volume")?,
            root_object_id: ObjectId::from_bytes([18; 16])?,
            owner_set_id: OwnerSetId::from_bytes([19; 16])?,
            owners: BoundedItems::new(vec![fixture.administrator], 1_024)?,
            key_generation: initial_test_volume_key(fixture.volume)?,
        }),
    )?;
    Ok(repository)
}

fn head_bootstrap(
    fixture: &HeadFixture,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let recovery_key = WrappingPublicKey::from_bytes([146; 32])?;
    let certificate = vec![221; 64];
    Ok(AuthoritativeCommand::BootstrapAppliance(
        BootstrapAppliance {
            mesh: BootstrapMesh {
                mesh_id: MeshId::from_bytes([12; 16])?,
                mesh_name: RecordName::new("Head proof mesh")?,
                administrator_id: fixture.administrator,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([13; 16])?,
                host_id: HostId::from_bytes([14; 16])?,
                host_name: RecordName::new("Head host")?,
                node_id: NodeId::from_bytes([15; 16])?,
                node_name: RecordName::new("Head node")?,
                partition_name: RecordName::new("Head authority")?,
            },
            authentication: CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([222; 16])?,
                principal_id: fixture.administrator,
                label: "Initial API key".to_owned(),
                service_scope: 7,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([223; 16])?,
                    key_digest: [224; 32],
                    scopes: 1,
                    valid_from: UnixMicros::new(100),
                },
            },
            recovery: Box::new(BootstrapRecoveryIdentity {
                public_wrapping_key: recovery_key.as_bytes(),
                key_fingerprint: recovery_key.fingerprint(),
                root_certificate_digest: Sha256::digest(&certificate).into(),
                root_certificate_der: certificate,
                bundle_digest: [225; 32],
                save_challenge_commitment: [226; 32],
            }),
        },
    ))
}

pub(super) fn publication_command(
    fixture: &HeadFixture,
    expected: Option<NamespaceCommitId>,
    commit_byte: u8,
    root_byte: u8,
    operation_byte: u8,
    request_byte: u8,
    result_byte: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::CommitConvergedVolumeHead(
        CommitConvergedVolumeHead {
            volume_id: fixture.volume,
            expected_namespace_commit_id: expected,
            namespace_commit_id: commit(commit_byte)?,
            root_object_revision_id: object_revision(root_byte)?,
            evidence: ConvergedHeadEvidence::Publication {
                operation_id: OperationId::from_bytes([operation_byte; 16])?,
                request_digest: [request_byte; 32],
                result_digest: [result_byte; 32],
            },
        },
    ))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the test names each independently bound reconciliation field"
)]
fn reconciliation_command(
    fixture: &HeadFixture,
    expected: NamespaceCommitId,
    commit_byte: u8,
    root_byte: u8,
    operation_byte: u8,
    request_byte: u8,
    causal_byte: u8,
    replay_byte: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let operation_id = OperationId::from_bytes([operation_byte; 16])?;
    let namespace_commit_id = commit(commit_byte)?;
    let root_object_revision_id = object_revision(root_byte)?;
    let request_digest = [request_byte; 32];
    let causal_plan_digest = [causal_byte; 32];
    let replay_plan_digest = [replay_byte; 32];
    Ok(AuthoritativeCommand::CommitConvergedVolumeHead(
        CommitConvergedVolumeHead {
            volume_id: fixture.volume,
            expected_namespace_commit_id: Some(expected),
            namespace_commit_id,
            root_object_revision_id,
            evidence: ConvergedHeadEvidence::Reconciliation {
                operation_id,
                request_digest,
                causal_plan_digest,
                replay_plan_digest,
                result_digest: namespace_reconciliation_result_digest(
                    operation_id,
                    namespace_commit_id,
                    request_digest,
                    causal_plan_digest,
                    replay_plan_digest,
                    root_object_revision_id,
                ),
            },
        },
    ))
}

pub(super) fn context(
    operation_byte: u8,
    administrator: PrincipalId,
    audit_byte: u8,
    occurred_at: i64,
    expected_revision: Option<u64>,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation_byte; 16])?,
        actor_principal_id: administrator,
        audit_event_id: AuditEventId::from_bytes([audit_byte; 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision: expected_revision.map(Revision::new),
    })
}

pub(super) fn fixture() -> Result<HeadFixture, meshspan_domain::IdentifierError> {
    Ok(HeadFixture {
        administrator: PrincipalId::from_bytes([2; 16])?,
        partition: PartitionId::from_bytes([1; 16])?,
        volume: VolumeId::from_bytes([3; 16])?,
    })
}

pub(super) fn commit(value: u8) -> Result<NamespaceCommitId, meshspan_domain::IdentifierError> {
    NamespaceCommitId::from_bytes([value; 16])
}

pub(super) fn object_revision(
    value: u8,
) -> Result<ObjectRevisionId, meshspan_domain::IdentifierError> {
    ObjectRevisionId::from_bytes([value; 16])
}
