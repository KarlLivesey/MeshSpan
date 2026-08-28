// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::{Signer, SigningKey};
use meshspan_domain::{HostId, JoinGrantId, NodeId, OperationId, Revision, UnixMicros};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::reachability::retained_root_summary;
use super::version_cleanup_tests::{cleanup_command, terminal_digest};
use super::volume_head_tests::{context, fixture, open_and_prepare, publication_command};
use super::{ApplyDisposition, EntityKind, LogPosition, RepositoryError};
use crate::{
    AttestVersionCleanup, AuthoritativeCommand, ConsumeJoinGrant, IssueJoinGrant, JoinRoles,
    PartitionDatabase, RecordName, RegisterCleanupAttestationKey, VersionCleanupAttestation,
};

const NODE_IDENTITY: u8 = 15;
const SIGNING_KEY: [u8; 32] = [91; 32];

struct ProposalFixture {
    repository: super::AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    partition: meshspan_domain::PartitionId,
    cleanup_id: OperationId,
    scan_request_digest: [u8; 32],
    subject_digest: [u8; 32],
}

#[test]
fn exact_node_attestation_is_replayable_complete_and_restart_safe()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("attestation.sqlite3");
    let ProposalFixture {
        mut repository,
        administrator,
        partition,
        cleanup_id,
        scan_request_digest: _,
        subject_digest,
    } = proposal(&file_path)?;
    register_key(&mut repository, administrator, 5, 1, SIGNING_KEY)?;

    let command = signed_attestation(cleanup_id, Revision::new(4), [90; 32], subject_digest, 60)?;
    let command_context = context(61, administrator, 62, 106, Some(5))?;
    let receipt =
        repository.apply_committed(LogPosition { index: 6, term: 1 }, command_context, &command)?;
    assert_eq!(receipt.entity.kind, EntityKind::VersionCleanup);
    assert_eq!(receipt.entity.id, cleanup_id.as_bytes());
    let progress = repository
        .version_cleanup_attestation_progress(cleanup_id)?
        .ok_or("missing attestation progress")?;
    assert_eq!(progress.required, 1);
    assert_eq!(progress.attested, 1);
    assert!(progress.complete());

    let replay =
        repository.apply_committed(LogPosition { index: 7, term: 1 }, command_context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);
    drop(repository);

    let reopened = PartitionDatabase::open(&file_path, partition, UnixMicros::new(500))?;
    let repository = super::AuthoritativeRepository::new(reopened);
    assert!(
        repository
            .version_cleanup_attestation_progress(cleanup_id)?
            .ok_or("attestation progress did not survive restart")?
            .complete()
    );
    Ok(())
}

#[test]
fn forged_stale_or_wrong_incarnation_attestations_do_not_advance()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("reject.sqlite3");
    let ProposalFixture {
        mut repository,
        administrator,
        cleanup_id,
        scan_request_digest,
        subject_digest,
        ..
    } = proposal(&file_path)?;
    register_key(&mut repository, administrator, 5, 1, SIGNING_KEY)?;
    let valid = signed_attestation(
        cleanup_id,
        Revision::new(4),
        scan_request_digest,
        subject_digest,
        70,
    )?;
    let AuthoritativeCommand::AttestVersionCleanup(valid_value) = valid else {
        return Err("wrong attestation fixture".into());
    };
    let command_context = context(71, administrator, 72, 107, Some(5))?;

    let mut forged_signature = valid_value;
    forged_signature.attestation.signature[0] ^= 1;
    reject_without_advancing(&mut repository, command_context, &forged_signature)?;

    let mut wrong_incarnation = valid_value;
    wrong_incarnation.attestation.node_incarnation = 2;
    resign(&mut wrong_incarnation.attestation, SIGNING_KEY);
    reject_without_advancing(&mut repository, command_context, &wrong_incarnation)?;

    let mut forged_result = valid_value;
    forged_result.attestation.scan_result_digest[0] ^= 1;
    resign(&mut forged_result.attestation, SIGNING_KEY);
    reject_without_advancing(&mut repository, command_context, &forged_result)?;
    assert_eq!(repository.current_revision()?, Revision::new(5));
    assert_eq!(
        repository
            .version_cleanup_attestation_progress(cleanup_id)?
            .ok_or("missing progress")?
            .attested,
        0
    );
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_the_complete_attestation() -> Result<(), Box<dyn std::error::Error>>
{
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        let directory = tempdir()?;
        let file_path = directory.path().join("fault.sqlite3");
        let ProposalFixture {
            mut repository,
            administrator,
            cleanup_id,
            scan_request_digest,
            subject_digest,
            ..
        } = proposal(&file_path)?;
        register_key(&mut repository, administrator, 5, 1, SIGNING_KEY)?;
        let command = signed_attestation(
            cleanup_id,
            Revision::new(4),
            scan_request_digest,
            subject_digest,
            80,
        )?;
        let command_context = context(81, administrator, 82, 108, Some(5))?;
        assert!(matches!(
            apply_committed_with_fault(
                &mut repository.database,
                LogPosition { index: 6, term: 1 },
                command_context,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert_eq!(repository.current_revision()?, Revision::new(5));
        assert_eq!(
            repository
                .version_cleanup_attestation_progress(cleanup_id)?
                .ok_or("missing progress")?
                .attested,
            0
        );
        repository.apply_committed(LogPosition { index: 6, term: 1 }, command_context, &command)?;
        assert!(
            repository
                .version_cleanup_attestation_progress(cleanup_id)?
                .ok_or("missing retried progress")?
                .complete()
        );
    }
    Ok(())
}

#[test]
fn every_snapshotted_gateway_must_attest_before_coverage_is_complete()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let fixture = fixture()?;
    let mut repository = open_and_prepare(&directory.path().join("coverage.sqlite3"), &fixture)?;
    let second_node = enrol_second_gateway(&mut repository, fixture.administrator)?;
    repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        context(30, fixture.administrator, 31, 102, Some(4))?,
        &publication_command(&fixture, None, 32, 33, 34, 35, 36)?,
    )?;
    let root_summary = retained_root_summary(
        repository.database.connection(),
        fixture.volume,
        Revision::new(5),
    )?;
    let AuthoritativeCommand::ProposeVersionCleanup(mut proposal) =
        cleanup_command(fixture.volume, root_summary, 40)?
    else {
        return Err("wrong proposal fixture".into());
    };
    proposal.reachability_revision = Revision::new(5);
    proposal.proof_result_digest = terminal_digest(&proposal);
    let cleanup_context = context(41, fixture.administrator, 42, 103, Some(5))?;
    repository.apply_committed(
        LogPosition { index: 6, term: 1 },
        cleanup_context,
        &AuthoritativeCommand::ProposeVersionCleanup(proposal),
    )?;
    let cleanup_id = cleanup_context.operation_id;
    assert_eq!(progress(&repository, cleanup_id)?, (2, 0, false));

    let first_key = [91; 32];
    let second_key = [92; 32];
    register_node_key(
        &mut repository,
        fixture.administrator,
        7,
        NodeId::from_bytes([NODE_IDENTITY; 16])?,
        first_key,
    )?;
    register_node_key(
        &mut repository,
        fixture.administrator,
        8,
        second_node,
        second_key,
    )?;
    let first = signed_attestation_for(
        cleanup_id,
        Revision::new(6),
        [120; 32],
        proposal.reachability_subject_digest,
        121,
        NodeId::from_bytes([NODE_IDENTITY; 16])?,
        first_key,
    )?;
    repository.apply_committed(
        LogPosition { index: 9, term: 1 },
        context(122, fixture.administrator, 123, 110, Some(8))?,
        &first,
    )?;
    assert_eq!(progress(&repository, cleanup_id)?, (2, 1, false));

    let second = signed_attestation_for(
        cleanup_id,
        Revision::new(6),
        [124; 32],
        proposal.reachability_subject_digest,
        125,
        second_node,
        second_key,
    )?;
    repository.apply_committed(
        LogPosition { index: 10, term: 1 },
        context(126, fixture.administrator, 127, 111, Some(9))?,
        &second,
    )?;
    assert_eq!(progress(&repository, cleanup_id)?, (2, 2, true));
    Ok(())
}

fn enrol_second_gateway(
    repository: &mut super::AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
) -> Result<NodeId, Box<dyn std::error::Error>> {
    let grant_id = JoinGrantId::from_bytes([90; 16])?;
    let secret_digest = [91; 32];
    let roles = JoinRoles::new(JoinRoles::GATEWAY)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(92, administrator, 93, 100, Some(2))?,
        &AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
            join_grant_id: grant_id,
            secret_digest,
            allowed_roles: roles,
            maximum_uses: 1,
            expires_at: UnixMicros::new(1_000),
        }),
    )?;
    let certificate_der = b"second gateway certificate".to_vec();
    let certificate_fingerprint = Sha256::digest(&certificate_der).into();
    let node_id = NodeId::from_bytes([94; 16])?;
    repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        context(95, administrator, 96, 101, Some(3))?,
        &AuthoritativeCommand::ConsumeJoinGrant(ConsumeJoinGrant {
            join_grant_id: grant_id,
            secret_digest,
            host_id: HostId::from_bytes([97; 16])?,
            new_host_name: Some(RecordName::new("Second gateway host")?),
            node_id,
            node_name: RecordName::new("Second gateway")?,
            incarnation: 1,
            requested_roles: roles,
            certificate_der,
            certificate_fingerprint,
            certificate_valid_until: UnixMicros::new(10_000),
        }),
    )?;
    Ok(node_id)
}

fn progress(
    repository: &super::AuthoritativeRepository,
    cleanup_id: OperationId,
) -> Result<(u64, u64, bool), Box<dyn std::error::Error>> {
    let progress = repository
        .version_cleanup_attestation_progress(cleanup_id)?
        .ok_or("missing cleanup progress")?;
    Ok((progress.required, progress.attested, progress.complete()))
}

fn proposal(file_path: &std::path::Path) -> Result<ProposalFixture, Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let mut repository = open_and_prepare(file_path, &fixture)?;
    repository.apply_committed(
        LogPosition { index: 3, term: 1 },
        context(30, fixture.administrator, 31, 102, Some(2))?,
        &publication_command(&fixture, None, 32, 33, 34, 35, 36)?,
    )?;
    let root_summary = retained_root_summary(
        repository.database.connection(),
        fixture.volume,
        Revision::new(3),
    )?;
    let command = cleanup_command(fixture.volume, root_summary, 40)?;
    let AuthoritativeCommand::ProposeVersionCleanup(proposal) = command else {
        return Err("wrong proposal fixture".into());
    };
    let command = AuthoritativeCommand::ProposeVersionCleanup(proposal);
    let command_context = context(41, fixture.administrator, 42, 103, Some(3))?;
    repository.apply_committed(LogPosition { index: 4, term: 1 }, command_context, &command)?;
    Ok(ProposalFixture {
        repository,
        administrator: fixture.administrator,
        partition: fixture.partition,
        cleanup_id: command_context.operation_id,
        scan_request_digest: proposal.scan_request_digest,
        subject_digest: proposal.reachability_subject_digest,
    })
}

fn register_key(
    repository: &mut super::AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    index: u64,
    generation: u64,
    key: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    register_node_key_generation(
        repository,
        administrator,
        index,
        NodeId::from_bytes([NODE_IDENTITY; 16])?,
        generation,
        key,
    )
}

fn register_node_key(
    repository: &mut super::AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    index: u64,
    node_id: NodeId,
    key: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    register_node_key_generation(repository, administrator, index, node_id, 1, key)
}

fn register_node_key_generation(
    repository: &mut super::AuthoritativeRepository,
    administrator: meshspan_domain::PrincipalId,
    index: u64,
    node_id: NodeId,
    generation: u64,
    key: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_bytes(&key);
    let operation = u8::try_from(index + 50)?;
    let audit = u8::try_from(index + 80)?;
    repository.apply_committed(
        LogPosition { index, term: 1 },
        context(operation, administrator, audit, 104, Some(index - 1))?,
        &AuthoritativeCommand::RegisterCleanupAttestationKey(RegisterCleanupAttestationKey {
            node_id,
            generation,
            verifying_key: signing_key.verifying_key().to_bytes(),
        }),
    )?;
    Ok(())
}

fn signed_attestation(
    cleanup_operation_id: OperationId,
    cleanup_revision: Revision,
    scan_request_digest: [u8; 32],
    reachability_subject_digest: [u8; 32],
    identity: u8,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    signed_attestation_for(
        cleanup_operation_id,
        cleanup_revision,
        scan_request_digest,
        reachability_subject_digest,
        identity,
        NodeId::from_bytes([NODE_IDENTITY; 16])?,
        SIGNING_KEY,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the helper names each independently signed attestation field"
)]
fn signed_attestation_for(
    cleanup_operation_id: OperationId,
    cleanup_revision: Revision,
    scan_request_digest: [u8; 32],
    reachability_subject_digest: [u8; 32],
    identity: u8,
    node_id: NodeId,
    signing_key: [u8; 32],
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let scan_operation_id = OperationId::from_bytes([identity; 16])?;
    let local_roots_digest = [identity.saturating_add(1); 32];
    let mut result = blake3::Hasher::new();
    result.update(b"meshspan.version-reachability-result.v1\0");
    result.update(&scan_operation_id.as_bytes());
    result.update(&scan_request_digest);
    result.update(&local_roots_digest);
    result.update(&[4]);
    let mut attestation = VersionCleanupAttestation {
        cleanup_operation_id,
        cleanup_revision,
        node_id,
        node_incarnation: 1,
        key_generation: 1,
        scan_operation_id,
        scan_request_digest,
        reachability_subject_digest,
        local_roots_digest,
        scan_result_digest: result.finalize().into(),
        signature: [0; 64],
    };
    resign(&mut attestation, signing_key);
    Ok(AuthoritativeCommand::AttestVersionCleanup(
        AttestVersionCleanup { attestation },
    ))
}

fn resign(attestation: &mut VersionCleanupAttestation, key: [u8; 32]) {
    attestation.signature = [0; 64];
    attestation.signature = SigningKey::from_bytes(&key)
        .sign(&attestation.signing_digest())
        .to_bytes();
}

fn reject_without_advancing(
    repository: &mut super::AuthoritativeRepository,
    command_context: crate::CommandContext,
    command: &AttestVersionCleanup,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        repository
            .apply_committed(
                LogPosition { index: 6, term: 1 },
                command_context,
                &AuthoritativeCommand::AttestVersionCleanup(*command),
            )
            .is_err()
    );
    assert_eq!(repository.current_revision()?, Revision::new(5));
    Ok(())
}
