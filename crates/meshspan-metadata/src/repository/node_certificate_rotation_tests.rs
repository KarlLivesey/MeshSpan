// SPDX-License-Identifier: GPL-2.0-only

use meshspan_certificates::{
    CertificateAuthority, NodeCertificateRequest, NodeIdentityKey, NodePublicIdentity,
};
use meshspan_domain::{
    AuditEventId, NodeId, OperationId, PartitionId, PrincipalId, Revision, UnixMicros,
};
use rusqlite::params;
use sha2::{Digest as _, Sha256};

use super::{
    ApplyDisposition, AuthoritativeRepository, LogPosition, NodeCertificateRotationState,
    tests::bootstrap_snapshot_repository,
};
use crate::{
    AcknowledgeNodeCertificateInstallation, AuthoritativeCommand, CommandContext,
    PartitionDatabase, RetireNodeCertificate, StageNodeCertificate, decode_authoritative_command,
    encode_authoritative_command,
};

const NOW: i64 = 1_800_000_000_000_000;

struct RenewalFixture {
    directory: tempfile::TempDir,
    repository: AuthoritativeRepository,
    identity: NodeIdentityKey,
    authority: meshspan_certificates::OnlineCertificateAuthority,
    stage: StageNodeCertificate,
    administrator: PrincipalId,
    partition: PartitionId,
}

impl RenewalFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let partition = PartitionId::from_bytes([11; 16])?;
        let node = NodeId::from_bytes([12; 16])?;
        let administrator = PrincipalId::from_bytes([13; 16])?;
        let database = PartitionDatabase::open(
            &directory.path().join("authority.sqlite3"),
            partition,
            UnixMicros::new(NOW),
        )?;
        let mut repository = AuthoritativeRepository::new(database);
        bootstrap_snapshot_repository(&mut repository, administrator, node)?;
        let identity = NodeIdentityKey::generate()?;
        let public = NodePublicIdentity::from_sec1(identity.public_key_sec1())?;
        let authority = CertificateAuthority::new()?.issue_online_authority()?;
        let name = format!(
            "node-{}.meshspan.internal",
            node.to_string().replace('-', "")
        );
        let previous = authority.sign_node_public_identity(&public, &name)?;
        let database = repository.into_database();
        database.connection().execute(
            "UPDATE nodes SET state = 2 WHERE node_id = ?1",
            [node.as_bytes().as_slice()],
        )?;
        database.connection().execute(
            "INSERT INTO online_certificate_authorities(mesh_id, generation, certificate_der,
                certificate_digest, state, created_at, revision) VALUES (?1, 1, ?2, ?3, 1, ?4, 1)",
            params![
                [106_u8; 16].as_slice(),
                authority.certificate_der(),
                Sha256::digest(authority.certificate_der()).as_slice(),
                NOW
            ],
        )?;
        database.connection().execute(
            "INSERT INTO node_certificates(node_id, generation, certificate_der, certificate_fingerprint,
                valid_from, valid_until, state, revision) VALUES (?1, 1, ?2, ?3, ?4, ?5, 1, 1)",
            params![node.as_bytes().as_slice(), &previous, Sha256::digest(&previous).as_slice(),
                NOW - 86_400_000_000, NOW + 86_400_000_000],
        )?;
        let request = NodeCertificateRequest {
            dns_name: &name,
            generation: 2,
            not_before: NOW / 1_000_000,
            not_after: NOW / 1_000_000 + 30 * 86_400,
        };
        let stage = StageNodeCertificate {
            node_id: node,
            incarnation: 1,
            previous_generation: 1,
            generation: 2,
            issuer_generation: 1,
            certificate_der: authority.renew_node_certificate(&public, request)?,
            valid_from: UnixMicros::new(NOW),
            valid_until: UnixMicros::new(NOW + 30 * 86_400_000_000),
        };
        Ok(Self {
            directory,
            repository: AuthoritativeRepository::new(database),
            identity,
            authority,
            stage,
            administrator,
            partition,
        })
    }

    fn context(&self, id: u8, now: i64) -> Result<CommandContext, Box<dyn std::error::Error>> {
        Ok(CommandContext {
            operation_id: OperationId::from_bytes([id; 16])?,
            actor_principal_id: self.administrator,
            audit_event_id: AuditEventId::from_bytes([id + 32; 16])?,
            occurred_at: UnixMicros::new(now),
            expected_revision: None,
        })
    }

    fn acknowledgement(
        &self,
        generation: u64,
        revision: Revision,
        der: &[u8],
    ) -> Result<AcknowledgeNodeCertificateInstallation, Box<dyn std::error::Error>> {
        let mut value = AcknowledgeNodeCertificateInstallation {
            node_id: self.stage.node_id,
            incarnation: 1,
            generation,
            staged_revision: revision,
            certificate_fingerprint: Sha256::digest(der).into(),
            signature: Vec::new(),
        };
        value.signature = self
            .identity
            .sign_enrolment_transcript(&value.signing_transcript())?;
        Ok(value)
    }
}

#[test]
fn renewal_staging_replays_and_reopens_without_selecting_the_new_leaf()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RenewalFixture::new()?;
    let node = fixture.stage.node_id;
    let context = fixture.context(1, NOW)?;
    let command = AuthoritativeCommand::StageNodeCertificate(fixture.stage.clone());
    let encoded = encode_authoritative_command(context, &command)?;
    assert_eq!(decode_authoritative_command(&encoded)?.command, command);
    let receipt =
        fixture
            .repository
            .apply_committed(LogPosition { index: 2, term: 1 }, context, &command)?;
    let replay =
        fixture
            .repository
            .apply_committed(LogPosition { index: 3, term: 1 }, context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(receipt.result_digest, replay.result_digest);
    assert_eq!(
        fixture
            .repository
            .active_node_certificate(node)?
            .ok_or("missing current")?
            .generation,
        1
    );
    let staged = fixture
        .repository
        .node_certificate_rotation(node)?
        .ok_or("missing stage")?;
    assert_eq!(staged.state, NodeCertificateRotationState::Staged);
    assert_eq!(staged.staged_revision, Revision::new(2));
    drop(fixture.repository);
    let reopened = AuthoritativeRepository::new(PartitionDatabase::open(
        &fixture.directory.path().join("authority.sqlite3"),
        fixture.partition,
        UnixMicros::new(NOW + 1_000_000),
    )?);
    assert_eq!(reopened.node_certificate_rotation(node)?, Some(staged));
    assert_eq!(
        reopened
            .active_node_certificate(node)?
            .ok_or("missing previous leaf")?
            .generation,
        1
    );
    Ok(())
}

#[test]
fn renewal_requires_the_owners_signature_and_waits_for_retirement_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RenewalFixture::new()?;
    let node = fixture.stage.node_id;
    let context = fixture.context(1, NOW)?;
    fixture.repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        context,
        &AuthoritativeCommand::StageNodeCertificate(fixture.stage.clone()),
    )?;
    let acknowledgement = AcknowledgeNodeCertificateInstallation {
        node_id: node,
        incarnation: 1,
        generation: 2,
        certificate_fingerprint: Sha256::digest(&fixture.stage.certificate_der).into(),
        staged_revision: Revision::new(2),
        signature: vec![0; 64],
    };
    let ack_context = fixture.context(2, NOW + 1_000_000)?;
    assert!(
        fixture
            .repository
            .apply_committed(
                LogPosition { index: 3, term: 1 },
                ack_context,
                &AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(
                    acknowledgement.clone()
                )
            )
            .is_err()
    );
    let acknowledgement =
        fixture.acknowledgement(2, Revision::new(2), &fixture.stage.certificate_der)?;
    drop(fixture.repository);
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &fixture.directory.path().join("authority.sqlite3"),
        fixture.partition,
        UnixMicros::new(NOW + 1_000_000),
    )?);
    assert_eq!(
        fixture
            .repository
            .node_certificate_rotation(node)?
            .ok_or("missing stage")?
            .state,
        NodeCertificateRotationState::Staged
    );
    let ack = AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(acknowledgement);
    assert_eq!(
        decode_authoritative_command(&encode_authoritative_command(ack_context, &ack)?)?.command,
        ack
    );
    fixture
        .repository
        .apply_committed(LogPosition { index: 3, term: 1 }, ack_context, &ack)?;
    let active = fixture
        .repository
        .active_node_certificate(node)?
        .ok_or("missing installed")?;
    assert_eq!(active.generation, 2);
    assert_eq!(active.certificate_der, fixture.stage.certificate_der);
    let installed = fixture
        .repository
        .node_certificate_rotation(node)?
        .ok_or("missing installed")?;
    assert_eq!(installed.state, NodeCertificateRotationState::Installed);
    let retire_at = installed.retire_after.ok_or("missing overlap")?.get();
    assert_eq!(retire_at, NOW + 3_601_000_000);
    let retirement = AuthoritativeCommand::RetireNodeCertificate(RetireNodeCertificate {
        node_id: node,
        incarnation: 1,
        generation: 2,
    });
    let early = fixture.context(3, retire_at - 1)?;
    assert!(
        fixture
            .repository
            .apply_committed(LogPosition { index: 4, term: 1 }, early, &retirement)
            .is_err()
    );
    let due = fixture.context(3, retire_at)?;
    fixture
        .repository
        .apply_committed(LogPosition { index: 4, term: 1 }, due, &retirement)?;
    assert_eq!(
        fixture
            .repository
            .node_certificate_rotation(node)?
            .ok_or("missing retired")?
            .state,
        NodeCertificateRotationState::Retired
    );
    let database = fixture.repository.into_database();
    let states = database
        .connection()
        .prepare("SELECT state FROM node_certificates ORDER BY generation")?
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(states, [3, 1]);
    Ok(())
}

#[test]
fn renewal_rejects_stale_identity_and_substituted_generation_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RenewalFixture::new()?;
    let original = fixture.stage.clone();
    for invalid in [
        StageNodeCertificate {
            incarnation: 2,
            ..original.clone()
        },
        StageNodeCertificate {
            previous_generation: 2,
            ..original.clone()
        },
        StageNodeCertificate {
            issuer_generation: 2,
            ..original.clone()
        },
        StageNodeCertificate {
            certificate_der: vec![0x30; 64],
            ..original.clone()
        },
        StageNodeCertificate {
            valid_until: UnixMicros::new(original.valid_until.get() - 1),
            ..original
        },
    ] {
        let context = fixture.context(1, NOW)?;
        assert!(
            fixture
                .repository
                .apply_committed(
                    LogPosition { index: 2, term: 1 },
                    context,
                    &AuthoritativeCommand::StageNodeCertificate(invalid)
                )
                .is_err()
        );
        assert!(
            fixture
                .repository
                .node_certificate_rotation(fixture.stage.node_id)?
                .is_none()
        );
        assert_eq!(fixture.repository.current_revision()?, Revision::new(1));
    }
    Ok(())
}

#[test]
fn expired_uninstalled_candidate_can_be_replaced_without_losing_the_active_generation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RenewalFixture::new()?;
    let node = fixture.stage.node_id;
    let staged_context = fixture.context(1, NOW)?;
    fixture.repository.apply_committed(
        LogPosition { index: 2, term: 1 },
        staged_context,
        &AuthoritativeCommand::StageNodeCertificate(fixture.stage.clone()),
    )?;
    let retirement = AuthoritativeCommand::RetireNodeCertificate(RetireNodeCertificate {
        node_id: node,
        incarnation: 1,
        generation: 2,
    });
    let expires = fixture.stage.valid_until.get();
    let early = fixture.context(2, expires - 1)?;
    assert!(
        fixture
            .repository
            .apply_committed(LogPosition { index: 3, term: 1 }, early, &retirement)
            .is_err()
    );
    let due = fixture.context(2, expires)?;
    fixture
        .repository
        .apply_committed(LogPosition { index: 3, term: 1 }, due, &retirement)?;
    assert_eq!(
        fixture
            .repository
            .node_certificate_rotation(node)?
            .ok_or("missing rotation")?
            .state,
        NodeCertificateRotationState::Abandoned
    );
    assert_eq!(
        fixture
            .repository
            .active_node_certificate(node)?
            .ok_or("missing previous leaf")?
            .generation,
        1
    );
    let public = NodePublicIdentity::from_sec1(fixture.identity.public_key_sec1())?;
    let name = format!(
        "node-{}.meshspan.internal",
        node.to_string().replace('-', "")
    );
    let der = fixture.authority.renew_node_certificate(
        &public,
        NodeCertificateRequest {
            dns_name: &name,
            generation: 3,
            not_before: expires / 1_000_000,
            not_after: expires / 1_000_000 + 30 * 86_400,
        },
    )?;
    let next = StageNodeCertificate {
        generation: 3,
        certificate_der: der.clone(),
        valid_from: UnixMicros::new(expires),
        valid_until: UnixMicros::new(expires + 30 * 86_400_000_000),
        ..fixture.stage.clone()
    };
    let next_context = fixture.context(3, expires)?;
    fixture.repository.apply_committed(
        LogPosition { index: 4, term: 1 },
        next_context,
        &AuthoritativeCommand::StageNodeCertificate(next),
    )?;
    let acknowledgement = fixture.acknowledgement(3, Revision::new(4), &der)?;
    let installed_context = fixture.context(4, expires + 1_000_000)?;
    fixture.repository.apply_committed(
        LogPosition { index: 5, term: 1 },
        installed_context,
        &AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(acknowledgement),
    )?;
    let installed = fixture
        .repository
        .node_certificate_rotation(node)?
        .ok_or("missing generation three")?;
    let retire_context =
        fixture.context(5, installed.retire_after.ok_or("missing deadline")?.get())?;
    fixture.repository.apply_committed(
        LogPosition { index: 6, term: 1 },
        retire_context,
        &AuthoritativeCommand::RetireNodeCertificate(RetireNodeCertificate {
            node_id: node,
            incarnation: 1,
            generation: 3,
        }),
    )?;
    let database = fixture.repository.into_database();
    let states = database
        .connection()
        .prepare("SELECT state FROM node_certificates ORDER BY generation")?
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(states, [3, 3, 1]);
    Ok(())
}
