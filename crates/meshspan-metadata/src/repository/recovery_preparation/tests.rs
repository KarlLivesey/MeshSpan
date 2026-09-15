// SPDX-License-Identifier: GPL-2.0-only

use std::{collections::BTreeSet, fs, path::Path};

use meshspan_consensus::{CompiledQuorumPlan, DurableMutation, LogEntry, compile_plan, flat_plan};
use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, BackupId, HostId, MeshId, NodeId, OperationId,
    PartitionId, PrincipalId, QuorumPlanId, Revision, RoleId, UnixMicros,
};
use meshspan_recovery_bundle::{
    RecoveredAuthority, RecoveryAuthorization, RecoveryAuthorizationClaims, create_recovery_bundle,
};
use sha2::{Digest as _, Sha256};

use super::prepare_authorized_partition_recovery;
use crate::{
    AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh, BootstrapRecoveryIdentity,
    CommandContext, ConsensusStoreError, CreateAuthenticationMethod, EncryptedBackupPaths,
    EncryptedPartitionBackupManifest, EncryptedRestorePaths, LogPosition,
    NewAuthenticationCredential, PartitionDatabase, RecordName, RepositoryError,
    encode_authoritative_command,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

mod consensus_activation;
mod consensus_permission;
mod fencing;
mod journal;
mod key_installation;
mod key_transfer;
mod keys;
mod node_key_projection;
mod plan;
mod providers;
mod retained;
mod targets;

struct Fixture {
    directory: tempfile::TempDir,
    authority: RecoveredAuthority,
    authorization: RecoveryAuthorization,
    manifest: EncryptedPartitionBackupManifest,
    plan: CompiledQuorumPlan,
}

#[test]
fn public_root_verification_requires_the_exact_prepared_source_state() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.prepare(&fixture.authorization, &fixture.authority)?;
    let database = PartitionDatabase::open_existing(
        &fixture.directory.path().join("prepared.sqlite3"),
        UnixMicros::new(30),
    )?;
    let repository = AuthoritativeRepository::new(database);
    let root = fixture.authority.root_certificate_der();
    assert_eq!(
        repository.verify_recovery_preparation(root)?,
        fixture.authorization
    );
    let other = Fixture::new()?;
    assert!(
        repository
            .verify_recovery_preparation(other.authority.root_certificate_der())
            .is_err()
    );
    let database = repository.into_database();
    database.connection().execute(
        "UPDATE applied_state SET state_revision = state_revision + 1",
        [],
    )?;
    let repository = AuthoritativeRepository::new(database);
    assert!(repository.verify_recovery_preparation(root).is_err());
    Ok(())
}

#[test]
fn exact_recovery_preparation_survives_reopen_but_cannot_start_consensus() -> TestResult {
    let fixture = Fixture::new()?;
    let original = fs::read(fixture.directory.path().join("backup.msb"))?;
    fixture.prepare(&fixture.authorization, &fixture.authority)?;
    let destination = fixture.directory.path().join("prepared.sqlite3");
    let database = PartitionDatabase::open_existing(&destination, UnixMicros::new(30))?;
    database.check_integrity()?;
    let (encoded, epoch): (Vec<u8>, i64) = database.connection().query_row(
        "SELECT authorization, recovery_epoch FROM partition_recovery_preparation",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(epoch, 1);
    assert_eq!(
        RecoveryAuthorization::decode(fixture.authority.root_certificate_der(), &encoded)?,
        fixture.authorization
    );
    let mut repository = AuthoritativeRepository::new(database);
    assert_eq!(repository.current_revision()?, Revision::new(1));
    assert!(matches!(
        repository.load_consensus_state(1),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    assert!(matches!(
        repository.initialise_consensus_quorum_plan(&fixture.plan, UnixMicros::new(31)),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    assert!(matches!(
        repository.persist_consensus_mutation(
            1,
            &DurableMutation {
                vote_state: Some((2, None)),
                truncate_from: None,
                append: vec![],
                membership_epoch: None,
                quorum_plan: None,
            },
            UnixMicros::new(31)
        ),
        Err(ConsensusStoreError::RecoveryAdmissionRequired)
    ));
    let database = repository.into_database();
    assert!(
        database
            .connection()
            .execute("DELETE FROM partition_recovery_preparation", [])
            .is_err()
    );
    assert!(
        database
            .connection()
            .execute(
                "UPDATE partition_recovery_preparation SET recovery_epoch = 2",
                [],
            )
            .is_err()
    );
    assert_eq!(
        fs::read(fixture.directory.path().join("backup.msb"))?,
        original
    );
    assert!(!fixture.directory.path().join("plaintext.sqlite3").exists());
    Ok(())
}

#[test]
fn recovery_preparation_rejects_substituted_source_before_creating_output() -> TestResult {
    let fixture = Fixture::new()?;
    let claims = *fixture.authorization.claims();
    for changed in [
        RecoveryAuthorizationClaims {
            backup_digest: [42; 32],
            ..claims
        },
        RecoveryAuthorizationClaims {
            backup_id: BackupId::from_bytes([43; 16])?,
            ..claims
        },
        RecoveryAuthorizationClaims {
            source_log_index: 2,
            ..claims
        },
        RecoveryAuthorizationClaims {
            source_log_term: 2,
            ..claims
        },
        RecoveryAuthorizationClaims {
            source_revision: Revision::new(2),
            ..claims
        },
        RecoveryAuthorizationClaims {
            previous_epoch: 1,
            recovery_epoch: 2,
            ..claims
        },
    ] {
        let changed = fixture.authority.authorize_recovery(changed)?;
        assert!(matches!(
            fixture.prepare(&changed, &fixture.authority),
            Err(RepositoryError::BackupMismatch)
        ));
        assert!(!fixture.directory.path().join("prepared.sqlite3").exists());
    }
    Ok(())
}

#[test]
fn recovery_preparation_rejects_a_second_root_and_preserves_existing_destinations() -> TestResult {
    let fixture = Fixture::new()?;
    let (bundle, code, _) = create_recovery_bundle(
        fixture.manifest.partition.mesh_id,
        &mut crate::test_support::SequentialRandom(77),
    )?;
    let impostor = bundle.open(&code)?;
    let changed = impostor.authorize_recovery(*fixture.authorization.claims())?;
    assert!(matches!(
        fixture.prepare(&changed, &fixture.authority),
        Err(RepositoryError::InvalidCommand)
    ));
    let destination = fixture.directory.path().join("prepared.sqlite3");
    assert!(!destination.exists());
    fs::write(&destination, b"operator-owned existing file")?;
    let original = fs::read(&destination)?;
    assert!(
        fixture
            .prepare(&fixture.authorization, &fixture.authority)
            .is_err()
    );
    assert_eq!(fs::read(destination)?, original);
    Ok(())
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_source(|_| Ok(()))
    }

    fn with_source(
        prepare: impl FnOnce(&mut AuthoritativeRepository) -> TestResult,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let partition = PartitionId::from_bytes([1; 16])?;
        let mesh = MeshId::from_bytes([5; 16])?;
        let (bundle, code, identity) =
            create_recovery_bundle(mesh, &mut crate::test_support::SequentialRandom(11))?;
        let authority = bundle.open(&code)?;
        let recovery = BootstrapRecoveryIdentity {
            public_wrapping_key: identity.public_wrapping_key().as_bytes(),
            key_fingerprint: identity.public_wrapping_key().fingerprint(),
            root_certificate_der: identity.root_certificate_der().to_vec(),
            root_certificate_digest: Sha256::digest(identity.root_certificate_der()).into(),
            online_authority_certificate_der: identity.root_certificate_der().to_vec(),
            online_authority_certificate_digest: Sha256::digest(identity.root_certificate_der())
                .into(),
            bundle_digest: identity.bundle_digest(),
            save_challenge_commitment: [15; 32],
        };
        let (context, command) = bootstrap(mesh, recovery)?;
        let (mut repository, plan) =
            committed_repository(directory.path(), partition, context, &command)?;
        prepare(&mut repository)?;
        let manifest = repository.create_encrypted_backup(
            EncryptedBackupPaths {
                plaintext_staging: &directory.path().join("copy.sqlite3"),
                encrypted_destination: &directory.path().join("backup.msb"),
            },
            BackupId::from_bytes([21; 16])?,
            UnixMicros::new(15),
            &[authority.public_wrapping_key()],
            &mut crate::test_support::SequentialRandom(31),
        )?;
        let authorization = authority.authorize_recovery(RecoveryAuthorizationClaims {
            mesh_id: mesh,
            partition_id: partition,
            recovery_id: OperationId::from_bytes([22; 16])?,
            backup_id: manifest.partition.backup_id,
            backup_digest: manifest.encrypted.digest,
            source_log_index: 1,
            source_log_term: 1,
            source_revision: Revision::new(1),
            previous_epoch: 0,
            recovery_epoch: 1,
            replacement_manifest_digest: [23; 32],
            target_inventory_digest: [24; 32],
        })?;
        Ok(Self {
            directory,
            authority,
            authorization,
            manifest,
            plan,
        })
    }

    fn prepare(
        &self,
        authorization: &RecoveryAuthorization,
        authority: &RecoveredAuthority,
    ) -> Result<(), RepositoryError> {
        prepare_authorized_partition_recovery(
            EncryptedRestorePaths {
                encrypted_source: &self.directory.path().join("backup.msb"),
                plaintext_staging: &self.directory.path().join("plaintext.sqlite3"),
                restored_destination: &self.directory.path().join("prepared.sqlite3"),
            },
            self.manifest,
            authority,
            authorization,
            UnixMicros::new(20),
        )
    }
}

fn committed_repository(
    directory: &Path,
    partition: PartitionId,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<(AuthoritativeRepository, CompiledQuorumPlan), Box<dyn std::error::Error>> {
    let database = PartitionDatabase::open(
        &directory.join("live.sqlite3"),
        partition,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let voter = NodeId::from_bytes([8; 16])?;
    let plan = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([20; 16])?,
        1,
        BTreeSet::from([voter]),
        BTreeSet::new(),
    )?)?;
    repository.initialise_consensus_quorum_plan(&plan, UnixMicros::new(2))?;
    repository.persist_consensus_mutation(
        1,
        &DurableMutation {
            vote_state: Some((1, Some(voter))),
            truncate_from: None,
            append: vec![LogEntry::new(
                meshspan_consensus::LogPosition { index: 1, term: 1 },
                context.operation_id,
                1,
                encode_authoritative_command(context, command)?,
            )?],
            membership_epoch: None,
            quorum_plan: None,
        },
        UnixMicros::new(3),
    )?;
    repository.apply_committed(LogPosition { index: 1, term: 1 }, context, command)?;
    assert_eq!(repository.load_consensus_state(1)?.applied_index, 1);
    Ok((repository, plan))
}

#[test]
fn recovery_preparation_migration_keeps_ordinary_databases_admissible() -> TestResult {
    verify_ordinary_migration(103)?;
    verify_ordinary_migration(104)?;
    verify_ordinary_migration(105)?;
    verify_ordinary_migration(106)?;
    verify_ordinary_migration(107)?;
    verify_ordinary_migration(108)?;
    verify_ordinary_migration(109)?;
    verify_ordinary_migration(110)?;
    verify_ordinary_migration(111)?;
    verify_ordinary_migration(112)?;
    verify_ordinary_migration(113)?;
    verify_ordinary_migration(114)?;
    verify_ordinary_migration(115)?;
    verify_ordinary_migration(116)?;
    verify_ordinary_migration(117)?;
    verify_ordinary_migration(118)
}

fn verify_ordinary_migration(version: u32) -> TestResult {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join(format!("schema{version}.sqlite3"));
    let mut connection = rusqlite::Connection::open(&source)?;
    crate::migration::migrate_partition_through(&mut connection, usize::try_from(version)?, 10)?;
    connection.execute(
        "INSERT INTO applied_state VALUES (1, ?1, 0, 0, 0, ?2)",
        rusqlite::params![[1_u8; 16].as_slice(), version],
    )?;
    drop(connection);
    let mut database = PartitionDatabase::open_existing(&source, UnixMicros::new(20))?;
    assert_eq!(
        database.schema_version(),
        PartitionDatabase::supported_schema_version()
    );
    assert!(!super::pending(database.connection())?);
    let plan = compile_plan(flat_plan(
        QuorumPlanId::from_bytes([20; 16])?,
        1,
        BTreeSet::from([NodeId::from_bytes([8; 16])?]),
        BTreeSet::new(),
    )?)?;
    super::super::quorum_plan::initialise(&mut database, &plan, UnixMicros::new(21))?;
    assert_eq!(
        super::super::consensus::load_state(&database, 1)?.applied_index,
        0
    );
    Ok(())
}

fn bootstrap(
    mesh: MeshId,
    recovery: BootstrapRecoveryIdentity,
) -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let context = CommandContext {
        operation_id: OperationId::from_bytes([3; 16])?,
        actor_principal_id: administrator,
        audit_event_id: AuditEventId::from_bytes([4; 16])?,
        occurred_at: UnixMicros::new(10),
        expected_revision: Some(Revision::ZERO),
    };
    let command = crate::test_support::bootstrap_appliance(
        BootstrapMesh {
            mesh_id: mesh,
            mesh_name: RecordName::new("Recovered mesh")?,
            administrator_id: administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([6; 16])?,
            host_id: HostId::from_bytes([7; 16])?,
            host_name: RecordName::new("Host")?,
            node_id: NodeId::from_bytes([8; 16])?,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root")?,
        },
        CreateAuthenticationMethod {
            method_id: AuthenticationMethodId::from_bytes([9; 16])?,
            principal_id: administrator,
            label: "Initial API key".to_owned(),
            service_scope: 7,
            expires_at: None,
            credential: NewAuthenticationCredential::ApiKey {
                key_id: ApiKeyId::from_bytes([10; 16])?,
                key_digest: [11; 32],
                smb_verifier_ciphertext: Some(vec![12; 65]),
                scopes: 7,
                valid_from: UnixMicros::new(10),
            },
        },
        Box::new(recovery),
    )?;
    Ok((
        context,
        AuthoritativeCommand::BootstrapAppliance(Box::new(command)),
    ))
}
