// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, HostId, MeshId, NodeId, OperationId,
    PartitionId, PrincipalId, Revision, RoleId, UnixMicros,
};
use meshspan_secret_envelope::WrappingPublicKey;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::apply::{ApplyFaultPoint, apply_committed_with_fault};
use super::{ApplyDisposition, AuthoritativeRepository, LogPosition, RepositoryError};
use crate::{
    AuthoritativeCommand, BootstrapAppliance, BootstrapMesh, BootstrapRecoveryIdentity,
    CommandContext, CreateAuthenticationMethod, NewAuthenticationCredential, PartitionDatabase,
    RecordName,
};

#[test]
fn first_mesh_and_login_method_commit_and_replay_as_one_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(
        &directory.path().join("authority.sqlite3"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let mut repository = AuthoritativeRepository::new(database);
    let (context, command) = fixture(partition_id)?;
    let receipt =
        repository.apply_committed(LogPosition { index: 1, term: 1 }, context, &command)?;
    assert_eq!(receipt.disposition, ApplyDisposition::Applied);
    let replay =
        repository.apply_committed(LogPosition { index: 2, term: 1 }, context, &command)?;
    assert_eq!(replay.disposition, ApplyDisposition::Replayed);
    assert_eq!(replay.result_digest, receipt.result_digest);

    let database = repository.into_database();
    assert_eq!(count(database.connection(), "meshes")?, 1);
    assert_eq!(count(database.connection(), "users")?, 1);
    assert_eq!(count(database.connection(), "authentication_methods")?, 1);
    assert_eq!(count(database.connection(), "api_keys")?, 1);
    assert_eq!(count(database.connection(), "operations")?, 1);
    Ok(())
}

#[test]
fn every_apply_fault_rolls_back_mesh_and_login_method_together()
-> Result<(), Box<dyn std::error::Error>> {
    for (number, fault) in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ]
    .into_iter()
    .enumerate()
    {
        let directory = tempdir()?;
        let partition_id = PartitionId::from_bytes([u8::try_from(number + 1)?; 16])?;
        let mut database = PartitionDatabase::open(
            &directory.path().join("authority.sqlite3"),
            partition_id,
            UnixMicros::new(1),
        )?;
        let (context, command) = fixture(partition_id)?;
        assert!(matches!(
            apply_committed_with_fault(
                &mut database,
                LogPosition { index: 1, term: 1 },
                context,
                &command,
                fault,
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert_eq!(count(database.connection(), "meshes")?, 0);
        assert_eq!(count(database.connection(), "principals")?, 0);
        assert_eq!(count(database.connection(), "authentication_methods")?, 0);
        assert_eq!(count(database.connection(), "api_keys")?, 0);
        assert_eq!(count(database.connection(), "operations")?, 0);
    }
    Ok(())
}

fn fixture(
    partition_id: PartitionId,
) -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
    let administrator = PrincipalId::from_bytes([2; 16])?;
    Ok((
        CommandContext {
            operation_id: OperationId::from_bytes([3; 16])?,
            actor_principal_id: administrator,
            audit_event_id: AuditEventId::from_bytes([4; 16])?,
            occurred_at: UnixMicros::new(10),
            expected_revision: Some(Revision::ZERO),
        },
        AuthoritativeCommand::BootstrapAppliance(BootstrapAppliance {
            mesh: BootstrapMesh {
                mesh_id: MeshId::from_bytes([5; 16])?,
                mesh_name: RecordName::new("First mesh")?,
                administrator_id: administrator,
                administrator_name: RecordName::new("First administrator")?,
                administrator_role_id: RoleId::from_bytes([6; 16])?,
                host_id: HostId::from_bytes([7; 16])?,
                host_name: RecordName::new("First host")?,
                node_id: NodeId::from_bytes([8; 16])?,
                node_name: RecordName::new("First node")?,
                partition_name: RecordName::new(&partition_id.to_string())?,
            },
            authentication: CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([9; 16])?,
                principal_id: administrator,
                label: "Initial API key".to_owned(),
                service_scope: 1 | 2 | 4,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([10; 16])?,
                    key_digest: [11; 32],
                    scopes: 1,
                    valid_from: UnixMicros::new(10),
                },
            },
            recovery: Box::new(recovery_identity()?),
        }),
    ))
}

fn recovery_identity() -> Result<BootstrapRecoveryIdentity, Box<dyn std::error::Error>> {
    let public_key = WrappingPublicKey::from_bytes([12; 32])?;
    let certificate = vec![13; 64];
    Ok(BootstrapRecoveryIdentity {
        public_wrapping_key: public_key.as_bytes(),
        key_fingerprint: public_key.fingerprint(),
        root_certificate_digest: Sha256::digest(&certificate).into(),
        root_certificate_der: certificate,
        bundle_digest: [14; 32],
        save_challenge_commitment: [15; 32],
    })
}

fn count(connection: &rusqlite::Connection, table: &'static str) -> Result<i64, rusqlite::Error> {
    let statement = format!("SELECT count(*) FROM {table}");
    connection.query_row(&statement, [], |row| row.get(0))
}
