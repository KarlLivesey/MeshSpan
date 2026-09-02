// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, HostId, MeshId, NodeId, OperationId,
    PartitionId, PrincipalId, Revision, RoleId, UnixMicros,
};
use meshspan_secret_envelope::WrappingPublicKey;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::{
    ApplyDisposition, AuthoritativeRepository, LogPosition, RecoveryBundleState, RepositoryError,
};
use crate::{
    AuthoritativeCommand, BootstrapMesh, BootstrapRecoveryIdentity, CommandContext,
    ConfirmRecoveryBundleSaved, CreateAuthenticationMethod, NewAuthenticationCredential,
    PartitionDatabase, RecordName,
};

#[test]
fn bootstrap_commits_recovery_recipient_and_exact_pending_bundle_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut repository, context, command, mesh_id, administrator) = fixture()?;
    repository.apply_committed(LogPosition { index: 1, term: 1 }, context, &command)?;

    let pending = repository
        .mesh_recovery_authority(mesh_id)?
        .ok_or("recovery authority missing")?;
    assert_eq!(pending.state, RecoveryBundleState::Pending);
    assert_eq!(pending.public_wrapping_key, wrapping_public_key()?);
    assert_eq!(pending.root_certificate_der, root_certificate());
    assert_eq!(pending.bundle_digest, [14; 32]);
    assert_eq!(pending.verified_by, None);
    assert_eq!(pending.verified_at, None);
    let online = repository
        .online_certificate_authority(mesh_id)?
        .ok_or("online certificate authority missing")?;
    assert_eq!(online.mesh_id, mesh_id);
    assert_eq!(online.generation, 1);
    assert_eq!(online.certificate_der, root_certificate());
    assert_eq!(online.revision, Revision::new(1));
    assert_eq!(
        repository.latest_online_authority_generation(mesh_id)?,
        Some(1)
    );

    let confirm_context = CommandContext {
        operation_id: OperationId::from_bytes([16; 16])?,
        actor_principal_id: administrator,
        audit_event_id: AuditEventId::from_bytes([17; 16])?,
        occurred_at: UnixMicros::new(20),
        expected_revision: Some(Revision::new(1)),
    };
    let confirm = AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
        mesh_id,
        bundle_digest: [14; 32],
        save_challenge_commitment: [15; 32],
    });
    let receipt =
        repository.apply_committed(LogPosition { index: 2, term: 1 }, confirm_context, &confirm)?;
    assert_eq!(receipt.disposition, ApplyDisposition::Applied);
    let verified = repository
        .mesh_recovery_authority(mesh_id)?
        .ok_or("verified recovery authority missing")?;
    assert_eq!(verified.state, RecoveryBundleState::Verified);
    assert_eq!(verified.verified_by, Some(administrator));
    assert_eq!(verified.verified_at, Some(UnixMicros::new(20)));
    assert_eq!(verified.revision, Revision::new(2));
    Ok(())
}

#[test]
fn wrong_bundle_or_challenge_cannot_mark_recovery_saved() -> Result<(), Box<dyn std::error::Error>>
{
    for (bundle_digest, challenge) in [([99; 32], [15; 32]), ([14; 32], [99; 32])] {
        let (mut repository, context, command, mesh_id, administrator) = fixture()?;
        repository.apply_committed(LogPosition { index: 1, term: 1 }, context, &command)?;
        let changed =
            AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
                mesh_id,
                bundle_digest,
                save_challenge_commitment: challenge,
            });
        assert!(matches!(
            repository.apply_committed(
                LogPosition { index: 2, term: 1 },
                CommandContext {
                    operation_id: OperationId::from_bytes([18; 16])?,
                    actor_principal_id: administrator,
                    audit_event_id: AuditEventId::from_bytes([19; 16])?,
                    occurred_at: UnixMicros::new(20),
                    expected_revision: Some(Revision::new(1)),
                },
                &changed,
            ),
            Err(RepositoryError::InvalidCommand)
        ));
        assert_eq!(
            repository
                .mesh_recovery_authority(mesh_id)?
                .ok_or("recovery authority missing")?
                .state,
            RecoveryBundleState::Pending
        );
    }
    Ok(())
}

type Fixture = (
    AuthoritativeRepository,
    CommandContext,
    AuthoritativeCommand,
    MeshId,
    PrincipalId,
);

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let partition_id = PartitionId::from_bytes([1; 16])?;
    let database = PartitionDatabase::open(
        &directory.path().join("authority.sqlite3"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let administrator = PrincipalId::from_bytes([2; 16])?;
    let mesh_id = MeshId::from_bytes([5; 16])?;
    let context = CommandContext {
        operation_id: OperationId::from_bytes([3; 16])?,
        actor_principal_id: administrator,
        audit_event_id: AuditEventId::from_bytes([4; 16])?,
        occurred_at: UnixMicros::new(10),
        expected_revision: Some(Revision::ZERO),
    };
    let command = AuthoritativeCommand::BootstrapAppliance(Box::new(
        crate::test_support::bootstrap_appliance(
            BootstrapMesh {
                mesh_id,
                mesh_name: RecordName::new("First mesh")?,
                administrator_id: administrator,
                administrator_name: RecordName::new("First administrator")?,
                administrator_role_id: RoleId::from_bytes([6; 16])?,
                host_id: HostId::from_bytes([7; 16])?,
                host_name: RecordName::new("First host")?,
                node_id: NodeId::from_bytes([8; 16])?,
                node_name: RecordName::new("First node")?,
                partition_name: RecordName::new("Root authority")?,
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
            Box::new(recovery_identity()?),
        )?,
    ));
    Ok((
        AuthoritativeRepository::new(database),
        context,
        command,
        mesh_id,
        administrator,
    ))
}

fn recovery_identity() -> Result<BootstrapRecoveryIdentity, Box<dyn std::error::Error>> {
    let public_key = wrapping_public_key()?;
    let certificate = root_certificate();
    Ok(BootstrapRecoveryIdentity {
        public_wrapping_key: public_key.as_bytes(),
        key_fingerprint: public_key.fingerprint(),
        online_authority_certificate_digest: Sha256::digest(&certificate).into(),
        online_authority_certificate_der: certificate.clone(),
        root_certificate_digest: Sha256::digest(&certificate).into(),
        root_certificate_der: certificate,
        bundle_digest: [14; 32],
        save_challenge_commitment: [15; 32],
    })
}

fn wrapping_public_key() -> Result<WrappingPublicKey, Box<dyn std::error::Error>> {
    Ok(WrappingPublicKey::from_bytes([12; 32])?)
}

fn root_certificate() -> Vec<u8> {
    vec![13; 64]
}
