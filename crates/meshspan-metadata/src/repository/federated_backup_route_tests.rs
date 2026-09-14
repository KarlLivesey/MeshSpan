// SPDX-License-Identifier: GPL-2.0-only

//! Route intent, operation receipt and revision move atomically; backups remain unacknowledged.

use super::*;
use crate::{
    BackupDestinationBinding, BackupFailureRelationship, BindFederatedBackupRoute,
    ConfigureBackupDestination,
};
use meshspan_contracts::{BackupObjectIdentity, FederatedBackupScope};
use meshspan_domain::{
    BackupDestinationId, FederationGrantId, FederationRelationshipId,
    FederationStorageAllocationId, TargetId,
};

#[test]
fn routing_intent_rolls_back_at_every_apply_boundary_and_survives_backup_restore()
-> Result<(), Box<dyn std::error::Error>> {
    use super::super::apply::{ApplyFaultPoint, apply_committed_with_fault};
    let (mut fixture, value) = prepared()?;
    let command = AuthoritativeCommand::BindFederatedBackupRoute(value);
    let context = context(70, fixture.administrator, 71, 130, 7)?;
    let position = LogPosition { index: 8, term: 1 };
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterOperation,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        assert!(matches!(
            apply_committed_with_fault(
                &mut fixture.repository.database,
                position,
                context,
                &command,
                fault
            ),
            Err(RepositoryError::InjectedFault)
        ));
        assert!(
            fixture
                .repository
                .federated_backup_route(value.object.backup_id, value.object.destination_id)?
                .is_none()
        );
        assert_eq!(fixture.repository.current_revision()?, Revision::new(7));
    }
    fixture
        .repository
        .apply_committed(position, context, &command)?;
    let expected = crate::FederatedBackupRouteRecord {
        binding: value,
        revision: Revision::new(8),
    };
    assert_eq!(
        fixture
            .repository
            .federated_backup_route(value.object.backup_id, value.object.destination_id)?,
        Some(expected)
    );
    assert!(
        fixture
            .repository
            .metadata_backup(value.object.backup_id)?
            .is_none()
    );
    assert!(
        fixture
            .repository
            .backup_copy(value.object.backup_id, value.object.destination_id)?
            .is_none()
    );
    let restored = super::super::federation_backup_test_support::backup_and_restore(
        &fixture.repository,
        fixture.directory.path(),
        90,
    )?;
    assert_eq!(
        restored.federated_backup_route(value.object.backup_id, value.object.destination_id)?,
        Some(expected)
    );
    super::super::federated_backup_route::validate_recorded_object(
        restored.database.connection(),
        value.object,
    )?;
    let changed = BackupObjectIdentity {
        digest: [99; 32],
        ..value.object
    };
    assert!(matches!(
        super::super::federated_backup_route::validate_recorded_object(
            restored.database.connection(),
            changed
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

#[test]
fn routing_record_has_exact_canonical_bytes_and_rejects_changed_dimensions()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, value) = prepared()?;
    let bytes = crate::command_codec::backup_route::record(&value)?;
    let mut expected = vec![2];
    for marker in [20, 46, 41, 3, 40, 44, 45, 45, 42, 43] {
        expected.extend_from_slice(&[marker; 16]);
    }
    for number in [1_u64, 50, 1, 1, 1, 1] {
        expected.extend_from_slice(&number.to_be_bytes());
    }
    expected.extend_from_slice(&[47; 32]);
    expected.extend_from_slice(&[4; 16]);
    for number in [1_u64, 1, 21, 7] {
        expected.extend_from_slice(&number.to_be_bytes());
    }
    assert_eq!(bytes, expected);
    assert_eq!(crate::command_codec::backup_route::parse(&bytes)?, value);
    let mut legacy = vec![1];
    legacy.extend_from_slice(&expected[1..113]);
    legacy.extend_from_slice(&expected[129..]);
    assert_eq!(crate::command_codec::backup_route::parse(&legacy)?, value);
    assert_route_command_versions(&value, &expected[1..], &legacy[1..])?;
    for malformed in [
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.clone(), vec![0]].concat(),
        vec![0; 321],
    ] {
        assert!(crate::command_codec::backup_route::parse(&malformed).is_err());
    }
    let mut invalid = value;
    invalid.object.byte_length = 0;
    assert!(crate::command_codec::backup_route::record(&invalid).is_err());
    invalid = value;
    invalid.scope.provider_mesh_id = invalid.scope.remote_mesh_id;
    assert!(crate::command_codec::backup_route::record(&invalid).is_err());
    invalid = value;
    invalid.claim.fence = u64::MAX;
    assert!(crate::command_codec::backup_route::record(&invalid).is_err());
    Ok(())
}

fn assert_route_command_versions(
    value: &BindFederatedBackupRoute,
    current_body: &[u8],
    legacy_body: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let context = context(70, PrincipalId::from_bytes([1; 16])?, 71, 130, 7)?;
    let mut header = b"MSC\x04".to_vec();
    for marker in [70, 1, 71] {
        header.extend_from_slice(&[marker; 16]);
    }
    header.extend_from_slice(&130_i64.to_be_bytes());
    header.push(1);
    header.extend_from_slice(&7_u64.to_be_bytes());
    let command = AuthoritativeCommand::BindFederatedBackupRoute(*value);
    for (kind, body) in [(120_u16, legacy_body), (121, current_body)] {
        let bytes = [header.as_slice(), &kind.to_be_bytes(), body].concat();
        let decoded = crate::decode_authoritative_command(&bytes)?;
        assert_eq!(decoded.context, context);
        assert_eq!(decoded.command, command);
        if kind == 121 {
            assert_eq!(
                crate::encode_authoritative_command(context, &command)?,
                bytes
            );
        }
    }
    Ok(())
}

fn prepared() -> Result<(Fixture, BindFederatedBackupRoute), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let backup_id = BackupId::from_bytes([20; 16])?;
    queue_run(&mut fixture, backup_id)?;
    let claim = claim(1, fixture.node, 21);
    apply_claim(&mut fixture, backup_id, claim, 200, 4)?;
    let relationship_id = FederationRelationshipId::from_bytes([41; 16])?;
    let provider_mesh_id = MeshId::from_bytes([40; 16])?;
    let destination_id = BackupDestinationId::from_bytes([46; 16])?;
    let commands = [
        AuthoritativeCommand::ProposeFederationRelationship(crate::ProposeFederationRelationship {
            relationship_id,
            remote_mesh_id: provider_mesh_id,
            remote_name: RecordName::new("Backup provider")?,
            kind: meshspan_domain::FederationRelationshipKind::Horizontal,
            governance_direction: crate::FederationGovernanceDirection::None,
        }),
        AuthoritativeCommand::ApproveFederationRelationship(crate::ApproveFederationRelationship {
            relationship_id,
            expected_authority_epoch: 1,
            local_identity: identity(50),
            remote_identity: identity(51),
            governance_proof: None,
        }),
        AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id,
            expected_destination_revision: Revision::ZERO,
            name: RecordName::new("Partner")?,
            binding: BackupDestinationBinding::FederatedMesh {
                remote_mesh_id: provider_mesh_id,
                provider_generation: 1,
            },
            failure_relationship: BackupFailureRelationship::Unknown,
            failure_evidence_digest: [0; 32],
            enabled: true,
        }),
    ];
    for (index, command) in commands.iter().enumerate() {
        let offset = u64::try_from(index)?;
        fixture.repository.apply_committed(
            LogPosition {
                index: 5 + offset,
                term: 1,
            },
            context(
                60 + u8::try_from(index)?,
                fixture.administrator,
                65 + u8::try_from(index)?,
                120,
                4 + offset,
            )?,
            command,
        )?;
    }
    let binding = BindFederatedBackupRoute {
        object: BackupObjectIdentity {
            backup_id,
            destination_id,
            provider_generation: 1,
            byte_length: 50,
            digest: [47; 32],
        },
        scope: FederatedBackupScope {
            relationship_id,
            remote_mesh_id: MeshId::from_bytes([3; 16])?,
            provider_mesh_id,
            allocation_id: FederationStorageAllocationId::from_bytes([44; 16])?,
            grant_id: FederationGrantId::from_bytes([45; 16])?,
            namespace_grant_id: FederationGrantId::from_bytes([45; 16])?,
            provider_node_id: NodeId::from_bytes([42; 16])?,
            target_id: TargetId::from_bytes([43; 16])?,
            target_generation: 1,
            relationship_authority_epoch: 1,
            grant_revision: Revision::new(1),
            allocation_revision: Revision::new(1),
        },
        claim,
        expected_destination_revision: Revision::new(7),
    };
    Ok((fixture, binding))
}

fn identity(marker: u8) -> crate::FederationTrustIdentity {
    crate::FederationTrustIdentity {
        generation: 1,
        certificate_fingerprint: [marker; 32],
        verifying_key: ed25519_dalek::SigningKey::from_bytes(&[marker; 32])
            .verifying_key()
            .to_bytes(),
        valid_from: UnixMicros::new(100),
        valid_until: UnixMicros::new(1000),
    }
}
