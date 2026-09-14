// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{BackupObjectReference, ContractVersion};
use meshspan_domain::{BackupDestinationId, BackupId, OperationId};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "identifier mutation vectors use fixed nonzero 16-byte arrays"
)]
fn every_provider_authority_dimension_is_authenticated() -> TestResult {
    let key = FederatedStoragePermitMacKey::from_bytes([31; 32])?;
    let mut permit = fixture()?;
    permit.permit_digest = federated_backup_permit_mac(&key, &permit);
    assert!(verify_federated_backup_permit_mac(&key, &permit));
    let mutations: [fn(&mut FederatedBackupScope); 12] = [
        |scope| scope.relationship_id = FederationRelationshipId::from_bytes([21; 16]).unwrap(),
        |scope| scope.remote_mesh_id = MeshId::from_bytes([21; 16]).unwrap(),
        |scope| scope.provider_mesh_id = MeshId::from_bytes([21; 16]).unwrap(),
        |scope| scope.allocation_id = FederationStorageAllocationId::from_bytes([21; 16]).unwrap(),
        |scope| scope.grant_id = FederationGrantId::from_bytes([21; 16]).unwrap(),
        |scope| scope.namespace_grant_id = FederationGrantId::from_bytes([21; 16]).unwrap(),
        |scope| scope.provider_node_id = NodeId::from_bytes([21; 16]).unwrap(),
        |scope| scope.target_id = TargetId::from_bytes([21; 16]).unwrap(),
        |scope| scope.target_generation += 1,
        |scope| scope.relationship_authority_epoch += 1,
        |scope| scope.grant_revision = Revision::new(21),
        |scope| scope.allocation_revision = Revision::new(21),
    ];
    for mutate in mutations {
        let mut changed = permit.clone();
        mutate(&mut changed.scope);
        assert_eq!(
            validate_federated_backup_permit(&changed, UnixMicros::new(100)),
            Ok(())
        );
        assert!(!verify_federated_backup_permit_mac(&key, &changed));
    }
    let wrong_key = FederatedStoragePermitMacKey::from_bytes([32; 32])?;
    assert!(!verify_federated_backup_permit_mac(&wrong_key, &permit));
    Ok(())
}

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "identifier mutation vectors use fixed nonzero 16-byte arrays"
)]
fn every_store_field_and_capability_interval_is_authenticated() -> TestResult {
    let key = FederatedStoragePermitMacKey::from_bytes([31; 32])?;
    let mut permit = fixture()?;
    permit.permit_digest = federated_backup_permit_mac(&key, &permit);
    let mutations: [fn(&mut BackupStoreRequest); 10] = [
        |request| request.context.operation_id = OperationId::from_bytes([22; 16]).unwrap(),
        |request| request.context.contract_version.major += 1,
        |request| request.context.contract_version.minor += 1,
        |request| request.context.deadline = UnixMicros::new(301),
        |request| request.context.expected_revision = Some(Revision::new(22)),
        |request| request.object.backup_id = BackupId::from_bytes([22; 16]).unwrap(),
        |request| {
            request.object.destination_id = BackupDestinationId::from_bytes([22; 16]).unwrap();
        },
        |request| request.object.provider_generation += 1,
        |request| request.object.byte_length += 1,
        |request| request.object.digest = [22; 32],
    ];
    for mutate in mutations {
        let mut changed = permit.clone();
        let FederatedBackupRequest::Store(request) = &mut changed.request else {
            return Err("fixture is not a store".into());
        };
        mutate(request);
        assert!(!verify_federated_backup_permit_mac(&key, &changed));
    }
    for (issued_at, expires_at, nonce) in [
        (99, 200, [15; 32]),
        (100, 201, [15; 32]),
        (100, 200, [23; 32]),
    ] {
        let mut changed = permit.clone();
        changed.issued_at = UnixMicros::new(issued_at);
        changed.expires_at = UnixMicros::new(expires_at);
        changed.capability_nonce = nonce;
        assert!(!verify_federated_backup_permit_mac(&key, &changed));
    }
    Ok(())
}

#[test]
fn read_verify_and_delete_cannot_substitute_for_one_another_or_another_object() -> TestResult {
    let key = FederatedStoragePermitMacKey::from_bytes([31; 32])?;
    let fixture = fixture()?;
    let context = fixture.request.context();
    let object = fixture.request.object();
    let reference = BackupObjectReference::new("opaque/provider/object".into())?;
    let requests = [
        FederatedBackupRequest::Read(BackupReadRequest {
            context,
            object,
            object_reference: reference.clone(),
        }),
        FederatedBackupRequest::Verify(BackupVerifyRequest {
            context,
            object,
            object_reference: reference.clone(),
        }),
        FederatedBackupRequest::Delete(BackupDeleteRequest {
            context,
            object,
            object_reference: reference,
            retirement_revision: Revision::new(11),
        }),
    ];
    let mut digests = std::collections::BTreeSet::new();
    for request in requests {
        let mut permit = FederatedBackupPermit {
            request,
            ..fixture.clone()
        };
        permit.permit_digest = federated_backup_permit_mac(&key, &permit);
        assert_eq!(
            validate_federated_backup_permit(&permit, UnixMicros::new(100)),
            Ok(())
        );
        assert!(digests.insert(permit.permit_digest));
        let mut changed = permit.clone();
        match &mut changed.request {
            FederatedBackupRequest::Read(value) => value.object.digest = [29; 32],
            FederatedBackupRequest::Verify(value) => value.object.digest = [29; 32],
            FederatedBackupRequest::Delete(value) => value.object.digest = [29; 32],
            FederatedBackupRequest::Store(_) | FederatedBackupRequest::Lookup(_) => {
                return Err("unexpected locator-free operation".into());
            }
        }
        assert!(!verify_federated_backup_permit_mac(&key, &changed));
        let mut changed = permit.clone();
        let reference = BackupObjectReference::new("another/object".into())?;
        match &mut changed.request {
            FederatedBackupRequest::Read(value) => value.object_reference = reference,
            FederatedBackupRequest::Verify(value) => value.object_reference = reference,
            FederatedBackupRequest::Delete(value) => value.object_reference = reference,
            FederatedBackupRequest::Store(_) | FederatedBackupRequest::Lookup(_) => {
                return Err("unexpected locator-free operation".into());
            }
        }
        assert!(!verify_federated_backup_permit_mac(&key, &changed));
    }
    Ok(())
}

#[test]
fn structural_and_time_boundaries_fail_closed() -> TestResult {
    let permit = fixture()?;
    assert_eq!(
        validate_federated_backup_permit(&permit, UnixMicros::new(100)),
        Ok(())
    );
    assert_eq!(
        validate_federated_backup_permit(&permit, UnixMicros::new(199)),
        Ok(())
    );
    for now in [99, 200, i64::MAX] {
        assert_eq!(
            validate_federated_backup_permit(&permit, UnixMicros::new(now)),
            Err(ContractError::DeadlineExceeded)
        );
    }
    let mutations: [fn(&mut FederatedBackupPermit); 11] = [
        |value| value.scope.remote_mesh_id = value.scope.provider_mesh_id,
        |value| value.scope.target_generation = 0,
        |value| value.scope.relationship_authority_epoch = 0,
        |value| value.scope.grant_revision = Revision::ZERO,
        |value| value.scope.allocation_revision = Revision::ZERO,
        |value| value.capability_nonce = [0; 32],
        |value| value.permit_digest = [0; 32],
        |value| value.issued_at = UnixMicros::new(0),
        |value| value.expires_at = value.issued_at,
        |value| value.expires_at = UnixMicros::new(301),
        |value| value.issued_at = UnixMicros::new(i64::MIN),
    ];
    for mutation in mutations {
        let mut changed = permit.clone();
        mutation(&mut changed);
        assert_eq!(
            validate_federated_backup_permit(&changed, UnixMicros::new(100)),
            Err(ContractError::InvalidInput)
        );
    }
    let mut extended = permit;
    extended.expires_at = UnixMicros::new(300_000_101);
    let FederatedBackupRequest::Store(request) = &mut extended.request else {
        return Err("fixture is not a store".into());
    };
    request.context.deadline = UnixMicros::new(300_000_200);
    assert_eq!(
        validate_federated_backup_permit(&extended, UnixMicros::new(100)),
        Err(ContractError::InvalidInput)
    );
    Ok(())
}

#[test]
fn lookup_capability_cannot_be_reused_as_upload_or_for_another_object() -> TestResult {
    let key = FederatedStoragePermitMacKey::from_bytes([31; 32])?;
    let mut permit = fixture()?;
    let lookup = crate::BackupLookupRequest {
        context: permit.request.context(),
        object: permit.request.object(),
    };
    permit.request = FederatedBackupRequest::Lookup(lookup);
    permit.permit_digest = federated_backup_permit_mac(&key, &permit);
    validate_federated_backup_permit(&permit, UnixMicros::new(100))?;
    assert!(verify_federated_backup_permit_mac(&key, &permit));
    let mut changed = permit.clone();
    changed.request = FederatedBackupRequest::Store(BackupStoreRequest {
        context: lookup.context,
        object: lookup.object,
    });
    assert!(!verify_federated_backup_permit_mac(&key, &changed));
    changed.request = FederatedBackupRequest::Lookup(crate::BackupLookupRequest {
        object: BackupObjectIdentity {
            digest: [99; 32],
            ..lookup.object
        },
        ..lookup
    });
    assert!(!verify_federated_backup_permit_mac(&key, &changed));
    Ok(())
}

#[test]
fn deletion_requires_exact_retirement_and_authenticates_it() -> TestResult {
    let mut permit = fixture()?;
    let request = BackupDeleteRequest {
        context: permit.request.context(),
        object: permit.request.object(),
        object_reference: BackupObjectReference::new("opaque/object".into())?,
        retirement_revision: Revision::new(11),
    };
    permit.request = FederatedBackupRequest::Delete(request);
    let key = FederatedStoragePermitMacKey::from_bytes([31; 32])?;
    permit.permit_digest = federated_backup_permit_mac(&key, &permit);
    let FederatedBackupRequest::Delete(request) = &mut permit.request else {
        return Err("fixture is not a delete".into());
    };
    request.retirement_revision = Revision::new(12);
    assert_eq!(
        validate_federated_backup_permit(&permit, UnixMicros::new(100)),
        Err(ContractError::InvalidInput)
    );
    assert!(!verify_federated_backup_permit_mac(&key, &permit));
    Ok(())
}

#[test]
fn request_digest_matches_independently_assembled_canonical_bytes() -> TestResult {
    let permit = fixture()?;
    let mut bytes = b"meshspan.federation.backup-request.v1".to_vec();
    for marker in [1, 2, 3, 4, 5, 5, 6, 7] {
        bytes.extend_from_slice(&[marker; 16]);
    }
    for number in [8_u64, 9, 10, 11] {
        bytes.extend_from_slice(&number.to_be_bytes());
    }
    bytes.push(1); // Store.
    bytes.extend_from_slice(&[12; 16]);
    bytes.extend_from_slice(&[0, 1, 0, 0]); // Contract 1.0.
    bytes.extend_from_slice(&300_i64.to_be_bytes());
    bytes.push(1); // Revision present.
    bytes.extend_from_slice(&11_u64.to_be_bytes());
    bytes.extend_from_slice(&[13; 16]);
    bytes.extend_from_slice(&[14; 16]);
    bytes.extend_from_slice(&1_u64.to_be_bytes());
    bytes.extend_from_slice(&4096_u64.to_be_bytes());
    bytes.extend_from_slice(&[16; 32]);
    bytes.extend_from_slice(&[0; 16]); // Empty reference, no retirement.
    assert_eq!(
        federated_backup_request_digest(permit.scope, &permit.request),
        *blake3::hash(&bytes).as_bytes()
    );
    Ok(())
}

#[test]
fn provider_namespace_separates_tenants_but_not_permission_revisions() -> TestResult {
    let permit = fixture()?;
    let object = permit.request.object();
    let local = federated_provider_backup_identity(permit.scope, object)?;
    assert_ne!(local.destination_id, object.destination_id);
    assert_eq!(local.provider_generation, permit.scope.target_generation);
    assert_eq!(local.backup_id, object.backup_id);
    assert_eq!(
        (local.byte_length, local.digest),
        (object.byte_length, object.digest)
    );
    let other_tenant = FederatedBackupScope {
        remote_mesh_id: MeshId::from_bytes([88; 16])?,
        ..permit.scope
    };
    assert_ne!(
        federated_provider_backup_identity(other_tenant, object)?.destination_id,
        local.destination_id
    );
    let renewed = FederatedBackupScope {
        grant_id: FederationGrantId::from_bytes([87; 16])?,
        relationship_authority_epoch: 22,
        grant_revision: Revision::new(23),
        ..permit.scope
    };
    assert_eq!(federated_provider_backup_identity(renewed, object)?, local);
    assert_eq!(
        local.destination_id.as_bytes(),
        [
            181, 148, 199, 218, 126, 22, 134, 47, 164, 136, 76, 39, 131, 29, 187, 173
        ],
        "renewal must preserve the original namespace hash"
    );
    let substituted = BackupObjectIdentity {
        digest: [89; 32],
        ..object
    };
    // The same provider catalogue must detect the changed payload under this exact backup ID.
    assert_eq!(
        federated_provider_backup_identity(permit.scope, substituted)?.destination_id,
        local.destination_id
    );
    Ok(())
}

fn fixture() -> Result<FederatedBackupPermit, Box<dyn std::error::Error>> {
    Ok(FederatedBackupPermit {
        scope: FederatedBackupScope {
            relationship_id: FederationRelationshipId::from_bytes([1; 16])?,
            remote_mesh_id: MeshId::from_bytes([2; 16])?,
            provider_mesh_id: MeshId::from_bytes([3; 16])?,
            allocation_id: FederationStorageAllocationId::from_bytes([4; 16])?,
            grant_id: FederationGrantId::from_bytes([5; 16])?,
            namespace_grant_id: FederationGrantId::from_bytes([5; 16])?,
            provider_node_id: NodeId::from_bytes([6; 16])?,
            target_id: TargetId::from_bytes([7; 16])?,
            target_generation: 8,
            relationship_authority_epoch: 9,
            grant_revision: Revision::new(10),
            allocation_revision: Revision::new(11),
        },
        request: FederatedBackupRequest::Store(BackupStoreRequest {
            context: RequestContext {
                operation_id: OperationId::from_bytes([12; 16])?,
                contract_version: ContractVersion::V1_0,
                deadline: UnixMicros::new(300),
                expected_revision: Some(Revision::new(11)),
            },
            object: BackupObjectIdentity {
                backup_id: BackupId::from_bytes([13; 16])?,
                destination_id: BackupDestinationId::from_bytes([14; 16])?,
                provider_generation: 1,
                byte_length: 4096,
                digest: [16; 32],
            },
        }),
        issued_at: UnixMicros::new(100),
        expires_at: UnixMicros::new(200),
        capability_nonce: [15; 32],
        permit_digest: [17; 32],
    })
}
