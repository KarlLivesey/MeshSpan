// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{BackupId, MeshId, OperationId, PartitionId, Revision};

use super::SequentialRandom;
use crate::{RecoveryAuthorization, RecoveryAuthorizationClaims, create_recovery_bundle};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn portable_recovery_container_rejects_every_truncation_and_changed_byte() -> TestResult {
    let original = claims()?;
    let (bundle, code, identity) =
        create_recovery_bundle(original.mesh_id, &mut SequentialRandom::new(101))?;
    let signed = bundle.open(&code)?.authorize_recovery(original)?;
    let encoded = signed.encode()?;
    let root = identity.root_certificate_der();
    assert_eq!(RecoveryAuthorization::decode(root, &encoded)?, signed);
    assert_eq!(&encoded[..211], &original.canonical_bytes()?);
    assert_eq!(usize::from(encoded[211]), signed.signature().len());
    for end in 0..encoded.len() {
        assert!(RecoveryAuthorization::decode(root, &encoded[..end]).is_err());
    }
    for index in 0..encoded.len() {
        let mut changed = encoded.clone();
        changed[index] ^= 1;
        assert!(
            RecoveryAuthorization::decode(root, &changed).is_err(),
            "changed byte {index} accepted"
        );
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(RecoveryAuthorization::decode(root, &trailing).is_err());
    assert!(RecoveryAuthorization::decode(root, &vec![0; 285]).is_err());
    Ok(())
}

pub(super) fn claims() -> Result<RecoveryAuthorizationClaims, Box<dyn std::error::Error>> {
    Ok(RecoveryAuthorizationClaims {
        mesh_id: MeshId::from_bytes([1; 16])?,
        partition_id: PartitionId::from_bytes([2; 16])?,
        recovery_id: OperationId::from_bytes([3; 16])?,
        backup_id: BackupId::from_bytes([4; 16])?,
        backup_digest: [5; 32],
        source_log_index: 12,
        source_log_term: 3,
        source_revision: Revision::new(10),
        previous_epoch: 0,
        recovery_epoch: 1,
        replacement_manifest_digest: [6; 32],
        target_inventory_digest: [7; 32],
    })
}

#[test]
fn recovery_claims_have_an_exact_fixed_width_signing_format() -> TestResult {
    let bytes = claims()?.canonical_bytes()?;
    assert_eq!(bytes.len(), 211);
    assert_eq!(&bytes[..11], b"MSRECOVERY\x01");
    assert_eq!(&bytes[11..27], &[1; 16]);
    assert_eq!(&bytes[27..43], &[2; 16]);
    assert_eq!(&bytes[43..59], &[3; 16]);
    assert_eq!(&bytes[59..75], &[4; 16]);
    assert_eq!(&bytes[75..107], &[5; 32]);
    assert_eq!(
        &bytes[107..147],
        &[
            0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
    );
    assert_eq!(&bytes[147..179], &[6; 32]);
    assert_eq!(&bytes[179..211], &[7; 32]);
    Ok(())
}

#[test]
fn recovery_signature_binds_every_claim_and_the_independent_root() -> TestResult {
    let original = claims()?;
    let (bundle, code, identity) =
        create_recovery_bundle(original.mesh_id, &mut SequentialRandom::new(41))?;
    let authority = bundle.open(&code)?;
    let signed = authority.authorize_recovery(original)?;
    assert_eq!(signed.claims(), &original);
    assert_eq!(
        RecoveryAuthorization::verify(
            identity.root_certificate_der(),
            original,
            signed.signature(),
        )?,
        signed
    );

    let replacements = [
        RecoveryAuthorizationClaims {
            mesh_id: MeshId::from_bytes([11; 16])?,
            ..original
        },
        RecoveryAuthorizationClaims {
            partition_id: PartitionId::from_bytes([12; 16])?,
            ..original
        },
        RecoveryAuthorizationClaims {
            recovery_id: OperationId::from_bytes([13; 16])?,
            ..original
        },
        RecoveryAuthorizationClaims {
            backup_id: BackupId::from_bytes([14; 16])?,
            ..original
        },
        RecoveryAuthorizationClaims {
            backup_digest: [15; 32],
            ..original
        },
        RecoveryAuthorizationClaims {
            source_log_index: 13,
            ..original
        },
        RecoveryAuthorizationClaims {
            source_log_term: 4,
            ..original
        },
        RecoveryAuthorizationClaims {
            source_revision: Revision::new(11),
            ..original
        },
        RecoveryAuthorizationClaims {
            previous_epoch: 1,
            recovery_epoch: 2,
            ..original
        },
        RecoveryAuthorizationClaims {
            replacement_manifest_digest: [16; 32],
            ..original
        },
        RecoveryAuthorizationClaims {
            target_inventory_digest: [17; 32],
            ..original
        },
    ];
    for changed in replacements {
        assert!(
            RecoveryAuthorization::verify(
                identity.root_certificate_der(),
                changed,
                signed.signature(),
            )
            .is_err(),
            "substituted claims accepted: {changed:?}"
        );
    }
    assert!(authority.authorize_recovery(replacements[0]).is_err());
    let (_, _, other) = create_recovery_bundle(original.mesh_id, &mut SequentialRandom::new(71))?;
    assert!(
        RecoveryAuthorization::verify(other.root_certificate_der(), original, signed.signature(),)
            .is_err()
    );
    Ok(())
}

#[test]
fn recovery_rejects_missing_evidence_and_invalid_epoch_successors() -> TestResult {
    let original = claims()?;
    let invalid = [
        RecoveryAuthorizationClaims {
            backup_digest: [0; 32],
            ..original
        },
        RecoveryAuthorizationClaims {
            replacement_manifest_digest: [0; 32],
            ..original
        },
        RecoveryAuthorizationClaims {
            target_inventory_digest: [0; 32],
            ..original
        },
        RecoveryAuthorizationClaims {
            source_log_index: 0,
            ..original
        },
        RecoveryAuthorizationClaims {
            source_log_term: 0,
            ..original
        },
        RecoveryAuthorizationClaims {
            source_revision: Revision::ZERO,
            ..original
        },
        RecoveryAuthorizationClaims {
            recovery_epoch: 0,
            ..original
        },
        RecoveryAuthorizationClaims {
            recovery_epoch: 2,
            ..original
        },
        RecoveryAuthorizationClaims {
            previous_epoch: u64::MAX,
            recovery_epoch: 0,
            ..original
        },
        RecoveryAuthorizationClaims {
            previous_epoch: i64::MAX.unsigned_abs(),
            recovery_epoch: i64::MAX.unsigned_abs() + 1,
            ..original
        },
    ];
    for candidate in invalid {
        assert!(
            candidate.canonical_bytes().is_err(),
            "invalid claims accepted: {candidate:?}"
        );
    }
    assert!(
        RecoveryAuthorizationClaims {
            previous_epoch: 4,
            recovery_epoch: 5,
            ..original
        }
        .canonical_bytes()
        .is_ok()
    );
    Ok(())
}

#[test]
fn recovery_rejects_noncanonical_roots_and_signature_containers() -> TestResult {
    let original = claims()?;
    let (bundle, code, identity) =
        create_recovery_bundle(original.mesh_id, &mut SequentialRandom::new(91))?;
    let signed = bundle.open(&code)?.authorize_recovery(original)?;
    let mut trailing_root = identity.root_certificate_der().to_vec();
    trailing_root.push(0);
    for root in [Vec::new(), vec![0; 16 * 1024 + 1], trailing_root] {
        assert!(RecoveryAuthorization::verify(&root, original, signed.signature()).is_err());
    }
    let mut trailing_signature = signed.signature().to_vec();
    trailing_signature.push(0);
    let mut corrupted = signed.signature().to_vec();
    corrupted[10] ^= 1;
    for signature in [Vec::new(), vec![0; 73], trailing_signature, corrupted] {
        assert!(
            RecoveryAuthorization::verify(identity.root_certificate_der(), original, &signature,)
                .is_err()
        );
    }
    Ok(())
}
