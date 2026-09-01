// SPDX-License-Identifier: GPL-2.0-only

use std::os::unix::fs::PermissionsExt as _;

use meshspan_domain::{EntropyError, MeshId, RandomSource};
use meshspan_recovery_bundle::RecoveryBundleCode;
use tempfile::tempdir;
use zeroize::Zeroizing;

use crate::{PendingRecoveryBundle, PendingRecoveryBundleError};

#[test]
fn pending_bundle_reopens_exactly_and_never_replaces_conflicting_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file = directory.path().join("pending-recovery.bundle");
    let mesh_id = MeshId::from_bytes([7; 16])?;
    let code = RecoveryBundleCode::from_high_entropy_seed(Zeroizing::new([8; 32]))?;
    let created =
        PendingRecoveryBundle::open_or_create(&file, mesh_id, &code, &mut SequentialRandom(11))?;
    let first_download = created.download_text()?;
    let first_identity = created.public_identity()?;
    let first_file = std::fs::read(&file)?;
    drop(created);

    let reopened =
        PendingRecoveryBundle::open_or_create(&file, mesh_id, &code, &mut SequentialRandom(99))?;
    assert_eq!(reopened.download_text()?, first_download);
    assert_eq!(reopened.public_identity()?, first_identity);
    assert_eq!(
        std::fs::metadata(&file)?.permissions().mode() & 0o777,
        0o600
    );

    let wrong_code = RecoveryBundleCode::from_high_entropy_seed(Zeroizing::new([9; 32]))?;
    assert!(matches!(
        PendingRecoveryBundle::open_or_create(
            &file,
            mesh_id,
            &wrong_code,
            &mut SequentialRandom(33),
        ),
        Err(PendingRecoveryBundleError::Bundle(_))
    ));
    assert!(matches!(
        PendingRecoveryBundle::open_or_create(
            &file,
            MeshId::from_bytes([10; 16])?,
            &code,
            &mut SequentialRandom(44),
        ),
        Err(PendingRecoveryBundleError::Conflict)
    ));
    assert_eq!(std::fs::read(&file)?, first_file);
    Ok(())
}

struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
