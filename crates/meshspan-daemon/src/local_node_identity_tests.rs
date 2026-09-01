// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use tempfile::tempdir;

use crate::{LocalNodeIdentity, LocalNodeIdentityError};

const DNS_NAME: &str = "meshspan.local";

#[test]
fn identity_is_owner_only_restart_stable_and_never_overwritten()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let identity_path = directory.path().join("node-identity.pk8");
    let created = LocalNodeIdentity::open_or_create(&identity_path, DNS_NAME)?;
    let fingerprint = created.public_key_fingerprint();
    assert_ne!(fingerprint, [0; 32]);
    assert_eq!(
        fs::metadata(&identity_path)?.permissions().mode() & 0o777,
        0o600
    );
    assert!(created.bootstrap_server_config().is_ok());
    assert!(matches!(
        LocalNodeIdentity::create(&identity_path, DNS_NAME),
        Err(LocalNodeIdentityError::File)
    ));

    let reopened = LocalNodeIdentity::open(&identity_path, DNS_NAME)?;
    assert_eq!(reopened.public_key_fingerprint(), fingerprint);
    assert!(reopened.bootstrap_server_config().is_ok());
    Ok(())
}

#[test]
fn identity_rejects_symlink_permissions_truncation_and_non_pkcs8()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let identity_path = directory.path().join("node-identity.pk8");
    let link_path = directory.path().join("node-identity-link.pk8");
    LocalNodeIdentity::create(&identity_path, DNS_NAME)?;
    symlink(&identity_path, &link_path)?;
    assert!(LocalNodeIdentity::open(&link_path, DNS_NAME).is_err());

    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o640))?;
    assert!(LocalNodeIdentity::open(&identity_path, DNS_NAME).is_err());
    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))?;
    fs::write(&identity_path, vec![1_u8; 63])?;
    assert!(LocalNodeIdentity::open(&identity_path, DNS_NAME).is_err());
    fs::write(&identity_path, vec![1_u8; 128])?;
    fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))?;
    assert!(LocalNodeIdentity::open(&identity_path, DNS_NAME).is_err());
    Ok(())
}
