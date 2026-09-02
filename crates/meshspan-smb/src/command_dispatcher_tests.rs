// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::VolumeId;
use meshspan_filesystem::NamespaceLimits;

use super::{SmbPublishedShare, classify_adapter_error};
use crate::{ConnectorFailure, SmbFilesystemAdapterError};

#[test]
fn published_share_rejects_ambiguous_or_unsafe_routes() -> Result<(), Box<dyn std::error::Error>> {
    let volume_id = VolumeId::from_bytes([1; 16])?;
    assert!(
        SmbPublishedShare::new(
            "files".to_owned(),
            volume_id,
            vec!["Departments".to_owned()],
            NamespaceLimits::PORTABLE,
            0x001f_01ff,
            true,
        )
        .is_ok()
    );
    for invalid in ["", " files", "files ", "one/two", "one\\two", "bad\nname"] {
        assert!(
            SmbPublishedShare::new(
                invalid.to_owned(),
                volume_id,
                Vec::new(),
                NamespaceLimits::PORTABLE,
                1,
                true,
            )
            .is_err()
        );
    }
    assert!(
        SmbPublishedShare::new(
            "files".to_owned(),
            volume_id,
            Vec::new(),
            NamespaceLimits::PORTABLE,
            0,
            true,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn adapter_failures_have_closed_stable_connector_classes() {
    #[derive(Debug)]
    struct TestError;

    let classifier = |_: &TestError| ConnectorFailure::StorageFull;
    let cases = [
        (
            SmbFilesystemAdapterError::UnsupportedMutation,
            ConnectorFailure::Unsupported,
        ),
        (
            SmbFilesystemAdapterError::UnknownFile,
            ConnectorFailure::HandleClosed,
        ),
        (
            SmbFilesystemAdapterError::NoMoreFiles,
            ConnectorFailure::NoMoreEntries,
        ),
        (
            SmbFilesystemAdapterError::DuplicateLock,
            ConnectorFailure::LockConflict,
        ),
        (
            SmbFilesystemAdapterError::InvalidPath,
            ConnectorFailure::InvalidInput,
        ),
        (
            SmbFilesystemAdapterError::Filesystem(TestError),
            ConnectorFailure::StorageFull,
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(classify_adapter_error(&classifier, &error), expected);
    }
}
