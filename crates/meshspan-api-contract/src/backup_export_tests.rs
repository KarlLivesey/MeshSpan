// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    BackupExportHeaders, BackupExportPath, validate_backup_export_headers,
    validate_backup_export_path,
};

const BACKUP: &str = "11111111-1111-4111-8111-111111111111";

#[test]
fn backup_export_evidence_preserves_exact_lengths_and_rejects_invalid_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = BackupExportHeaders {
        backup_id: BACKUP.to_owned(),
        byte_length: "9007199254740993".to_owned(),
        digest: format!("sha256:{}", "a".repeat(64)),
    };
    validate_backup_export_headers(&valid)?;
    assert_eq!(
        serde_json::to_value(&valid)?["Content-Length"],
        "9007199254740993"
    );
    for length in ["", "0", "01", "-1", "3.0", "18446744073709551615"] {
        let mut changed = valid.clone();
        changed.byte_length = length.to_owned();
        assert!(
            validate_backup_export_headers(&changed).is_err(),
            "{length}"
        );
    }
    for digest in ["sha256:a", "md5:abc", &format!("sha256:{}", "A".repeat(64))] {
        let mut changed = valid.clone();
        changed.digest = digest.to_owned();
        assert!(validate_backup_export_headers(&changed).is_err());
    }
    for changes in [
        serde_json::json!({"Content-Length": null}),
        serde_json::json!({"Content-Length": 3}),
        serde_json::json!({"unknown": true}),
    ] {
        let mut value = serde_json::to_value(&valid)?;
        for (key, replacement) in changes.as_object().ok_or("fixture not an object")? {
            value[key] = replacement.clone();
        }
        assert!(serde_json::from_value::<BackupExportHeaders>(value).is_err());
    }
    Ok(())
}

#[test]
fn backup_export_path_is_canonical_and_does_not_accept_provider_details()
-> Result<(), Box<dyn std::error::Error>> {
    validate_backup_export_path(&BackupExportPath {
        backup_id: BACKUP.to_owned(),
    })?;
    for identifier in [
        "../provider",
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-4111-8111-111111111111/extra",
    ] {
        assert!(
            validate_backup_export_path(&BackupExportPath {
                backup_id: identifier.to_owned()
            })
            .is_err()
        );
    }
    assert!(
        serde_json::from_value::<BackupExportPath>(
            serde_json::json!({"backup_id": BACKUP, "provider_path": "/secret"})
        )
        .is_err()
    );
    Ok(())
}
