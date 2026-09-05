// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    BackupReadinessResponse, BackupReadinessVerification, encode_backup_readiness_response,
};

#[test]
fn restore_readiness_evidence_is_lossless_and_never_claims_offline_key_verification()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = BackupReadinessResponse {
        backup_id: "11111111-1111-4111-8111-111111111111".to_owned(),
        checked_by_node_id: "22222222-2222-4222-8222-222222222222".to_owned(),
        partition_id: "33333333-3333-4333-8333-333333333333".to_owned(),
        source_log_index: "9007199254740993".to_owned(),
        source_log_term: "1".to_owned(),
        state_revision: "9007199254740992".to_owned(),
        checked_at_epoch_micros: 20,
        verification: BackupReadinessVerification::GatewayKey,
    };
    let encoded = encode_backup_readiness_response(&valid)?;
    assert_eq!(
        serde_json::from_slice::<BackupReadinessResponse>(&encoded)?,
        valid
    );
    for index in ["0", "01", "-1", "18446744073709551615"] {
        let mut changed = valid.clone();
        changed.source_log_index = index.to_owned();
        assert!(encode_backup_readiness_response(&changed).is_err());
    }
    for changes in [
        serde_json::json!({"verification": "offline_recovery"}),
        serde_json::json!({"source_log_index": 1}),
        serde_json::json!({"state_revision": null}),
        serde_json::json!({"private_key": "never accepted"}),
    ] {
        let mut value = serde_json::to_value(&valid)?;
        for (key, replacement) in changes.as_object().ok_or("fixture")? {
            value[key] = replacement.clone();
        }
        assert!(serde_json::from_value::<BackupReadinessResponse>(value).is_err());
    }
    let mut changed = valid;
    changed.checked_at_epoch_micros = 9_007_199_254_740_992;
    assert!(encode_backup_readiness_response(&changed).is_err());
    Ok(())
}
