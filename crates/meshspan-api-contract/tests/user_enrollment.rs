// SPDX-License-Identifier: GPL-2.0-only

//! Public first-credential contract and hostile request regressions.

use meshspan_api_contract::{decode_redeem_user_enrollment_api_key_request, generate_openapi};
use serde_json::json;

#[test]
fn public_first_credential_route_is_anonymous_and_bounded() -> Result<(), Box<dyn std::error::Error>>
{
    let document = generate_openapi()?;
    let operation = &document.value()["paths"]["/user-enrollments/api-keys"]["post"];
    assert_eq!(operation["x-meshspan-access"], "anonymous");
    assert_eq!(operation["x-meshspan-max-request-bytes"], 2048);
    assert_eq!(operation["operationId"], "redeemUserEnrollmentApiKey");
    Ok(())
}

#[test]
fn recipient_enrollment_rejects_login_keys_missing_expiry_and_duplicate_scopes()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = json!({
        "operation_id": "00000000-0000-4000-8000-000000000009",
        "token": format!("meshspan-user-enrollment-v1.{}.{}", "1".repeat(32), "2".repeat(64)),
        "label": "My first key", "scopes": ["https_session", "headless_api"], "expires_at_epoch_micros": null
    });
    decode_redeem_user_enrollment_api_key_request(&serde_json::to_vec(&valid)?)?;
    let mut missing_expiry = valid.clone();
    missing_expiry
        .as_object_mut()
        .ok_or("expected object")?
        .remove("expires_at_epoch_micros");
    let mut login_key = valid.clone();
    login_key["token"] = json!(format!(
        "meshspan-key-v1.{}.{}",
        "1".repeat(32),
        "2".repeat(64)
    ));
    let mut duplicate = valid.clone();
    duplicate["scopes"] = json!(["https_session", "https_session"]);
    let mut extra = valid;
    extra["principal_id"] = json!("00000000-0000-4000-8000-000000000010");
    for invalid in [missing_expiry, login_key, duplicate, extra] {
        assert!(
            decode_redeem_user_enrollment_api_key_request(&serde_json::to_vec(&invalid)?).is_err()
        );
    }
    Ok(())
}
