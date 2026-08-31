// SPDX-License-Identifier: GPL-2.0-only

use serde_json::json;

use crate::{
    ApiKeyId, ApiKeyScope, AuthenticationMethodDetails, AuthenticationMethodId,
    AuthenticationMethodState, AuthenticationMethodSummary, ListAuthenticationMethodsQuery,
    ListAuthenticationMethodsResponse, encode_list_authentication_methods_response,
    validate_list_authentication_methods_query_value,
};

#[test]
fn authentication_method_page_is_bounded_and_secret_free() -> Result<(), Box<dyn std::error::Error>>
{
    let page = ListAuthenticationMethodsResponse {
        methods: vec![AuthenticationMethodSummary {
            method_id: AuthenticationMethodId::from_uuid_bytes(versioned(1))
                .ok_or("invalid method")?,
            label: "Laptop automation".to_owned(),
            state: AuthenticationMethodState::Active,
            details: AuthenticationMethodDetails::ApiKey {
                key_id: ApiKeyId::from_uuid_bytes(versioned(2)).ok_or("invalid key")?,
                scopes: vec![ApiKeyScope::HeadlessApi],
                valid_from_epoch_micros: 10,
            },
            created_at_epoch_micros: 10,
            last_used_at_epoch_micros: None,
            expires_at_epoch_micros: Some(20),
            revision: 3,
        }],
        next_page_url: Some(
            "/api/latest/users/current/authentication-methods?limit=1&cursor=v1.am.aa".to_owned(),
        ),
    };
    let encoded = encode_list_authentication_methods_response(&page)?;
    let value: serde_json::Value = serde_json::from_slice(&encoded)?;
    assert_eq!(value["methods"][0]["details"]["kind"], "api_key");
    assert!(value.to_string().find("secret").is_none());
    Ok(())
}

#[test]
fn authentication_method_query_and_output_reject_substitution() {
    assert!(validate_list_authentication_methods_query_value(&json!({})).is_ok());
    assert!(validate_list_authentication_methods_query_value(&json!({ "limit": 0 })).is_err());
    assert!(
        validate_list_authentication_methods_query_value(&json!({ "unexpected": true })).is_err()
    );
    let hostile_cursor = json!({ "cursor": "../another-user" });
    assert!(
        serde_json::from_value::<ListAuthenticationMethodsQuery>(hostile_cursor.clone()).is_ok()
    );
    assert!(validate_list_authentication_methods_query_value(&hostile_cursor).is_err());

    let invalid = ListAuthenticationMethodsResponse {
        methods: Vec::new(),
        next_page_url: Some("/api/latest/admin/users".to_owned()),
    };
    assert!(encode_list_authentication_methods_response(&invalid).is_err());
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x41;
    value[8] = 0x81;
    value
}
