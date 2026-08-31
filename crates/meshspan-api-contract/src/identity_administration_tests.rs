// SPDX-License-Identifier: GPL-2.0-only

use serde_json::json;

use crate::{
    BoundaryError, CreatePrincipalResponse, ListPrincipalsQuery, ListPrincipalsResponse,
    OperationId, PrincipalId, PrincipalKind, PrincipalState, PrincipalSummary,
    decode_create_group_request, decode_create_user_request, encode_create_principal_response,
    encode_list_principals_response, validate_list_principals_query_value,
};

#[test]
fn principal_creation_rejects_unknown_ambiguous_and_oversized_input()
-> Result<(), Box<dyn std::error::Error>> {
    let operation = "00000000-0000-4000-8000-000000000001";
    assert!(
        decode_create_user_request(&serde_json::to_vec(
            &json!({ "operation_id": operation, "display_name": "Alex" })
        )?)
        .is_ok()
    );
    for name in ["", " Alex", "Alex ", ".", "..", "a/b", "a\\b"] {
        assert!(
            decode_create_group_request(&serde_json::to_vec(&json!({
                "operation_id": operation,
                "display_name": name
            }))?)
            .is_err()
        );
    }
    assert!(matches!(
        decode_create_user_request(&serde_json::to_vec(&json!({
            "operation_id": operation,
            "display_name": "Alex",
            "unexpected": true
        }))?),
        Err(BoundaryError::Invalid { .. })
    ));
    assert!(matches!(
        decode_create_user_request(&vec![b' '; 2_049]),
        Err(BoundaryError::BodyTooLarge { limit: 2_048 })
    ));
    Ok(())
}

#[test]
fn principal_pages_and_receipts_validate_bounded_public_output()
-> Result<(), Box<dyn std::error::Error>> {
    let mut principal_bytes = [0x11; 16];
    principal_bytes[6] = 0x81;
    principal_bytes[8] = 0x81;
    let principal = PrincipalSummary {
        principal_id: PrincipalId::from_uuid_bytes(principal_bytes).ok_or("invalid principal")?,
        kind: PrincipalKind::User,
        display_name: "Alex".to_owned(),
        state: PrincipalState::Active,
        created_at_epoch_micros: 1,
        revision: 2,
    };
    let response = CreatePrincipalResponse {
        operation_id: OperationId::parse("22222222-2222-4222-8222-222222222222")
            .ok_or("invalid operation")?,
        principal: principal.clone(),
    };
    assert!(!encode_create_principal_response(&response)?.is_empty());
    let page = ListPrincipalsResponse {
        kind: PrincipalKind::User,
        principals: vec![principal],
        next_page_url: Some("/api/latest/admin/users?limit=1&cursor=v1.u.aa.bb".to_owned()),
    };
    assert!(!encode_list_principals_response(&page)?.is_empty());
    assert!(validate_list_principals_query_value(&json!({ "limit": 0 })).is_err());
    assert!(validate_list_principals_query_value(&json!({ "limit": 1 })).is_ok());
    let decoded: ListPrincipalsQuery = serde_json::from_value(json!({ "limit": 1 }))?;
    assert_eq!(decoded.limit, Some(1));
    Ok(())
}
