// SPDX-License-Identifier: GPL-2.0-only

use serde_json::json;

use crate::{
    AddGroupMemberResponse, BoundaryError, GroupMembershipSummary, ListGroupMembershipsQuery,
    ListGroupMembershipsResponse, NullableField, OperationId, PrincipalId, PrincipalKind,
    PrincipalState, PrincipalSummary, RemoveGroupMemberResponse, decode_add_group_member_request,
    decode_remove_group_member_request, encode_add_group_member_response,
    encode_list_group_memberships_response, encode_remove_group_member_response,
    validate_list_group_memberships_query,
};

const OPERATION_ID: &str = "22222222-2222-4222-8222-222222222222";
const MEMBER_ID: &str = "33333333-3333-4333-8333-333333333333";

#[test]
fn addition_distinguishes_missing_null_and_exact_windows() -> Result<(), Box<dyn std::error::Error>>
{
    let missing = decode_add_group_member_request(&serde_json::to_vec(&json!({
        "operation_id": OPERATION_ID,
        "member_principal_id": MEMBER_ID,
        "activation_required": true
    }))?)?;
    assert_eq!(missing.valid_from_epoch_micros, NullableField::Missing);

    let null = decode_add_group_member_request(&serde_json::to_vec(&json!({
        "operation_id": OPERATION_ID,
        "member_principal_id": MEMBER_ID,
        "valid_from_epoch_micros": null,
        "valid_until_epoch_micros": null,
        "activation_required": false
    }))?)?;
    assert_eq!(null.valid_from_epoch_micros, NullableField::Null);

    assert!(
        decode_add_group_member_request(&serde_json::to_vec(&json!({
            "operation_id": OPERATION_ID,
            "member_principal_id": MEMBER_ID,
            "valid_from_epoch_micros": 20,
            "valid_until_epoch_micros": 20,
            "activation_required": false
        }))?)
        .is_err()
    );
    Ok(())
}

#[test]
fn mutations_reject_unknown_blank_and_oversized_input() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        decode_add_group_member_request(&serde_json::to_vec(&json!({
            "operation_id": OPERATION_ID,
            "member_principal_id": MEMBER_ID,
            "activation_required": false,
            "unexpected": true
        }))?),
        Err(BoundaryError::Invalid { .. })
    ));
    for reason in ["", " leading", "trailing "] {
        assert!(
            decode_remove_group_member_request(&serde_json::to_vec(&json!({
                "operation_id": OPERATION_ID,
                "reason": reason
            }))?)
            .is_err()
        );
    }
    assert!(matches!(
        decode_remove_group_member_request(&vec![b' '; 4_097]),
        Err(BoundaryError::BodyTooLarge { limit: 4_096 })
    ));
    Ok(())
}

#[test]
fn pages_and_durable_results_validate_authoritative_output()
-> Result<(), Box<dyn std::error::Error>> {
    let operation_id = OperationId::parse(OPERATION_ID).ok_or("invalid operation")?;
    let group_id = principal_id(0x11).ok_or("invalid group")?;
    let member_id = principal_id(0x33).ok_or("invalid member")?;
    let membership = membership(group_id.clone(), member_id.clone());

    assert!(
        !encode_add_group_member_response(&AddGroupMemberResponse {
            operation_id: operation_id.clone(),
            membership: membership.clone(),
        })?
        .is_empty()
    );
    assert!(
        !encode_remove_group_member_response(&RemoveGroupMemberResponse {
            operation_id,
            group_id: group_id.clone(),
            member_principal_id: member_id,
            removed_at_epoch_micros: 30,
            revision: 4,
        })?
        .is_empty()
    );
    assert!(!encode_list_group_memberships_response(&ListGroupMembershipsResponse {
        group_id,
        memberships: vec![membership],
        next_page_url: Some(
            "/api/latest/admin/groups/11111111-1111-4111-8111-111111111111/members?limit=1&cursor=v1.gm.aa".to_owned(),
        ),
    })?.is_empty());
    assert!(
        validate_list_group_memberships_query(&ListGroupMembershipsQuery {
            cursor: None,
            limit: Some(0),
        })
        .is_err()
    );
    Ok(())
}

fn principal_id(seed: u8) -> Option<PrincipalId> {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    PrincipalId::from_uuid_bytes(bytes)
}

fn membership(group_id: PrincipalId, member_id: PrincipalId) -> GroupMembershipSummary {
    GroupMembershipSummary {
        group_id: group_id.clone(),
        member: PrincipalSummary {
            principal_id: member_id,
            kind: PrincipalKind::User,
            display_name: "Alex".to_owned(),
            state: PrincipalState::Active,
            created_at_epoch_micros: 1,
            revision: 2,
        },
        valid_from_epoch_micros: None,
        valid_until_epoch_micros: Some(100),
        activation_required: true,
        created_by: group_id,
        created_at_epoch_micros: 10,
        revision: 3,
    }
}
