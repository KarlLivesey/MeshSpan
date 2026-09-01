// SPDX-License-Identifier: GPL-2.0-only

use serde_json::json;

use crate::{
    CreateVolumeResponse, ListVolumesResponse, NamespaceRight, ObjectId, OperationId, PrincipalId,
    VolumeId, VolumeState, VolumeSummary, decode_create_volume_request,
    encode_create_volume_response, encode_list_volumes_response, validate_list_volumes_query_value,
};

#[test]
fn volume_creation_rejects_unknown_empty_and_invalid_owner_sets()
-> Result<(), Box<dyn std::error::Error>> {
    let operation_id = uuid_text(versioned(2));
    let owner_id = uuid_text(versioned(3));
    let valid = json!({
        "operation_id": operation_id,
        "name": "Shared files",
        "owner_principal_ids": [owner_id]
    });
    assert!(decode_create_volume_request(&serde_json::to_vec(&valid)?).is_ok());
    for value in [
        json!({ "operation_id": operation_id, "name": "Shared files", "owner_principal_ids": [] }),
        json!({ "operation_id": operation_id, "name": " ../bad ", "owner_principal_ids": [owner_id] }),
        json!({ "operation_id": operation_id, "name": "Shared files", "owner_principal_ids": [owner_id], "unknown": true }),
    ] {
        assert!(decode_create_volume_request(&serde_json::to_vec(&value)?).is_err());
    }
    Ok(())
}

#[test]
fn volume_creation_response_is_validated_before_emission() -> Result<(), Box<dyn std::error::Error>>
{
    let response = CreateVolumeResponse {
        operation_id: OperationId::parse(&uuid_text(versioned(4))).ok_or("operation")?,
        volume_id: VolumeId::from_uuid_bytes(versioned(1)).ok_or("volume")?,
        root_object_id: ObjectId::from_uuid_bytes(versioned(5)).ok_or("root")?,
        name: "Shared files".to_owned(),
        owner_principal_ids: vec![PrincipalId::from_uuid_bytes(versioned(3)).ok_or("principal")?],
        created_at_epoch_micros: 10,
        revision: 1,
    };
    assert!(encode_create_volume_response(&response).is_ok());
    Ok(())
}

#[test]
fn volume_query_rejects_unknown_and_ambiguous_bounds() {
    for value in [
        json!({ "limit": 0 }),
        json!({ "limit": 257 }),
        json!({ "cursor": "bad cursor" }),
        json!({ "unknown": true }),
    ] {
        assert!(validate_list_volumes_query_value(&value).is_err());
    }
}

#[test]
fn response_requires_ordered_unique_browse_rights() -> Result<(), Box<dyn std::error::Error>> {
    let mut response = valid_response()?;
    assert!(encode_list_volumes_response(&response).is_ok());

    response.volumes[0].effective_rights = vec![NamespaceRight::List, NamespaceRight::Traverse];
    assert!(encode_list_volumes_response(&response).is_err());
    response.volumes[0].effective_rights = vec![NamespaceRight::Traverse, NamespaceRight::Traverse];
    assert!(encode_list_volumes_response(&response).is_err());
    Ok(())
}

fn valid_response() -> Result<ListVolumesResponse, Box<dyn std::error::Error>> {
    Ok(ListVolumesResponse {
        volumes: vec![VolumeSummary {
            volume_id: VolumeId::from_uuid_bytes(versioned(1)).ok_or("invalid volume")?,
            name: "Shared files".to_owned(),
            state: VolumeState::Active,
            effective_rights: vec![
                NamespaceRight::Traverse,
                NamespaceRight::List,
                NamespaceRight::ReadData,
            ],
            created_at_epoch_micros: 10,
            revision: 1,
        }],
        next_page_url: Some("/api/latest/volumes?limit=1&cursor=v1.vol.proof".to_owned()),
    })
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x40;
    value[8] = 0x80;
    value
}

fn uuid_text(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
