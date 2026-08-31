// SPDX-License-Identifier: GPL-2.0-only

use serde_json::json;

use crate::{
    ListVolumesResponse, NamespaceRight, VolumeId, VolumeState, VolumeSummary,
    encode_list_volumes_response, validate_list_volumes_query_value,
};

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
