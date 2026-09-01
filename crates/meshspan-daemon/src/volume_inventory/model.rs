// SPDX-License-Identifier: GPL-2.0-only

//! Cursor and strict public projection for permission-filtered volumes.

use meshspan_api_contract::{
    ListVolumesResponse, NamespaceRight, VolumeCursor as ApiCursor, VolumeId as ApiVolumeId,
    VolumeState as ApiState, VolumeSummary,
};
use meshspan_domain::{Rights, VolumeId};
use meshspan_metadata::{VolumeInventoryCursor, VolumeInventoryRecord};

use super::VolumeInventoryError;

pub(super) fn decode_cursor(
    cursor: &ApiCursor,
) -> Result<VolumeInventoryCursor, VolumeInventoryError> {
    let fields = cursor.as_str().split('.').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != "v1" || fields[1] != "vol" {
        return Err(VolumeInventoryError::InvalidRequest);
    }
    let canonical_name = decode_text(fields[2])?;
    let volume_id = VolumeId::from_bytes(decode_array(fields[3])?)
        .map_err(|_| VolumeInventoryError::InvalidRequest)?;
    Ok(VolumeInventoryCursor::new(canonical_name, volume_id))
}

pub(super) fn list_response(
    limit: u16,
    mut visible: Vec<(VolumeInventoryRecord, Rights)>,
) -> Result<ListVolumesResponse, VolumeInventoryError> {
    let next = (visible.len() > usize::from(limit)).then(|| {
        let record = &visible[usize::from(limit) - 1].0;
        next_page_url(limit, record)
    });
    visible.truncate(usize::from(limit));
    let volumes = visible
        .into_iter()
        .map(|(record, rights)| public_volume(record, rights))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ListVolumesResponse {
        volumes,
        next_page_url: next.transpose()?,
    })
}

fn public_volume(
    record: VolumeInventoryRecord,
    rights: Rights,
) -> Result<VolumeSummary, VolumeInventoryError> {
    if record.display_name.is_empty()
        || record.display_name.len() > 256
        || record.display_name.chars().any(char::is_control)
        || !(0..=9_007_199_254_740_991).contains(&record.created_at.get())
        || record.revision.get() == 0
        || record.revision.get() > 9_007_199_254_740_991
    {
        return Err(VolumeInventoryError::Failed);
    }
    Ok(VolumeSummary {
        volume_id: ApiVolumeId::from_uuid_bytes(record.volume_id.as_bytes())
            .ok_or(VolumeInventoryError::Failed)?,
        name: record.display_name,
        state: public_state(record.state)?,
        effective_rights: public_rights(rights),
        created_at_epoch_micros: record.created_at.get(),
        revision: record.revision.get(),
    })
}

fn public_rights(rights: Rights) -> Vec<NamespaceRight> {
    let definitions = [
        (Rights::TRAVERSE, NamespaceRight::Traverse),
        (Rights::LIST, NamespaceRight::List),
        (Rights::READ_DATA, NamespaceRight::ReadData),
        (Rights::CREATE_CHILD, NamespaceRight::CreateChild),
        (Rights::WRITE_DATA, NamespaceRight::WriteData),
        (Rights::APPEND_DATA, NamespaceRight::AppendData),
        (Rights::RENAME, NamespaceRight::Rename),
        (Rights::DELETE, NamespaceRight::Delete),
        (Rights::READ_ATTRIBUTES, NamespaceRight::ReadAttributes),
        (Rights::WRITE_ATTRIBUTES, NamespaceRight::WriteAttributes),
        (Rights::READ_PERMISSIONS, NamespaceRight::ReadPermissions),
        (
            Rights::CHANGE_PERMISSIONS,
            NamespaceRight::ChangePermissions,
        ),
        (Rights::CHANGE_OWNER, NamespaceRight::ChangeOwner),
    ];
    definitions
        .into_iter()
        .filter_map(|(required, public)| rights.contains(required).then_some(public))
        .collect()
}

const fn public_state(state: u8) -> Result<ApiState, VolumeInventoryError> {
    match state {
        1 => Ok(ApiState::Active),
        2 => Ok(ApiState::Suspended),
        3 => Ok(ApiState::Draining),
        4 => Ok(ApiState::Retired),
        _ => Err(VolumeInventoryError::Failed),
    }
}

fn next_page_url(
    limit: u16,
    record: &VolumeInventoryRecord,
) -> Result<String, VolumeInventoryError> {
    let cursor = format!(
        "v1.vol.{}.{}",
        encode_hex(record.canonical_name.as_bytes()),
        encode_hex(&record.volume_id.as_bytes())
    );
    let url = format!("/api/latest/volumes?limit={limit}&cursor={cursor}");
    (url.len() <= 16_384)
        .then_some(url)
        .ok_or(VolumeInventoryError::Failed)
}

fn encode_hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        use std::fmt::Write;
        let _ignored = write!(output, "{byte:02x}");
    }
    output
}

fn decode_text(value: &str) -> Result<String, VolumeInventoryError> {
    if value.is_empty() || value.len() > 512 || !value.len().is_multiple_of(2) {
        return Err(VolumeInventoryError::InvalidRequest);
    }
    let bytes = decode_bytes(value)?;
    let text = String::from_utf8(bytes).map_err(|_| VolumeInventoryError::InvalidRequest)?;
    if text.is_empty() || text.len() > 256 {
        return Err(VolumeInventoryError::InvalidRequest);
    }
    Ok(text)
}

fn decode_array(value: &str) -> Result<[u8; 16], VolumeInventoryError> {
    decode_bytes(value)?
        .try_into()
        .map_err(|_| VolumeInventoryError::InvalidRequest)
}

fn decode_bytes(value: &str) -> Result<Vec<u8>, VolumeInventoryError> {
    if !value.len().is_multiple_of(2) {
        return Err(VolumeInventoryError::InvalidRequest);
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(VolumeInventoryError::InvalidRequest);
    }
    pairs
        .iter()
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).map_err(|_| VolumeInventoryError::InvalidRequest)?;
            u8::from_str_radix(text, 16).map_err(|_| VolumeInventoryError::InvalidRequest)
        })
        .collect()
}
