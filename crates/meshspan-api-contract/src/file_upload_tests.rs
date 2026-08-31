// SPDX-License-Identifier: GPL-2.0-only

use serde_json::json;

use crate::{
    BoundaryError, FileVersionId, NamespacePath, ObjectId, UploadId, UploadState,
    UploadStatusResponse, VolumeId, decode_begin_upload_request, decode_commit_upload_request,
    encode_upload_status_response,
};

#[test]
fn begin_upload_rejects_unknown_noncanonical_and_incoherent_dispositions()
-> Result<(), Box<dyn std::error::Error>> {
    let base = json!({
        "operation_id": "01010101-0101-4101-8101-010101010101",
        "path": "reports/result.bin",
        "disposition": { "mode": "create_new" },
        "maximum_bytes": 1024
    });
    let bytes = serde_json::to_vec(&base)?;
    assert_eq!(
        decode_begin_upload_request(&bytes)?.path.as_str(),
        "reports/result.bin"
    );

    let mut invalid = base.clone();
    invalid["path"] = json!("reports//result.bin");
    assert!(matches!(
        decode_begin_upload_request(&serde_json::to_vec(&invalid)?),
        Err(BoundaryError::DecodeMismatch)
    ));
    invalid = base.clone();
    invalid["unexpected"] = json!(true);
    assert!(decode_begin_upload_request(&serde_json::to_vec(&invalid)?).is_err());
    invalid = base;
    invalid["disposition"] = json!({ "mode": "replace_if_version" });
    assert!(decode_begin_upload_request(&serde_json::to_vec(&invalid)?).is_err());
    Ok(())
}

#[test]
fn commit_upload_bounds_digest_and_rejects_unknown_input() -> Result<(), Box<dyn std::error::Error>>
{
    let valid = json!({
        "operation_id": "02020202-0202-4202-8202-020202020202",
        "stage_fence": 1,
        "expected_sequence": 20,
        "final_length": 4096,
        "sparse": false,
        "expected_blake3": null
    });
    assert_eq!(
        decode_commit_upload_request(&serde_json::to_vec(&valid)?)?.final_length,
        4096
    );
    let mut invalid = valid.clone();
    invalid["expected_blake3"] = json!("00");
    assert!(decode_commit_upload_request(&serde_json::to_vec(&invalid)?).is_err());
    invalid = valid;
    invalid["final_length"] = json!(9_007_199_254_740_992_u64);
    assert!(decode_commit_upload_request(&serde_json::to_vec(&invalid)?).is_err());
    Ok(())
}

#[test]
fn outgoing_status_requires_exact_committed_identity_pair() -> Result<(), Box<dyn std::error::Error>>
{
    let mut response = status(UploadState::Active)?;
    assert!(encode_upload_status_response(&response).is_ok());
    response.committed_object_id = Some(ObjectId::from_uuid_bytes(versioned(3)).ok_or("object")?);
    assert!(matches!(
        encode_upload_status_response(&response),
        Err(BoundaryError::EncodeMismatch)
    ));
    response.state = UploadState::Committed;
    response.committed_version_id =
        Some(FileVersionId::from_uuid_bytes(versioned(4)).ok_or("version")?);
    assert!(encode_upload_status_response(&response).is_ok());
    Ok(())
}

fn status(state: UploadState) -> Result<UploadStatusResponse, Box<dyn std::error::Error>> {
    Ok(UploadStatusResponse {
        upload_id: UploadId::from_uuid_bytes(versioned(1)).ok_or("upload")?,
        volume_id: VolumeId::from_uuid_bytes(versioned(2)).ok_or("volume")?,
        path: NamespacePath::from_decoded("result.bin".to_owned()).ok_or("path")?,
        state,
        stage_fence: 1,
        maximum_bytes: 1_024,
        checkpoint_sequence: 0,
        logical_extent: 0,
        expires_at_epoch_micros: 1_000_000,
        committed_object_id: None,
        committed_version_id: None,
        ranges_url: "/api/latest/uploads/one/ranges".to_owned(),
    })
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
