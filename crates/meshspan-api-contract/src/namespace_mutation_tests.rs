// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    BoundaryError, CreateDirectoryResponse, DeleteObjectResponse, DeleteObjectScope,
    DirectoryEntryKind, NamespaceCommitId, NamespacePath, ObjectId, ObjectRevisionId, OperationId,
    RenameObjectResponse, VolumeId, decode_create_directory_request, decode_delete_object_request,
    decode_rename_object_request, encode_create_directory_response, encode_delete_object_response,
    encode_rename_object_response,
};

#[test]
fn namespace_mutation_requests_reject_unknown_noncanonical_and_noop_input() {
    assert!(
        decode_create_directory_request(
            br#"{"operation_id":"01010101-0101-4101-8101-010101010101","path":"a/b"}"#
        )
        .is_ok()
    );
    assert!(
        decode_delete_object_request(
            br#"{"operation_id":"01010101-0101-4101-8101-010101010101","path":"a/b"}"#
        )
        .is_ok()
    );
    assert!(decode_rename_object_request(br#"{"operation_id":"01010101-0101-4101-8101-010101010101","source_path":"a","target_path":"b"}"#).is_ok());
    for hostile in [
        br#"{"operation_id":"01010101-0101-4101-8101-010101010101","path":"a/../b"}"#.as_slice(),
        br#"{"operation_id":"01010101-0101-4101-8101-010101010101","path":"a","extra":true}"#
            .as_slice(),
    ] {
        assert!(decode_create_directory_request(hostile).is_err());
    }
    assert!(matches!(
        decode_rename_object_request(br#"{"operation_id":"01010101-0101-4101-8101-010101010101","source_path":"same","target_path":"same"}"#),
        Err(BoundaryError::DecodeMismatch)
    ));
}

#[test]
fn namespace_mutation_receipts_are_exact_and_json_safe() -> Result<(), Box<dyn std::error::Error>> {
    let operation_id =
        OperationId::parse("01010101-0101-4101-8101-010101010101").ok_or("operation")?;
    let volume_id = VolumeId::from_uuid_bytes(versioned(2)).ok_or("volume")?;
    let object_id = ObjectId::from_uuid_bytes(versioned(3)).ok_or("object")?;
    let object_revision_id = ObjectRevisionId::from_uuid_bytes(versioned(4)).ok_or("revision")?;
    let namespace_commit_id = NamespaceCommitId::from_uuid_bytes(versioned(5)).ok_or("commit")?;
    let created = CreateDirectoryResponse {
        operation_id: operation_id.clone(),
        volume_id: volume_id.clone(),
        path: NamespacePath::from_decoded("created".to_owned()).ok_or("path")?,
        object_id: object_id.clone(),
        object_revision_id: object_revision_id.clone(),
        namespace_commit_id: namespace_commit_id.clone(),
        head_sequence: 1,
    };
    assert!(!encode_create_directory_response(&created)?.is_empty());
    let renamed = RenameObjectResponse {
        operation_id: operation_id.clone(),
        volume_id: volume_id.clone(),
        source_path: NamespacePath::from_decoded("created".to_owned()).ok_or("source")?,
        target_path: NamespacePath::from_decoded("renamed".to_owned()).ok_or("target")?,
        object_id: object_id.clone(),
        object_revision_id: object_revision_id.clone(),
        namespace_commit_id: namespace_commit_id.clone(),
        head_sequence: 2,
    };
    assert!(!encode_rename_object_response(&renamed)?.is_empty());
    let deleted = DeleteObjectResponse {
        operation_id,
        volume_id,
        path: NamespacePath::from_decoded("renamed".to_owned()).ok_or("path")?,
        object_id,
        object_revision_id,
        object_kind: DirectoryEntryKind::Directory,
        namespace_commit_id,
        head_sequence: 3,
        scope: DeleteObjectScope::BranchDeleted,
    };
    assert!(!encode_delete_object_response(&deleted)?.is_empty());
    let mut unsafe_sequence = deleted;
    unsafe_sequence.head_sequence = 9_007_199_254_740_992;
    assert!(encode_delete_object_response(&unsafe_sequence).is_err());
    Ok(())
}

const fn versioned(seed: u8) -> [u8; 16] {
    let mut bytes = [seed; 16];
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}
