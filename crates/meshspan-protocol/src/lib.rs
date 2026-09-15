// SPDX-License-Identifier: GPL-2.0-only

//! Generated private wire messages plus strict bounded framing and validation.

mod consensus_bulk;
mod federation_backup_discovery;
mod federation_backup_signing;
mod federation_signing;
mod framing;
mod metadata_replica;
mod node_capability;
mod validation;

pub use consensus_bulk::{
    MAXIMUM_CONSENSUS_BULK_BODY_BYTES, MAXIMUM_CONSENSUS_BULK_ENTRIES,
    MAXIMUM_CONSENSUS_COMMAND_BYTES, ValidatedConsensusBulk, consensus_transfer_support,
    decode_consensus_bulk, encode_consensus_bulk_entries,
};

pub use federation_backup_discovery::{
    decode_backup_allocation_cursor, encode_backup_allocation_cursor,
};
pub use federation_backup_signing::{
    federation_backup_allocation_request_digest_payload, federation_backup_request_digest_payload,
    federation_backup_signing_payload,
};
pub use federation_signing::{
    federation_authority_fetch_signing_payload, federation_authority_page_digest_payload,
    federation_authority_page_signing_payload, federation_branch_fetch_signing_payload,
    federation_branch_page_digest_payload, federation_branch_page_signing_payload,
    federation_content_layout_fetch_signing_payload, federation_content_layout_page_digest_payload,
    federation_content_layout_page_signing_payload, federation_content_shard_fetch_signing_payload,
    federation_content_shard_header_signing_payload, federation_hello_signing_payload,
    federation_history_object_fetch_signing_payload,
    federation_history_object_header_signing_payload, federation_storage_capability_digest_payload,
    federation_storage_capability_request_digest_payload,
    federation_storage_capability_request_signing_payload,
    federation_storage_capability_signing_payload,
    federation_storage_inventory_fetch_signing_payload,
    federation_storage_inventory_page_digest_payload,
    federation_storage_inventory_page_signing_payload, federation_storage_receipt_signing_payload,
    federation_welcome_signing_payload,
};
pub use framing::{
    ValidatedControlEnvelope, ValidatedDataControlEnvelope, ValidatedDataFrame,
    ValidatedFederationEnvelope, WireContractError, WireLimits, decode_control_frame,
    decode_data_control_frame, decode_data_frame, decode_federation_frame, encode_control_frame,
    encode_data_control_frame, encode_data_frame, encode_federation_frame,
};
pub use meshspan_protobuf::EncodeError as ProtocolEncodeError;
pub use metadata_replica::{
    MAXIMUM_METADATA_REPLICA_BODY_BYTES, MAXIMUM_METADATA_REPLICA_COMMAND_BYTES,
    MAXIMUM_METADATA_REPLICA_ENTRIES, decode_metadata_replica_body, encode_metadata_replica_body,
};
pub use node_capability::node_capability_digest;

/// Generated version-one private wire messages.
#[allow(
    missing_docs,
    clippy::cognitive_complexity,
    clippy::doc_markdown,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/meshspan.private.v1.rs"));
}
