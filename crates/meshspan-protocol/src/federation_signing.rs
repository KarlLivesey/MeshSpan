// SPDX-License-Identifier: GPL-2.0-only

//! Canonical domain-separated bytes for signed federation negotiation messages.

use prost::Message;

use crate::v1::{
    FederatedBranchPage, FederationAuthorityPage, FederationHeader, FederationHello,
    FederationWelcome, FetchFederatedBranchPage, FetchFederatedStorageInventory,
    FetchFederationAuthority, RequestFederatedStorageCapability,
};

const HELLO_DOMAIN: &[u8] = b"meshspan.federation.hello.v1\0";
const WELCOME_DOMAIN: &[u8] = b"meshspan.federation.welcome.v1\0";
const AUTHORITY_PAGE_DOMAIN: &[u8] = b"meshspan.federation.authority-page.v1\0";
const AUTHORITY_PAGE_DIGEST_DOMAIN: &[u8] = b"meshspan.federation.authority-page-digest.v1\0";
const AUTHORITY_FETCH_DOMAIN: &[u8] = b"meshspan.federation.authority-fetch.v1\0";
const BRANCH_FETCH_DOMAIN: &[u8] = b"meshspan.federation.branch-fetch.v1\0";
const BRANCH_PAGE_DOMAIN: &[u8] = b"meshspan.federation.branch-page.v1\0";
const BRANCH_PAGE_DIGEST_DOMAIN: &[u8] = b"meshspan.federation.branch-page-digest.v1\0";
const STORAGE_CAPABILITY_REQUEST_DOMAIN: &[u8] =
    b"meshspan.federation.storage-capability-request.v1\0";
const STORAGE_INVENTORY_FETCH_DOMAIN: &[u8] = b"meshspan.federation.storage-inventory-fetch.v1\0";

/// Returns the exact bytes signed by a federation hello identity.
#[must_use]
pub fn federation_hello_signing_payload(
    header: &FederationHeader,
    hello: &FederationHello,
) -> Vec<u8> {
    let mut unsigned = hello.clone();
    unsigned.signature.clear();
    signing_payload(HELLO_DOMAIN, header, &unsigned)
}

/// Returns the exact bytes signed by a federation welcome identity.
#[must_use]
pub fn federation_welcome_signing_payload(
    header: &FederationHeader,
    welcome: &FederationWelcome,
) -> Vec<u8> {
    let mut unsigned = welcome.clone();
    unsigned.signature.clear();
    signing_payload(WELCOME_DOMAIN, header, &unsigned)
}

/// Returns the exact bytes signed by a federation authority page identity.
#[must_use]
pub fn federation_authority_page_signing_payload(
    header: &FederationHeader,
    page: &FederationAuthorityPage,
) -> Vec<u8> {
    let mut unsigned = page.clone();
    unsigned.signature.clear();
    signing_payload(AUTHORITY_PAGE_DOMAIN, header, &unsigned)
}

/// Returns canonical domain-separated page content for the embedded digest.
#[must_use]
pub fn federation_authority_page_digest_payload(page: &FederationAuthorityPage) -> Vec<u8> {
    let mut unsigned = page.clone();
    unsigned.page_digest.clear();
    unsigned.signature.clear();
    let encoded = unsigned.encode_to_vec();
    let mut payload = Vec::with_capacity(
        AUTHORITY_PAGE_DIGEST_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(encoded.len()),
    );
    payload.extend_from_slice(AUTHORITY_PAGE_DIGEST_DOMAIN);
    append_part(&mut payload, &encoded);
    payload
}

/// Returns the exact bytes signed by an authority fetch identity.
#[must_use]
pub fn federation_authority_fetch_signing_payload(
    header: &FederationHeader,
    request: &FetchFederationAuthority,
) -> Vec<u8> {
    let mut unsigned = request.clone();
    unsigned.signature.clear();
    signing_payload(AUTHORITY_FETCH_DOMAIN, header, &unsigned)
}

/// Returns the exact bytes signed by a federated branch-page fetch identity.
#[must_use]
pub fn federation_branch_fetch_signing_payload(
    header: &FederationHeader,
    request: &FetchFederatedBranchPage,
) -> Vec<u8> {
    let mut unsigned = request.clone();
    unsigned.signature.clear();
    signing_payload(BRANCH_FETCH_DOMAIN, header, &unsigned)
}

/// Returns the exact bytes signed by a federated branch-page identity.
#[must_use]
pub fn federation_branch_page_signing_payload(
    header: &FederationHeader,
    page: &FederatedBranchPage,
) -> Vec<u8> {
    let mut unsigned = page.clone();
    unsigned.signature.clear();
    signing_payload(BRANCH_PAGE_DOMAIN, header, &unsigned)
}

/// Returns canonical domain-separated branch-page content for the embedded digest.
#[must_use]
pub fn federation_branch_page_digest_payload(page: &FederatedBranchPage) -> Vec<u8> {
    let mut unsigned = page.clone();
    unsigned.page_digest.clear();
    unsigned.signature.clear();
    let encoded = unsigned.encode_to_vec();
    let mut payload = Vec::with_capacity(
        BRANCH_PAGE_DIGEST_DOMAIN
            .len()
            .saturating_add(8)
            .saturating_add(encoded.len()),
    );
    payload.extend_from_slice(BRANCH_PAGE_DIGEST_DOMAIN);
    append_part(&mut payload, &encoded);
    payload
}

/// Returns the exact bytes signed by a remote-storage capability requester.
#[must_use]
pub fn federation_storage_capability_request_signing_payload(
    header: &FederationHeader,
    request: &RequestFederatedStorageCapability,
) -> Vec<u8> {
    let mut unsigned = request.clone();
    unsigned.signature.clear();
    signing_payload(STORAGE_CAPABILITY_REQUEST_DOMAIN, header, &unsigned)
}

/// Returns the exact bytes signed by a remote-storage inventory fetch identity.
#[must_use]
pub fn federation_storage_inventory_fetch_signing_payload(
    header: &FederationHeader,
    request: &FetchFederatedStorageInventory,
) -> Vec<u8> {
    let mut unsigned = request.clone();
    unsigned.signature.clear();
    signing_payload(STORAGE_INVENTORY_FETCH_DOMAIN, header, &unsigned)
}

fn signing_payload(domain: &[u8], header: &FederationHeader, message: &impl Message) -> Vec<u8> {
    let header = header.encode_to_vec();
    let message = message.encode_to_vec();
    let mut payload = Vec::with_capacity(
        domain
            .len()
            .saturating_add(16)
            .saturating_add(header.len())
            .saturating_add(message.len()),
    );
    payload.extend_from_slice(domain);
    append_part(&mut payload, &header);
    append_part(&mut payload, &message);
    payload
}

fn append_part(payload: &mut Vec<u8>, part: &[u8]) {
    payload.extend_from_slice(&u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
    payload.extend_from_slice(part);
}

#[cfg(test)]
mod tests {
    use crate::v1::{
        FederatedBranchPage, FederationAuthorityPage, FederationHeader, FederationHello,
        ProtocolVersion, VersionedPayload,
    };

    use super::{
        federation_authority_page_digest_payload, federation_authority_page_signing_payload,
        federation_branch_page_digest_payload, federation_branch_page_signing_payload,
        federation_hello_signing_payload,
    };

    #[test]
    fn hello_signature_excludes_only_its_signature_and_binds_the_header() {
        let header = FederationHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            relationship_id: vec![1; 16],
            sender_mesh_id: vec![2; 16],
            recipient_mesh_id: vec![3; 16],
            request_id: vec![4; 16],
            operation_id: vec![5; 16],
            authority_epoch: 1,
            deadline_unix_micros: 10,
            trace_id: vec![6; 16],
            replay_nonce: vec![7; 32],
        };
        let mut hello = FederationHello {
            versions: vec![ProtocolVersion { major: 1, minor: 0 }],
            identity_generation: 1,
            public_identity_chain: vec![8],
            challenge_nonce: vec![9; 32],
            feature_bits: vec![1],
            maximum_control_bytes: 1,
            maximum_data_frame_bytes: 1,
            maximum_streams: 1,
            signature: vec![10; 64],
        };
        let original = federation_hello_signing_payload(&header, &hello);
        hello.signature = vec![11; 64];
        assert_eq!(federation_hello_signing_payload(&header, &hello), original);
        hello.maximum_streams = 2;
        assert_ne!(federation_hello_signing_payload(&header, &hello), original);
        let mut changed_header = header;
        changed_header.authority_epoch = 2;
        assert_ne!(
            federation_hello_signing_payload(&changed_header, &hello),
            original
        );
    }

    #[test]
    fn authority_page_digest_and_signature_cover_distinct_exact_fields() {
        let header = FederationHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            relationship_id: vec![1; 16],
            sender_mesh_id: vec![2; 16],
            recipient_mesh_id: vec![3; 16],
            request_id: vec![4; 16],
            operation_id: vec![5; 16],
            authority_epoch: 1,
            deadline_unix_micros: 10,
            trace_id: vec![6; 16],
            replay_nonce: vec![7; 32],
        };
        let mut page = FederationAuthorityPage {
            authority_revision: 8,
            records: vec![VersionedPayload {
                format_version: 1,
                canonical_bytes: vec![9],
            }],
            next_cursor: vec![10],
            page_digest: vec![11; 32],
            signature: vec![12; 64],
        };
        let digest_payload = federation_authority_page_digest_payload(&page);
        let signing_payload = federation_authority_page_signing_payload(&header, &page);
        page.signature = vec![13; 64];
        assert_eq!(
            federation_authority_page_digest_payload(&page),
            digest_payload
        );
        assert_eq!(
            federation_authority_page_signing_payload(&header, &page),
            signing_payload
        );
        page.page_digest = vec![14; 32];
        assert_eq!(
            federation_authority_page_digest_payload(&page),
            digest_payload
        );
        assert_ne!(
            federation_authority_page_signing_payload(&header, &page),
            signing_payload
        );
        page.records[0].canonical_bytes[0] ^= 1;
        assert_ne!(
            federation_authority_page_digest_payload(&page),
            digest_payload
        );
    }

    #[test]
    fn branch_page_digest_and_signature_bind_every_page_field() {
        let header = FederationHeader {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            relationship_id: vec![1; 16],
            sender_mesh_id: vec![2; 16],
            recipient_mesh_id: vec![3; 16],
            request_id: vec![4; 16],
            operation_id: vec![5; 16],
            authority_epoch: 1,
            deadline_unix_micros: 10,
            trace_id: vec![6; 16],
            replay_nonce: vec![7; 32],
        };
        let mut page = FederatedBranchPage {
            grant_id: vec![8; 16],
            resource_scope: Some(VersionedPayload {
                format_version: 1,
                canonical_bytes: vec![9],
            }),
            branch_commits: vec![VersionedPayload {
                format_version: 1,
                canonical_bytes: vec![10],
            }],
            immutable_object_digests: vec![vec![11; 32]],
            next_cursor: vec![12],
            page_digest: vec![13; 32],
            signature: vec![14; 64],
            export_token: vec![15; 32],
        };
        let digest = federation_branch_page_digest_payload(&page);
        let signature = federation_branch_page_signing_payload(&header, &page);
        page.signature = vec![15; 64];
        assert_eq!(federation_branch_page_digest_payload(&page), digest);
        assert_eq!(
            federation_branch_page_signing_payload(&header, &page),
            signature
        );
        page.page_digest = vec![16; 32];
        assert_eq!(federation_branch_page_digest_payload(&page), digest);
        assert_ne!(
            federation_branch_page_signing_payload(&header, &page),
            signature
        );
        page.immutable_object_digests[0][0] ^= 1;
        assert_ne!(federation_branch_page_digest_payload(&page), digest);
        page.immutable_object_digests[0][0] ^= 1;
        page.export_token[0] ^= 1;
        assert_ne!(federation_branch_page_digest_payload(&page), digest);
    }
}
