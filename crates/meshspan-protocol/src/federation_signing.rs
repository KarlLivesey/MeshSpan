// SPDX-License-Identifier: GPL-2.0-only

//! Canonical domain-separated bytes for signed federation negotiation messages.

use prost::Message;

use crate::v1::{FederationAuthorityPage, FederationHeader, FederationHello, FederationWelcome};

const HELLO_DOMAIN: &[u8] = b"meshspan.federation.hello.v1\0";
const WELCOME_DOMAIN: &[u8] = b"meshspan.federation.welcome.v1\0";
const AUTHORITY_PAGE_DOMAIN: &[u8] = b"meshspan.federation.authority-page.v1\0";
const AUTHORITY_PAGE_DIGEST_DOMAIN: &[u8] = b"meshspan.federation.authority-page-digest.v1\0";

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
        FederationAuthorityPage, FederationHeader, FederationHello, ProtocolVersion,
        VersionedPayload,
    };

    use super::{
        federation_authority_page_digest_payload, federation_authority_page_signing_payload,
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
}
