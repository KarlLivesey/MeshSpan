// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use meshspan_domain::UnixMicros;
use meshspan_protocol::WireLimits;
use meshspan_protocol::v1::{
    FederatedStorageInventoryPage, FetchFederatedStorageInventory, VersionedPayload,
};

use crate::{
    FederationExchangeContext, FederationLocalIdentity, FederationPeerRegistry, TransportError,
    signed_federation_storage_inventory_fetch, signed_federation_storage_inventory_page,
};

use super::super::{AuthorityPageProof, validated_federation};
use super::{exchange_context, federation_replay};

pub(super) fn prove_signed_storage_inventory_fetch(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    identity: &FederationLocalIdentity<'_>,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let context = exchange_context(121, 122, 123, 124)?;
    let outbound = signed_federation_storage_inventory_fetch(
        identity,
        context,
        inventory_fetch(),
        limits,
        UnixMicros::new(1_500_000),
    )?;
    let validated = validated_federation(outbound.envelope(), limits)?;
    let mut replay = federation_replay()?;
    let authenticated = registry.authenticate_storage_inventory_fetch(
        connection,
        &validated,
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(authenticated.request().cursor, vec![125; 16]);
    assert_eq!(authenticated.request().limit, 1);
    assert_eq!(
        authenticated.response_context([126; 32])?.request_id,
        [121; 16]
    );
    reject_tampered_fetch(registry, connection, outbound.envelope(), limits)?;
    assert!(matches!(
        registry.authenticate_storage_inventory_fetch(
            connection,
            &validated,
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    Ok(())
}

pub(super) fn prove_storage_inventory_page(
    proof: &AuthorityPageProof<'_>,
    client_identity: &FederationLocalIdentity<'_>,
) -> Result<(), Box<dyn Error>> {
    let request_context = exchange_context(131, 132, 133, 134)?;
    let fetch = signed_federation_storage_inventory_fetch(
        client_identity,
        request_context,
        inventory_fetch(),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    let response_context = correlated_context(request_context, [135; 32])?;
    let signed = signed_federation_storage_inventory_page(
        proof.server_identity,
        response_context,
        inventory_page(1),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    let validated = validated_federation(signed.envelope(), proof.limits)?;
    let mut replay = federation_replay()?;
    let page = proof.registry.authenticate_storage_inventory_page(
        proof.connection,
        &validated,
        fetch.expectation(),
        UnixMicros::new(1_500_000),
        &mut replay,
    )?;
    assert_eq!(page.records().len(), 1);
    assert_eq!(page.next_cursor(), &[136; 16]);
    assert!(matches!(
        proof.registry.authenticate_storage_inventory_page(
            proof.connection,
            &validated,
            fetch.expectation(),
            UnixMicros::new(1_500_001),
            &mut replay,
        ),
        Err(TransportError::ReplayedFederationMessage)
    ));
    prove_hostile_inventory_pages(
        proof,
        fetch.expectation(),
        response_context,
        request_context,
    )
}

fn prove_hostile_inventory_pages(
    proof: &AuthorityPageProof<'_>,
    expectation: &crate::FederationStorageInventoryPageExpectation,
    response_context: FederationExchangeContext,
    request_context: FederationExchangeContext,
) -> Result<(), Box<dyn Error>> {
    let mut wrong_target = inventory_page(1);
    wrong_target.target_id[0] ^= 1;
    for hostile in [wrong_target, inventory_page(2)] {
        let signed = signed_federation_storage_inventory_page(
            proof.server_identity,
            response_context,
            hostile,
            proof.limits,
            UnixMicros::new(1_500_000),
        )?;
        reject_inventory_page(proof, expectation, signed.envelope())?;
    }
    let reflected = signed_federation_storage_inventory_page(
        proof.server_identity,
        request_context,
        inventory_page(1),
        proof.limits,
        UnixMicros::new(1_500_000),
    )?;
    reject_inventory_page(proof, expectation, reflected.envelope())
}

fn reject_tampered_fetch(
    registry: &FederationPeerRegistry,
    connection: &quinn::Connection,
    original: &meshspan_protocol::v1::FederationEnvelope,
    limits: WireLimits,
) -> Result<(), Box<dyn Error>> {
    let mut tampered = original.clone();
    inventory_fetch_mut(&mut tampered).cursor[0] ^= 1;
    let mut replay = federation_replay()?;
    assert!(matches!(
        registry.authenticate_storage_inventory_fetch(
            connection,
            &validated_federation(&tampered, limits)?,
            UnixMicros::new(1_500_000),
            &mut replay,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    Ok(())
}

fn reject_inventory_page(
    proof: &AuthorityPageProof<'_>,
    expectation: &crate::FederationStorageInventoryPageExpectation,
    envelope: &meshspan_protocol::v1::FederationEnvelope,
) -> Result<(), Box<dyn Error>> {
    let mut replay = federation_replay()?;
    assert!(matches!(
        proof.registry.authenticate_storage_inventory_page(
            proof.connection,
            &validated_federation(envelope, proof.limits)?,
            expectation,
            UnixMicros::new(1_500_000),
            &mut replay,
        ),
        Err(TransportError::UntrustedFederationPeer)
    ));
    Ok(())
}

fn correlated_context(
    request: FederationExchangeContext,
    replay_nonce: [u8; 32],
) -> Result<FederationExchangeContext, TransportError> {
    FederationExchangeContext::new(
        request.version,
        request.request_id,
        request.operation_id,
        request.trace_id,
        request.deadline,
        replay_nonce,
    )
}

fn inventory_fetch() -> FetchFederatedStorageInventory {
    FetchFederatedStorageInventory {
        grant_id: vec![101; 16],
        target_id: vec![102; 16],
        target_generation: 7,
        cursor: vec![125; 16],
        limit: 1,
        signature: Vec::new(),
    }
}

fn inventory_page(record_count: usize) -> FederatedStorageInventoryPage {
    FederatedStorageInventoryPage {
        grant_id: vec![101; 16],
        target_id: vec![102; 16],
        target_generation: 7,
        records: (0..record_count)
            .map(|index| VersionedPayload {
                format_version: 1,
                canonical_bytes: vec![u8::try_from(index).unwrap_or(u8::MAX); 32],
            })
            .collect(),
        next_cursor: vec![136; 16],
        page_digest: Vec::new(),
        signature: Vec::new(),
    }
}

fn inventory_fetch_mut(
    envelope: &mut meshspan_protocol::v1::FederationEnvelope,
) -> &mut FetchFederatedStorageInventory {
    let Some(meshspan_protocol::v1::federation_envelope::Message::FetchStorageInventory(fetch)) =
        envelope.message.as_mut()
    else {
        unreachable!("fixture inventory fetch")
    };
    fetch
}
