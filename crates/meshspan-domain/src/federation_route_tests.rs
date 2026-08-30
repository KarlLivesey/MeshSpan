// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn direct_and_downstream_routes_preserve_exact_contact_order()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = mesh(1)?;
    let recipient = mesh(2)?;
    let downstream = mesh(3)?;

    let direct = FederationGrantRoute::direct(owner, recipient)?;
    assert_eq!(direct.authority_mesh_id(), owner);
    assert_eq!(direct.issuer_mesh_id(), owner);
    assert_eq!(direct.recipient_mesh_id(), recipient);
    assert_eq!(direct.downstream_depth(), 0);

    let delegated = direct.delegate_to(downstream)?;
    assert_eq!(delegated.authority_mesh_id(), owner);
    assert_eq!(delegated.issuer_mesh_id(), recipient);
    assert_eq!(delegated.recipient_mesh_id(), downstream);
    assert_eq!(delegated.downstream_depth(), 1);
    assert_eq!(delegated.meshes(), &[owner, recipient, downstream]);
    Ok(())
}

#[test]
fn direct_transitive_and_decoded_cycles_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let owner = mesh(1)?;
    let recipient = mesh(2)?;
    let route = FederationGrantRoute::direct(owner, recipient)?;

    assert_eq!(
        FederationGrantRoute::direct(owner, owner),
        Err(FederationGrantRouteError::Cycle)
    );
    assert_eq!(
        route.delegate_to(owner),
        Err(FederationGrantRouteError::Cycle)
    );
    assert_eq!(
        FederationGrantRoute::from_meshes(vec![owner]),
        Err(FederationGrantRouteError::MissingRecipient)
    );
    Ok(())
}

#[test]
fn route_depth_is_bounded_before_allocation_can_grow_without_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let maximum = u8::try_from(MAXIMUM_FEDERATION_ROUTE_MESHES)?;
    let meshes = (1_u8..=maximum).map(mesh).collect::<Result<Vec<_>, _>>()?;
    let route = FederationGrantRoute::from_meshes(meshes)?;

    assert_eq!(route.meshes().len(), MAXIMUM_FEDERATION_ROUTE_MESHES);
    assert_eq!(
        route.delegate_to(mesh(65)?),
        Err(FederationGrantRouteError::TooDeep)
    );
    Ok(())
}

fn mesh(value: u8) -> Result<MeshId, crate::IdentifierError> {
    MeshId::from_bytes([value; 16])
}
