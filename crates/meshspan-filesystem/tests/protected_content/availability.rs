// SPDX-License-Identifier: GPL-2.0-only

//! Availability observations must reconstruct real encrypted bytes using only survivors.

use meshspan_filesystem::StripeReadRequest;
use meshspan_filesystem::{
    DurableContentCatalog, VolumeReadAvailabilityError, VolumeReadAvailabilityProgress,
};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    BoundedBytes, ContentShardRouter, ContractError, MeshId, OperationId, PERMIT_KEY,
    ProtectedShardRepairer, PutShardRequest, ReedSolomonCoding, RequestContext,
    ReserveStorageRequest, Revision, ShardReadPermit, ShardReceipt, StoragePermitMacKey,
    StorageReservation, TargetId, TestRouter, UnixMicros, VolumeId, assert_exact_read,
    fixture_bytes, protected_publisher, protection_fixture, publication_request, publish, tempdir,
};

#[test]
fn verifies_only_selected_survivors_without_keys_or_storage_mutations()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let mesh_id = MeshId::from_bytes([81; 16])?;
    let volume_id = VolumeId::from_bytes([82; 16])?;
    let fixture = protection_fixture(root.path(), mesh_id)?;
    let mut publisher = protected_publisher(
        &root.path().join("filesystem-state"),
        fixture.router,
        volume_id,
        fixture.protection,
        mesh_id,
        83,
    )?;
    let bytes = fixture_bytes();
    let content = publish(&mut publisher, publication_request(volume_id, 84)?, &bytes)?;
    let stripe = publisher.catalog().committed_protected_stripe(content, 0)?;
    assert_eq!(stripe.stripe.coding_layout().data_slices(), 2);
    assert_eq!(stripe.receipts.as_slice().len(), 4);
    let expected = [stripe.receipts.as_slice()[1], stripe.receipts.as_slice()[3]];
    let targets = expected.map(|receipt| receipt.target_id);
    let verifier = ProtectedShardRepairer::new(
        ReadOnlySurvivors {
            router: fixture.control.clone(),
            targets,
        },
        ReedSolomonCoding::new(),
        mesh_id,
        StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
    );
    let request = StripeReadRequest {
        operation_id: OperationId::from_bytes([85; 16])?,
        authorization_revision: Revision::new(1),
        deadline: UnixMicros::new(1_000),
        observed_at: UnixMicros::new(30),
    };
    assert_eq!(
        verifier
            .verify_read_availability(request, &stripe, &targets)?
            .as_slice(),
        &expected,
    );
    fixture.control.set_offline(targets[0])?;
    assert_eq!(
        verifier.verify_read_availability(request, &stripe, &targets),
        Err(ContractError::Unavailable),
    );
    fixture.control.set_all_online()?;
    assert_eq!(
        verifier.verify_read_availability(request, &stripe, &[targets[0], targets[0]]),
        Err(ContractError::InvalidInput),
    );
    assert_exact_read(&mut publisher, content, &bytes, 86)?;
    Ok(())
}

/// Real provider reads, but a forbidden target or mutation fails the operation immediately.
struct ReadOnlySurvivors {
    router: TestRouter,
    targets: [TargetId; 2],
}

#[test]
fn survivor_scopes_preserve_required_cells_without_promoting_eventual_cells()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let fixture = super::campus_fixture(root.path(), MeshId::from_bytes([69; 16])?)?;
    let excluded: BTreeSet<_> = fixture.targets[0].iter().copied().collect();
    let scopes = fixture
        .strict_protection
        .read_availability_scopes(&excluded);
    let expected: BTreeSet<_> = fixture
        .cell_targets
        .iter()
        .flatten()
        .copied()
        .filter(|target| !excluded.contains(target))
        .collect();
    assert_eq!(scopes.targets, expected);
    assert_eq!(scopes.required_cells.len(), 2);
    for (index, cell_byte) in [92, 93].into_iter().enumerate() {
        let cell = meshspan_domain::AvailabilityCellId::from_bytes([cell_byte; 16])?;
        let expected: BTreeSet<_> = fixture.cell_targets[index]
            .iter()
            .copied()
            .filter(|target| !excluded.contains(target))
            .collect();
        assert_eq!(scopes.required_cells[&cell], expected);
    }
    assert!(
        !scopes
            .required_cells
            .contains_key(&meshspan_domain::AvailabilityCellId::from_bytes([94; 16])?)
    );
    Ok(())
}

#[test]
fn whole_volume_probe_checks_each_publication_and_invalidates_on_concurrent_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let mesh = MeshId::from_bytes([71; 16])?;
    let volume = VolumeId::from_bytes([72; 16])?;
    let fixture = protection_fixture(root.path(), mesh)?;
    let state = root.path().join("volume-probe");
    let mut publisher = protected_publisher(
        &state,
        fixture.router.clone(),
        volume,
        fixture.protection,
        mesh,
        73,
    )?;
    let bytes = fixture_bytes();
    publish(&mut publisher, publication_request(volume, 74)?, &bytes)?;
    publish(&mut publisher, publication_request(volume, 75)?, &bytes)?;
    let survivors: BTreeSet<_> = fixture.required_targets.iter().copied().collect();
    let cell = meshspan_domain::AvailabilityCellId::from_bytes([76; 16])?;
    let cells = BTreeMap::from([(
        cell,
        BTreeSet::from([fixture.required_targets[0], fixture.required_targets[1]]),
    )]);
    let verifier = ProtectedShardRepairer::new(
        fixture.control.clone(),
        ReedSolomonCoding::new(),
        mesh,
        StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
    );
    let request = StripeReadRequest {
        operation_id: OperationId::from_bytes([77; 16])?,
        authorization_revision: Revision::new(1),
        deadline: UnixMicros::new(1_000),
        observed_at: UnixMicros::new(30),
    };
    let catalogue = DurableContentCatalog::open(&state, UnixMicros::new(30))?;
    let mut probe = catalogue.into_read_availability(volume, survivors.clone(), cells.clone())?;
    assert_eq!(
        probe.advance(&verifier, request)?,
        VolumeReadAvailabilityProgress {
            publications: 1,
            stripes: 1,
            complete: false,
        }
    );
    fixture.control.set_offline(fixture.required_targets[0])?;
    assert!(matches!(
        probe.advance(&verifier, request),
        Err(VolumeReadAvailabilityError::Read(
            ContractError::Unavailable
        ))
    ));
    assert_eq!(
        probe.progress()?.stripes,
        1,
        "a failed required-cell check cannot advance"
    );
    fixture.control.set_all_online()?;
    assert_eq!(probe.advance(&verifier, request)?.stripes, 2);
    assert_eq!(
        probe.advance(&verifier, request)?,
        VolumeReadAvailabilityProgress {
            publications: 2,
            stripes: 2,
            complete: true,
        }
    );
    // The writer uses its existing, separate connection while the completed probe remains alive.
    // Its commit must invalidate even a previously completed scan.
    publish(&mut publisher, publication_request(volume, 78)?, &bytes)?;
    assert!(matches!(
        probe.progress(),
        Err(VolumeReadAvailabilityError::CatalogueChanged)
    ));
    assert!(matches!(
        probe.advance(&verifier, request),
        Err(VolumeReadAvailabilityError::CatalogueChanged)
    ));
    drop(probe);
    let reopened = DurableContentCatalog::open(&state, UnixMicros::new(40))?;
    let mut resumed = reopened.into_read_availability(volume, survivors, cells)?;
    assert_eq!(
        resumed.progress()?,
        VolumeReadAvailabilityProgress::default()
    );
    for expected in 1..=3 {
        assert_eq!(resumed.advance(&verifier, request)?.stripes, expected);
    }
    assert_eq!(resumed.advance(&verifier, request)?.publications, 3);
    assert!(resumed.progress()?.complete);
    Ok(())
}

#[test]
fn volume_transition_keeps_the_original_catalogue_fence() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempdir()?;
    let mesh = MeshId::from_bytes([61; 16])?;
    let volume = VolumeId::from_bytes([62; 16])?;
    let later_volume = VolumeId::from_bytes([63; 16])?;
    let fixture = protection_fixture(root.path(), mesh)?;
    let state = root.path().join("volume-transition");
    let mut publisher = protected_publisher(
        &state,
        fixture.router.clone(),
        volume,
        fixture.protection,
        mesh,
        64,
    )?;
    let verifier = ProtectedShardRepairer::new(
        fixture.control,
        ReedSolomonCoding::new(),
        mesh,
        StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
    );
    let request = StripeReadRequest {
        operation_id: OperationId::from_bytes([65; 16])?,
        authorization_revision: Revision::new(1),
        deadline: UnixMicros::new(1_000),
        observed_at: UnixMicros::new(30),
    };
    let mut resumed = DurableContentCatalog::open(&state, UnixMicros::new(30))?
        .into_read_availability(volume, BTreeSet::new(), BTreeMap::new())?;
    assert!(matches!(
        resumed.next_volume(later_volume, BTreeSet::new(), BTreeMap::new()),
        Err(VolumeReadAvailabilityError::Read(
            ContractError::InvalidInput
        ))
    ));
    assert!(resumed.advance(&verifier, request)?.complete);
    assert!(matches!(
        resumed.next_volume(volume, BTreeSet::new(), BTreeMap::new()),
        Err(VolumeReadAvailabilityError::Read(
            ContractError::InvalidInput
        ))
    ));
    resumed.next_volume(later_volume, BTreeSet::new(), BTreeMap::new())?;
    assert_eq!(
        resumed.progress()?,
        VolumeReadAvailabilityProgress::default()
    );
    assert_eq!(
        resumed.advance(&verifier, request)?,
        VolumeReadAvailabilityProgress {
            publications: 0,
            stripes: 0,
            complete: true,
        }
    );
    // A later empty volume cannot reset the fence over previously checked volumes.
    publish(
        &mut publisher,
        publication_request(volume, 66)?,
        &fixture_bytes(),
    )?;
    assert!(matches!(
        resumed.progress(),
        Err(VolumeReadAvailabilityError::CatalogueChanged)
    ));
    Ok(())
}

#[test]
fn availability_inventory_includes_acknowledged_stripes_with_eventual_debt()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let mesh_id = MeshId::from_bytes([91; 16])?;
    let volume_id = VolumeId::from_bytes([92; 16])?;
    let fixture = protection_fixture(root.path(), mesh_id)?;
    fixture.control.set_offline(fixture.eventual_target)?;
    let mut publisher = protected_publisher(
        &root.path().join("filesystem-state"),
        fixture.router,
        volume_id,
        fixture.protection,
        mesh_id,
        93,
    )?;
    let bytes = fixture_bytes();
    let incomplete = publish(&mut publisher, publication_request(volume_id, 94)?, &bytes)?;
    fixture.control.set_all_online()?;
    let complete = publish(&mut publisher, publication_request(volume_id, 95)?, &bytes)?;
    let catalogue = publisher.catalog();
    let first = catalogue.committed_volume_stripes(volume_id, None, 1)?;
    assert_eq!(first.stripes.len(), 1);
    assert_eq!(first.stripes.as_slice()[0].content, incomplete);
    assert_eq!(first.stripes.as_slice()[0].stripe.receipts.len(), 3);
    assert_eq!(first.next, Some(first.stripes.as_slice()[0].cursor));
    let second = catalogue.committed_volume_stripes(volume_id, first.next, 1)?;
    assert_eq!(second.stripes.len(), 1);
    assert_eq!(second.stripes.as_slice()[0].content, complete);
    assert_eq!(second.stripes.as_slice()[0].stripe.receipts.len(), 4);
    assert_eq!(second.next, None);
    let rebalancing = catalogue.current_volume_stripes(volume_id, None, 1)?;
    assert_eq!(rebalancing.stripes.len(), 1);
    assert_eq!(rebalancing.stripes.as_slice()[0].content, complete);
    assert_eq!(rebalancing.next, None);
    assert_exact_read(&mut publisher, incomplete, &bytes, 96)?;
    Ok(())
}

impl ContentShardRouter for ReadOnlySurvivors {
    fn reserve(
        &mut self,
        _request: ReserveStorageRequest,
    ) -> Result<StorageReservation, ContractError> {
        Err(ContractError::InternalContract)
    }

    fn put_exact(
        &mut self,
        _request: PutShardRequest,
        _observed_at: UnixMicros,
    ) -> Result<ShardReceipt, ContractError> {
        Err(ContractError::InternalContract)
    }

    fn prepare_repair_put(
        &mut self,
        _intent: meshspan_contracts::ShardPutIntent,
        _authority: meshspan_contracts::ShardWritePermit,
        _observed_at: UnixMicros,
    ) -> Result<meshspan_contracts::RepairPutAdmission, ContractError> {
        Err(ContractError::InternalContract)
    }

    fn finish_repair_put(
        &mut self,
        _request: PutShardRequest,
        _authority: meshspan_contracts::ShardWritePermit,
        _observed_at: UnixMicros,
    ) -> Result<ShardReceipt, ContractError> {
        Err(ContractError::InternalContract)
    }

    fn get_exact(
        &self,
        context: RequestContext,
        permit: ShardReadPermit,
        observed_at: UnixMicros,
    ) -> Result<BoundedBytes, ContractError> {
        if !self.targets.contains(&permit.target_id) {
            return Err(ContractError::InternalContract);
        }
        self.router.get_exact(context, permit, observed_at)
    }
}
