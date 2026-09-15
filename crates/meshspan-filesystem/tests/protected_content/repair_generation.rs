// SPDX-License-Identifier: GPL-2.0-only

//! Physical generation fences allow repeated movement without retiring live content.

use super::*;
use meshspan_contracts::{RemovalPermit, removal_permit_mac};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn repair_returns_to_reclaimed_target_and_old_removal_cannot_delete_replacement() -> TestResult {
    let root = tempdir()?;
    let mesh = MeshId::from_bytes([180; 16])?;
    let fixture = protection_fixture(root.path(), mesh)?;
    let router = fixture.router.clone();
    let volume = VolumeId::from_bytes([181; 16])?;
    let protection = fixture.protection.clone();
    let state = root.path().join("return-to-target");
    let mut publisher = protected_publisher(
        &state,
        fixture.router,
        volume,
        fixture.protection,
        mesh,
        182,
    )?;
    let bytes = fixture_bytes();
    let content = publish(&mut publisher, publication_request(volume, 183)?, &bytes)?;
    let stripe = publisher.catalog().committed_protected_stripe(content, 0)?;
    let source = stripe.receipts.as_slice()[0];
    let destination = stripe.receipts.as_slice()[1].target_id;
    let mut repairer = ProtectedShardRepairer::new(
        router.clone(),
        ReedSolomonCoding::new(),
        mesh,
        StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
    );
    router.set_offline(source.target_id)?;
    let replacement = repairer.repair(repair_request(source, destination, 184)?, &stripe)?;
    publisher.install_shard_repair(content, &transition(source, replacement, 1, 185)?)?;
    router.set_all_online()?;
    retire_copy(&router, mesh, source, 186)?;
    let current = publisher.catalog().committed_protected_stripe(content, 0)?;
    let returned = repairer.repair(
        repair_request(replacement, source.target_id, 187)?,
        &current,
    )?;
    assert_eq!(returned.shard.generation, 3);
    assert_eq!(returned.digest, source.digest);
    publisher.install_shard_repair(content, &transition(replacement, returned, 2, 188)?)?;
    // Replay an already-authorised exact physical removal after this target hosts a new route.
    // The fixture supplies authority; this does not prove automatic cleanup admission.
    retire_copy(&router, mesh, source, 186)?;
    retire_copy(&router, mesh, replacement, 189)?;
    for receipt in &stripe.receipts.as_slice()[2..] {
        router.set_offline(receipt.target_id)?;
    }
    assert_exact_read(&mut publisher, content, &bytes, 190)?;
    let publisher_router = publisher.into_router();
    let mut reopened =
        protected_publisher(&state, publisher_router, volume, protection, mesh, 182)?;
    assert_exact_read(&mut reopened, content, &bytes, 191)?;
    let current = reopened.catalog().committed_protected_stripe(content, 0)?;
    assert_eq!(
        current.stripe, stripe.stripe,
        "immutable content layout remains unchanged"
    );
    assert_eq!(current.receipts.as_slice()[0], returned);
    Ok(())
}

fn transition(
    source: ShardReceipt,
    replacement: ShardReceipt,
    generation: u64,
    operation: u8,
) -> TestResult<ShardRepairTransition> {
    Ok(ShardRepairTransition {
        effect_operation_id: OperationId::from_bytes([operation; 16])?,
        source_layout_generation: generation,
        replacement_layout_generation: generation + 1,
        source_receipt: source,
        replacement_receipt: replacement,
        committed_revision: Revision::new(generation + 1),
    })
}

fn retire_copy(
    router: &TestRouter,
    mesh: MeshId,
    receipt: ShardReceipt,
    operation: u8,
) -> TestResult {
    let mut state = router.lock()?;
    let provider = state
        .providers
        .get_mut(&receipt.target_id)
        .ok_or("provider missing")?;
    let mut permit = RemovalPermit {
        operation_id: OperationId::from_bytes([operation; 16])?,
        mesh_id: mesh,
        target_id: receipt.target_id,
        target_generation: receipt.target_generation,
        shard: receipt.shard,
        authority_epoch: 1,
        catalogue_revision: Revision::new(1),
        expires_at: UnixMicros::new(1_000),
        permit_digest: [0; 32],
    };
    permit.permit_digest =
        removal_permit_mac(&StoragePermitMacKey::from_bytes(PERMIT_KEY)?, permit);
    let tombstone = StorageProvider::tombstone(provider, permit, UnixMicros::new(40))?;
    let reclaimed = StorageProvider::unlink_tombstoned(provider, tombstone, UnixMicros::new(41))?;
    assert_eq!(reclaimed.tombstone.shard, receipt.shard);
    Ok(())
}
