// SPDX-License-Identifier: GPL-2.0-only

//! A durable replacement remains recoverable when its original reconstruction inputs disappear.

use super::*;

#[test]
fn repair_recovers_original_write_after_deadline_without_reconstructing_again()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let mesh = MeshId::from_bytes([170; 16])?;
    let fixture = protection_fixture(root.path(), mesh)?;
    let router = fixture.router.clone();
    let volume = VolumeId::from_bytes([171; 16])?;
    let mut publisher = protected_publisher(
        &root.path().join("resume"),
        fixture.router,
        volume,
        fixture.protection,
        mesh,
        172,
    )?;
    let content = publish(
        &mut publisher,
        publication_request(volume, 173)?,
        &fixture_bytes(),
    )?;
    let stripe = publisher.catalog().committed_protected_stripe(content, 0)?;
    let receipts = stripe.receipts.as_slice();
    let source = receipts[0];
    let destination = receipts[1].target_id;
    let request = repair_request(source, destination, 174)?;
    let intent = request.physical_intent();
    fixture.control.set_offline(source.target_id)?;
    let mut repairer = ProtectedShardRepairer::new(
        router.clone(),
        ReedSolomonCoding::new(),
        mesh,
        StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
    );
    let written = repairer.resume_repair(intent, request, &stripe, &FixedClock(30))?;
    assert_eq!(written.operation_id, OperationId::from_bytes([174; 16])?);
    assert_eq!(written.digest, source.digest);
    drop(repairer);
    for receipt in receipts {
        if receipt.target_id != destination {
            fixture.control.set_offline(receipt.target_id)?;
        }
    }
    let mut repairer = ProtectedShardRepairer::new(
        router,
        ReedSolomonCoding::new(),
        mesh,
        StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
    );
    let refreshed = ShardRepairRequest {
        authorization_revision: Revision::new(2),
        observed_at: UnixMicros::new(2_000),
        deadline: UnixMicros::new(3_000),
        ..request
    };
    assert!(
        repairer.repair(refreshed, &stripe).is_err(),
        "inputs cannot reconstruct the stripe"
    );
    assert_eq!(
        repairer.resume_repair(intent, refreshed, &stripe, &FixedClock(2_000))?,
        written
    );
    assert_eq!(
        repairer.resume_repair(intent, refreshed, &stripe, &FixedClock(2_000))?,
        written
    );
    assert_eq!(
        repairer.resume_repair(intent, refreshed, &stripe, &FixedClock(3_000)),
        Err(ContractError::DeadlineExceeded),
    );
    Ok(())
}

struct FixedClock(i64);
impl meshspan_domain::Clock for FixedClock {
    fn now(&self) -> UnixMicros {
        UnixMicros::new(self.0)
    }
}
