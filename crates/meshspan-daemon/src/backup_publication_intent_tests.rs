// SPDX-License-Identifier: GPL-2.0-only

//! Provider IO must be preceded by a durably accepted exact upload identity.

use super::*;

#[test]
fn unavailable_upload_intent_prevents_provider_io() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let directory = tempdir()?;
    let encrypted = directory.path().join("backup.msb");
    std::fs::write(&encrypted, fixture.bytes)?;
    let destination_id = fixture.destination.destination_id;
    let authority = MemoryAuthority::new(fixture.destination);
    authority.reject_intents.set(true);
    let mut provider = MemoryProvider::default();
    let result = MetadataBackupPublisher::new(&authority).publish(
        &mut provider,
        &BackupPublicationRequest {
            encrypted_source: &encrypted,
            evidence: fixture.evidence,
            destination_id,
            claim: fixture.claim,
            actor_principal_id: fixture.actor,
            now: UnixMicros::new(20),
            deadline: UnixMicros::new(100),
        },
    );
    assert_eq!(provider.stores, 0);
    assert!(matches!(
        result,
        Err(crate::BackupPublicationError::Authority(_))
    ));
    assert!(authority.intent.borrow().is_none());
    assert!(authority.backup.borrow().is_none());
    Ok(())
}

#[test]
fn provider_operation_identity_survives_renewed_attempt_time()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::backup_publication::evidence::{PublicationStep, provider_context};
    let fixture = Fixture::new()?;
    let first = provider_context(
        PublicationStep::StoreProvider,
        fixture.evidence,
        fixture.destination.destination_id,
        UnixMicros::new(20),
        UnixMicros::new(100),
        Revision::new(3),
    )?;
    let retry = provider_context(
        PublicationStep::StoreProvider,
        fixture.evidence,
        fixture.destination.destination_id,
        UnixMicros::new(21),
        UnixMicros::new(101),
        Revision::new(4),
    )?;
    assert_eq!(first.operation_id, retry.operation_id);
    assert_ne!(first.deadline, retry.deadline);
    assert_ne!(first.expected_revision, retry.expected_revision);
    Ok(())
}
