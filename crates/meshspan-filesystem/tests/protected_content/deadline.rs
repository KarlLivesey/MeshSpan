// SPDX-License-Identifier: GPL-2.0-only

//! Recovery deadlines bound provider work, while completed content remains resolvable.

use meshspan_filesystem::ContentPublicationError;

use super::{
    DurableContentPublisher, MeshId, PublishedContentReference, UnixMicros, VolumeId,
    assert_exact_read, fixture_bytes, protected_publisher, protection_fixture, publication_request,
    publish, tempdir,
};

#[test]
fn expired_prepared_publication_does_not_attempt_provider_io()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempdir()?;
    let mesh = MeshId::from_bytes([91; 16])?;
    let volume = VolumeId::from_bytes([92; 16])?;
    let fixture = protection_fixture(root.path(), mesh)?;
    fixture
        .control
        .set_offline_many(&fixture.required_targets)?;
    let mut publisher = protected_publisher(
        &root.path().join("filesystem-state"),
        fixture.router,
        volume,
        fixture.protection,
        mesh,
        93,
    )?;
    let request = publication_request(volume, 94)?;
    let bytes = fixture_bytes();
    assert!(publish(&mut publisher, request, &bytes).is_err());
    assert!(publisher.catalog().prepared_layout(request)?.is_some());
    let reserves = fixture.control.lock()?.reserve_calls;
    let mut expired = request;
    expired.observed_at = expired.deadline;
    let result = publisher.resolve(expired);
    assert_eq!(
        fixture.control.lock()?.reserve_calls,
        reserves,
        "expired recovery must not call the provider"
    );
    assert!(matches!(result, Err(ContentPublicationError::InvalidInput)));
    assert!(publisher.catalog().resolve(expired)?.is_none());

    // A rejected attempt must leave the prepared publication recoverable by a live request.
    fixture.control.set_all_online()?;
    let manifest = publisher
        .resolve(request)?
        .ok_or("live recovery did not finish")?;
    let content = PublishedContentReference {
        publication_operation_id: request.operation_id,
        manifest,
    };
    assert_exact_read(&mut publisher, content, &bytes, 95)?;
    let reserves = fixture.control.lock()?.reserve_calls;
    expired.observed_at = UnixMicros::new(1_001);
    assert_eq!(publisher.resolve(expired)?, Some(manifest));
    assert_eq!(fixture.control.lock()?.reserve_calls, reserves);
    Ok(())
}
