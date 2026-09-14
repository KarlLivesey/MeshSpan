// SPDX-License-Identifier: GPL-2.0-only

use super::renewal_at_admission;
use crate::native_upload_service_tests::{seed_namespace, versioned};
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, BranchId, HandleId, NodeId, OperationId, PrincipalId,
    Revision, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    AdapterLeaseRequest, CreateDisposition, FilesystemAccessContext, HandleAccess, HandleError,
    HandleLeaseRequest, HandleShare, NamespaceLimits, NamespacePath, OpenHandleRequest,
    VersionPublicationStore,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, Ordering},
    mpsc,
};
use std::time::Duration;

#[test]
fn waiting_for_native_ownership_cannot_renew_an_expired_handle()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    seed_namespace(directory.path())?;
    let mut store = VersionPublicationStore::open(directory.path(), UnixMicros::new(10))?;
    let (context, request) = renewal(AuthenticationService::Smb)?;
    store.open_handle(&OpenHandleRequest {
        operation_id: OperationId::from_bytes(versioned(200))?,
        handle_id: request.handle_id,
        branch_id: BranchId::from_bytes(versioned(11))?,
        volume_id: VolumeId::from_bytes(versioned(12))?,
        path: NamespacePath::from_components(["seed"], NamespaceLimits::PORTABLE)?,
        principal_id: PrincipalId::from_bytes(versioned(18))?,
        authorization_revision: Revision::new(1),
        gateway_node_id: context.gateway_node_id,
        desired_access: HandleAccess::new(true, false, false)?,
        share_access: HandleShare::new(true, true, true),
        create_disposition: CreateDisposition::OpenExisting,
        delete_on_close: false,
        lease_expires_at: UnixMicros::new(60),
        opened_at: UnixMicros::new(10),
    })?;
    let owner = Arc::new(Mutex::new(store));
    let clock = Arc::new(AtomicI64::new(30));
    let guard = owner.lock().map_err(|_| "owner poisoned")?;
    let (started, queued) = mpsc::sync_channel(1);
    let worker_owner = Arc::clone(&owner);
    let worker_clock = Arc::clone(&clock);
    let principal_id = PrincipalId::from_bytes(versioned(18))?;
    let worker = std::thread::spawn(move || {
        started.send(()).map_err(|_| "test receiver closed")?;
        let mut guard = worker_owner.lock().map_err(|_| "test owner poisoned")?;
        let (context, request) = renewal_at_admission(&guard, context, request, || {
            Some(UnixMicros::new(worker_clock.load(Ordering::SeqCst)))
        })
        .map_err(|_| "forward clock admission failed")?;
        Ok::<_, &'static str>(guard.renew_handle_lease(HandleLeaseRequest {
            operation_id: request.operation_id,
            handle_id: request.handle_id,
            expected_fence: request.expected_fence,
            principal_id,
            authorization_revision: Revision::new(1),
            gateway_node_id: context.gateway_node_id,
            takeover: request.takeover,
            lease_expires_at: request.lease_expires_at,
            observed_at: request.observed_at,
        }))
    });
    let queued_result = queued.recv_timeout(Duration::from_secs(2));
    clock.store(70, Ordering::SeqCst);
    drop(guard);
    let outcome = worker.join().map_err(|_| "worker panicked")??;
    queued_result?;
    assert!(
        matches!(outcome, Err(HandleError::StaleHandle)),
        "expected expired handle, got {outcome:?}"
    );
    Ok(())
}

#[test]
fn smb_admission_rejects_backward_missing_and_inconsistent_time()
-> Result<(), Box<dyn std::error::Error>> {
    let owner = Mutex::new(());
    let guard = owner.lock().map_err(|_| "owner poisoned")?;
    let (context, request) = renewal(AuthenticationService::Smb)?;
    assert!(renewal_at_admission(&guard, context, request, || Some(UnixMicros::new(20))).is_err());
    assert!(renewal_at_admission(&guard, context, request, || None).is_err());
    let mut mismatched = request;
    mismatched.observed_at = UnixMicros::new(29);
    assert!(
        renewal_at_admission(&guard, context, mismatched, || Some(UnixMicros::new(40))).is_err()
    );
    let (admitted_context, admitted) =
        renewal_at_admission(&guard, context, request, || Some(UnixMicros::new(40)))?;
    assert_eq!(admitted_context.now, UnixMicros::new(40));
    assert_eq!(admitted.observed_at, UnixMicros::new(40));
    assert_eq!(admitted.operation_id, request.operation_id);
    assert_eq!(admitted.lease_expires_at, UnixMicros::new(90));
    Ok(())
}

#[test]
fn other_adapters_and_takeover_preserve_exact_replay_time() -> Result<(), Box<dyn std::error::Error>>
{
    let owner = Mutex::new(());
    let guard = owner.lock().map_err(|_| "owner poisoned")?;
    for (service, takeover) in [
        (AuthenticationService::Https, false),
        (AuthenticationService::HeadlessApi, false),
        (AuthenticationService::Smb, true),
    ] {
        let (context, mut request) = renewal(service)?;
        request.takeover = takeover;
        let sampled = std::cell::Cell::new(false);
        assert_eq!(
            renewal_at_admission(&guard, context, request, || {
                sampled.set(true);
                None
            })?,
            (context, request)
        );
        assert!(!sampled.get(), "caller owns replay time");
    }
    Ok(())
}

fn renewal(
    service: AuthenticationService,
) -> Result<(FilesystemAccessContext, AdapterLeaseRequest), Box<dyn std::error::Error>> {
    Ok((
        FilesystemAccessContext {
            authentication_service: service,
            credential_digest: [1; 32],
            required_assurance: AssuranceLevel::SingleFactor,
            gateway_node_id: NodeId::from_bytes(versioned(203))?,
            gateway_incarnation: 1,
            now: UnixMicros::new(30),
        },
        AdapterLeaseRequest {
            operation_id: OperationId::from_bytes(versioned(201))?,
            handle_id: HandleId::from_bytes(versioned(202))?,
            expected_fence: 1,
            takeover: false,
            lease_expires_at: UnixMicros::new(90),
            observed_at: UnixMicros::new(30),
        },
    ))
}
