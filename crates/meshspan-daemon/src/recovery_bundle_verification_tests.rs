// SPDX-License-Identifier: GPL-2.0-only

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    ConfirmRecoveryBundleRequest, ConfirmRecoveryBundleResponse,
    decode_confirm_recovery_bundle_request,
};
use meshspan_domain::{MeshId, OperationId, PrincipalId, Revision, UnixMicros};
use meshspan_metadata::{
    AuthoritativeCommand, BrowserSessionAccessRequest, CommandContext, MeshRecoveryAuthority,
    RecoveryBundleState, SessionAccessDecision,
};
use meshspan_recovery_bundle::RecoveryBundleCode;
use tempfile::tempdir;
use tower::ServiceExt;

use crate::create_session_tests::SequentialRandom;
use crate::{
    BrowserSessionAuthority, BrowserSessionAuthorityError, GatewaySessionIdentity,
    IdentityAdministrator, NativeApiKeyAuthority, NativeApiKeyAuthorityError,
    PendingRecoveryBundle, RecoveryBundleVerificationAuthority,
    RecoveryBundleVerificationAuthorityError, RecoveryBundleVerificationCommit,
    RecoveryBundleVerificationController, RecoveryBundleVerificationError,
    RecoveryBundleVerificationService, recovery_bundle_verification_api_router,
};

const OPERATION_TEXT: &str = "00000000-0000-4000-8000-000000000041";

#[test]
fn exact_committed_proof_removes_pending_bundle_and_replays()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(false)?;
    let pending_path = fixture.pending_path.clone();
    let request = verification_request(fixture.mesh_id, &fixture.challenge)?;
    let administrator = IdentityAdministrator {
        principal_id: fixture.administrator_id,
        now: UnixMicros::new(50),
    };
    let mut service = RecoveryBundleVerificationService::new(
        fixture.authority,
        GatewaySessionIdentity::new(fixture.node_id, 1)?,
        pending_path.clone(),
    );
    let first = service.confirm_saved(administrator, request.clone())?;
    assert!(!pending_path.exists());
    assert_eq!(first.verified_at_epoch_micros, 50);
    assert_eq!(first.revision, 2);

    let replay = service.confirm_saved(
        IdentityAdministrator {
            now: UnixMicros::new(99),
            ..administrator
        },
        request,
    )?;
    assert_eq!(replay, first);
    let authority = service.into_authority();
    assert!(authority.file_existed_when_committed);
    assert_eq!(authority.commit_calls, 1);
    Ok(())
}

#[test]
fn unavailable_or_wrong_authority_never_removes_pending_bundle()
-> Result<(), Box<dyn std::error::Error>> {
    let unavailable = fixture(true)?;
    let pending_path = unavailable.pending_path.clone();
    let request = verification_request(unavailable.mesh_id, &unavailable.challenge)?;
    let mut service = RecoveryBundleVerificationService::new(
        unavailable.authority,
        GatewaySessionIdentity::new(unavailable.node_id, 1)?,
        pending_path.clone(),
    );
    assert_eq!(
        service.confirm_saved(
            IdentityAdministrator {
                principal_id: unavailable.administrator_id,
                now: UnixMicros::new(50),
            },
            request,
        ),
        Err(RecoveryBundleVerificationError::Unavailable)
    );
    assert!(pending_path.exists());

    let wrong = fixture(false)?;
    let pending_path = wrong.pending_path.clone();
    let request = verification_request(wrong.mesh_id, "meshspan-check-v1.0000000000000000")?;
    let mut service = RecoveryBundleVerificationService::new(
        wrong.authority,
        GatewaySessionIdentity::new(wrong.node_id, 1)?,
        pending_path.clone(),
    );
    assert_eq!(
        service.confirm_saved(
            IdentityAdministrator {
                principal_id: wrong.administrator_id,
                now: UnixMicros::new(50),
            },
            request,
        ),
        Err(RecoveryBundleVerificationError::Conflict)
    );
    assert!(pending_path.exists());
    Ok(())
}

#[tokio::test]
async fn http_authenticates_before_inspecting_an_unbounded_body()
-> Result<(), Box<dyn std::error::Error>> {
    let authentication_calls = Arc::new(AtomicUsize::new(0));
    let confirmation_calls = Arc::new(AtomicUsize::new(0));
    let router = recovery_bundle_verification_api_router(FakeController {
        authentication_calls: Arc::clone(&authentication_calls),
        confirmation_calls: Arc::clone(&confirmation_calls),
        authenticated: false,
    })?;
    let response = router
        .oneshot(
            Request::post("/api/latest/admin/recovery-bundle-verifications")
                .body(Body::from(vec![b'x'; 4_096]))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(authentication_calls.load(Ordering::SeqCst), 1);
    assert_eq!(confirmation_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn http_validates_then_returns_only_a_contract_checked_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let authentication_calls = Arc::new(AtomicUsize::new(0));
    let confirmation_calls = Arc::new(AtomicUsize::new(0));
    let router = recovery_bundle_verification_api_router(FakeController {
        authentication_calls: Arc::clone(&authentication_calls),
        confirmation_calls: Arc::clone(&confirmation_calls),
        authenticated: true,
    })?;
    let response = router
        .oneshot(
            Request::post("/api/latest/admin/recovery-bundle-verifications")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "operation_id": OPERATION_TEXT,
                    "mesh_id": uuid_text(versioned(9)),
                    "recovery_challenge": "meshspan-check-v1.0102030405060708"
                }))?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response: ConfirmRecoveryBundleResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), 4_096).await?)?;
    assert_eq!(response.operation_id.as_str(), OPERATION_TEXT);
    assert_eq!(response.revision, 2);
    assert_eq!(authentication_calls.load(Ordering::SeqCst), 1);
    assert_eq!(confirmation_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

struct Fixture {
    authority: FakeAuthority,
    pending_path: PathBuf,
    mesh_id: MeshId,
    administrator_id: PrincipalId,
    node_id: meshspan_domain::NodeId,
    challenge: String,
    _directory: tempfile::TempDir,
}

fn fixture(fail_commit: bool) -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let pending_path = directory.path().join("pending.bundle");
    let mesh_id = MeshId::from_bytes(versioned(9))?;
    let code = RecoveryBundleCode::parse(&format!("meshspan-offline-v1.{}", "12".repeat(32)))?;
    let mut random = SequentialRandom(20);
    let pending =
        PendingRecoveryBundle::open_or_create(&pending_path, mesh_id, &code, &mut random)?;
    let identity = pending.public_identity()?;
    let challenge = pending.challenge(&code);
    let administrator_id = PrincipalId::from_bytes(versioned(10))?;
    let node_id = meshspan_domain::NodeId::from_bytes(versioned(11))?;
    Ok(Fixture {
        authority: FakeAuthority {
            current: MeshRecoveryAuthority {
                mesh_id,
                public_wrapping_key: identity.public_wrapping_key(),
                root_certificate_der: identity.root_certificate_der().to_vec(),
                bundle_digest: identity.bundle_digest(),
                state: RecoveryBundleState::Pending,
                verified_by: None,
                verified_at: None,
                revision: Revision::new(1),
            },
            expected_challenge_commitment: challenge.commitment(),
            pending_path: pending_path.clone(),
            committed: None,
            fail_commit,
            file_existed_when_committed: false,
            commit_calls: 0,
        },
        pending_path,
        mesh_id,
        administrator_id,
        node_id,
        challenge: challenge.expose_for_verification(),
        _directory: directory,
    })
}

fn verification_request(
    mesh_id: MeshId,
    challenge: &str,
) -> Result<ConfirmRecoveryBundleRequest, Box<dyn std::error::Error>> {
    Ok(decode_confirm_recovery_bundle_request(
        &serde_json::to_vec(&serde_json::json!({
            "operation_id": OPERATION_TEXT,
            "mesh_id": uuid_text(mesh_id.as_bytes()),
            "recovery_challenge": challenge
        }))?,
    )?)
}

struct FakeAuthority {
    current: MeshRecoveryAuthority,
    expected_challenge_commitment: [u8; 32],
    pending_path: PathBuf,
    committed: Option<(OperationId, RecoveryBundleVerificationCommit)>,
    fail_commit: bool,
    file_existed_when_committed: bool,
    commit_calls: usize,
}

impl BrowserSessionAuthority for FakeAuthority {
    fn evaluate_browser_session(
        &self,
        _request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError> {
        Err(BrowserSessionAuthorityError::Failed)
    }
}

impl NativeApiKeyAuthority for FakeAuthority {
    fn authenticate_native_api_key(
        &self,
        _key_id: meshspan_domain::ApiKeyId,
        _digest: [u8; 32],
        _required_assurance: meshspan_domain::AssuranceLevel,
        _now: UnixMicros,
    ) -> Result<Option<meshspan_metadata::ApiKeyAuthentication>, NativeApiKeyAuthorityError> {
        Err(NativeApiKeyAuthorityError::Failed)
    }
}

impl RecoveryBundleVerificationAuthority for FakeAuthority {
    fn is_system_manager(
        &self,
        _principal_id: PrincipalId,
        _now: UnixMicros,
    ) -> Result<bool, RecoveryBundleVerificationAuthorityError> {
        Ok(true)
    }

    fn recovery_authority(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<MeshRecoveryAuthority>, RecoveryBundleVerificationAuthorityError> {
        Ok((self.current.mesh_id == mesh_id).then(|| self.current.clone()))
    }

    fn resolve_recovery_bundle_verification(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<RecoveryBundleVerificationCommit>, RecoveryBundleVerificationAuthorityError>
    {
        Ok(self
            .committed
            .as_ref()
            .filter(|(stored, _)| *stored == operation_id)
            .map(|(_, commit)| commit.clone()))
    }

    fn commit_or_resolve_recovery_bundle_verification(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<RecoveryBundleVerificationCommit, RecoveryBundleVerificationAuthorityError> {
        self.commit_calls = self.commit_calls.saturating_add(1);
        if self.fail_commit {
            return Err(RecoveryBundleVerificationAuthorityError::Unavailable);
        }
        let AuthoritativeCommand::ConfirmRecoveryBundleSaved(proof) = command else {
            return Err(RecoveryBundleVerificationAuthorityError::Failed);
        };
        if proof.mesh_id != self.current.mesh_id
            || proof.bundle_digest != self.current.bundle_digest
            || proof.save_challenge_commitment != self.expected_challenge_commitment
        {
            return Err(RecoveryBundleVerificationAuthorityError::Conflict);
        }
        self.file_existed_when_committed = self.pending_path.is_file();
        self.current.state = RecoveryBundleState::Verified;
        self.current.verified_by = Some(context.actor_principal_id);
        self.current.verified_at = Some(context.occurred_at);
        self.current.revision = Revision::new(2);
        let commit = RecoveryBundleVerificationCommit {
            request_digest: command.request_digest(context),
            result_digest: [7; 32],
            authority: self.current.clone(),
        };
        self.committed = Some((context.operation_id, commit.clone()));
        Ok(commit)
    }
}

struct FakeController {
    authentication_calls: Arc<AtomicUsize>,
    confirmation_calls: Arc<AtomicUsize>,
    authenticated: bool,
}

impl RecoveryBundleVerificationController for FakeController {
    fn authenticate(
        &self,
        _headers: &HeaderMap,
        _now: UnixMicros,
    ) -> Result<IdentityAdministrator, RecoveryBundleVerificationError> {
        self.authentication_calls.fetch_add(1, Ordering::SeqCst);
        if !self.authenticated {
            return Err(RecoveryBundleVerificationError::Unauthenticated);
        }
        Ok(IdentityAdministrator {
            principal_id: PrincipalId::from_bytes(versioned(10))
                .map_err(|_| RecoveryBundleVerificationError::Failed)?,
            now: UnixMicros::new(50),
        })
    }

    fn confirm_saved(
        &mut self,
        _administrator: IdentityAdministrator,
        request: ConfirmRecoveryBundleRequest,
    ) -> Result<ConfirmRecoveryBundleResponse, RecoveryBundleVerificationError> {
        self.confirmation_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ConfirmRecoveryBundleResponse {
            operation_id: request.operation_id,
            mesh_id: request.mesh_id,
            verified_at_epoch_micros: 50,
            revision: 2,
        })
    }
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x40;
    value[8] = 0x80;
    value
}

fn uuid_text(bytes: [u8; 16]) -> String {
    crate::create_mesh_setup::format_uuid(bytes)
}
