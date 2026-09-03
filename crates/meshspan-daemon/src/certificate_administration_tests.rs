// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use meshspan_api_contract::{ProvisionCertificateRequest, decode_provision_certificate_request};
use meshspan_domain::{
    ApiKeyId, AssuranceLevel, EntropyError, OperationId, PrincipalId, RandomSource, Revision,
    UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AcmeConfigurationRecord, ApiKeyAuthentication, AuthoritativeCommand,
    BrowserSessionAccessRequest, CertificateOrderRecord, CertificateOrderState, CommandContext,
    SessionAccessDecision, SessionAccessDenial,
};
use meshspan_secret_envelope::{WrappingPrivateKey, WrappingPublicKey};

use crate::{
    BrowserSessionAuthority, BrowserSessionAuthorityError, CertificateProvisioningAuthority,
    CertificateProvisioningAuthorityError, CertificateProvisioningCommit,
    CertificateProvisioningController, CertificateProvisioningError,
    CertificateProvisioningService, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthority, NativeApiKeyAuthorityError, SystemManagerAuthenticationError,
    SystemManagerAuthority,
};

#[test]
fn exact_secret_bearing_retry_resolves_before_entropy_or_recipient_reads()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(Mutex::new(None));
    let authority = MockAuthority::new(Arc::clone(&state))?;
    let entropy_calls = Arc::new(Mutex::new(0_usize));
    let administrator = administrator()?;
    let mut first = CertificateProvisioningService::new(
        authority.clone(),
        gateway()?,
        CountingRandom::new(Arc::clone(&entropy_calls)),
    );
    let created = first.provision(administrator, request("0123456789abcdef")?)?;
    assert!(*entropy_calls.lock().map_err(|_| "entropy lock")? > 0);
    let recipient_reads = authority.recipient_reads();

    let observer = authority.clone();
    let mut replay = CertificateProvisioningService::new(authority, gateway()?, FailingRandom);
    let resolved = replay.provision(administrator, request("0123456789abcdef")?)?;
    assert_eq!(resolved, created);
    assert_eq!(observer.recipient_reads(), recipient_reads);
    Ok(())
}

#[test]
fn changed_provider_secret_conflicts_without_generating_another_account_key()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(Mutex::new(None));
    let authority = MockAuthority::new(state)?;
    let administrator = administrator()?;
    let mut first = CertificateProvisioningService::new(
        authority.clone(),
        gateway()?,
        CountingRandom::new(Arc::new(Mutex::new(0))),
    );
    first.provision(administrator, request("0123456789abcdef")?)?;

    let mut replay = CertificateProvisioningService::new(authority, gateway()?, FailingRandom);
    assert_eq!(
        replay.provision(administrator, request("fedcba9876543210")?),
        Err(CertificateProvisioningError::Conflict),
    );
    Ok(())
}

#[derive(Clone)]
struct MockAuthority {
    state: Arc<Mutex<Option<(OperationId, CertificateProvisioningCommit)>>>,
    recipient: WrappingPublicKey,
    recipient_reads: Arc<Mutex<usize>>,
}

impl MockAuthority {
    fn new(
        state: Arc<Mutex<Option<(OperationId, CertificateProvisioningCommit)>>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            state,
            recipient: WrappingPrivateKey::from_bytes([31; 32])?.public_key(),
            recipient_reads: Arc::new(Mutex::new(0)),
        })
    }

    fn recipient_reads(&self) -> usize {
        self.recipient_reads
            .lock()
            .map_or(usize::MAX, |value| *value)
    }
}

impl CertificateProvisioningAuthority for MockAuthority {
    fn resolve_certificate_provisioning(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<CertificateProvisioningCommit>, CertificateProvisioningAuthorityError> {
        let state = self
            .state
            .lock()
            .map_err(|_| CertificateProvisioningAuthorityError::Failed)?;
        Ok(state
            .as_ref()
            .filter(|(stored, _)| *stored == operation_id)
            .map(|(_, commit)| commit.clone()))
    }

    fn certificate_secret_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, CertificateProvisioningAuthorityError> {
        let mut reads = self
            .recipient_reads
            .lock()
            .map_err(|_| CertificateProvisioningAuthorityError::Failed)?;
        *reads = reads.saturating_add(1);
        Ok(vec![self.recipient])
    }

    fn commit_or_resolve_certificate_provisioning(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CertificateProvisioningCommit, CertificateProvisioningAuthorityError> {
        let AuthoritativeCommand::ProvisionAcme(value) = command else {
            return Err(CertificateProvisioningAuthorityError::Failed);
        };
        let revision = Revision::new(1);
        let commit = CertificateProvisioningCommit {
            request_digest: command.request_digest(context),
            result_digest: [32; 32],
            committed_revision: revision,
            configuration: AcmeConfigurationRecord {
                config_id: value.configuration.config_id,
                directory_url: value.configuration.directory_url.clone(),
                account_key: value.configuration.account_key,
                challenge_kind: value.configuration.challenge_kind,
                challenge_settings: value.configuration.challenge_settings,
                certificate_names: value.configuration.certificate_names.as_slice().to_vec(),
                provisioning_intent_digest: Some(value.intent_digest),
                configured_by: context.actor_principal_id,
                revision,
            },
            order: CertificateOrderRecord {
                order_id: value.initial_order.order_id,
                config_id: value.initial_order.config_id,
                state: CertificateOrderState::Queued,
                next_attempt_at: value.initial_order.next_attempt_at,
                attempt_count: 0,
                certificate: None,
                claim: None,
                revision,
            },
        };
        *self
            .state
            .lock()
            .map_err(|_| CertificateProvisioningAuthorityError::Failed)? =
            Some((context.operation_id, commit.clone()));
        Ok(commit)
    }
}

impl SystemManagerAuthority for MockAuthority {
    fn principal_is_system_manager(
        &self,
        _principal_id: PrincipalId,
        _now: UnixMicros,
    ) -> Result<bool, SystemManagerAuthenticationError> {
        Ok(true)
    }
}

impl BrowserSessionAuthority for MockAuthority {
    fn evaluate_browser_session(
        &self,
        _request: BrowserSessionAccessRequest,
    ) -> Result<SessionAccessDecision, BrowserSessionAuthorityError> {
        Ok(SessionAccessDecision::Denied(
            SessionAccessDenial::Unavailable,
        ))
    }
}

impl NativeApiKeyAuthority for MockAuthority {
    fn authenticate_native_api_key(
        &self,
        _key_id: ApiKeyId,
        _digest: [u8; 32],
        _required_assurance: AssuranceLevel,
        _now: UnixMicros,
    ) -> Result<Option<ApiKeyAuthentication>, NativeApiKeyAuthorityError> {
        Ok(None)
    }
}

struct CountingRandom {
    next: u8,
    calls: Arc<Mutex<usize>>,
}

impl CountingRandom {
    fn new(calls: Arc<Mutex<usize>>) -> Self {
        Self { next: 41, calls }
    }
}

impl RandomSource for CountingRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        let mut calls = self.calls.lock().map_err(|_| EntropyError)?;
        *calls = calls.saturating_add(1);
        for byte in destination {
            *byte = self.next;
            self.next = self.next.wrapping_add(1).max(1);
        }
        Ok(())
    }
}

struct FailingRandom;

impl RandomSource for FailingRandom {
    fn fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError)
    }
}

fn request(token: &str) -> Result<ProvisionCertificateRequest, Box<dyn std::error::Error>> {
    let value = serde_json::json!({
        "operation_id": "12121212-1212-4212-9212-121212121212",
        "directory_url": "https://acme.example.test/directory",
        "certificate_names": ["files.example.test"],
        "challenge": {
            "kind": "dns01_cloudflare",
            "zone_id": "0123456789abcdef0123456789abcdef",
            "api_token": token
        }
    });
    Ok(decode_provision_certificate_request(&serde_json::to_vec(
        &value,
    )?)?)
}

fn administrator() -> Result<IdentityAdministrator, meshspan_domain::IdentifierError> {
    Ok(IdentityAdministrator {
        principal_id: PrincipalId::from_bytes(uuid_v8([11; 16]))?,
        now: UnixMicros::new(100),
    })
}

fn gateway() -> Result<GatewaySessionIdentity, meshspan_domain::IdentifierError> {
    Ok(GatewaySessionIdentity {
        node_id: meshspan_domain::NodeId::from_bytes(uuid_v8([12; 16]))?,
        incarnation: 1,
    })
}
