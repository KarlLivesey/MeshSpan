// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use meshspan_domain::{
    ApiKeyId, AssuranceLevel, EntropyError, OperationId, PrincipalId, RandomSource, Revision,
    UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    ApiKeyAuthentication, AuthoritativeCommand, BrowserSessionAccessRequest, CommandContext,
    SessionAccessDecision, SessionAccessDenial, VolumeInventoryRecord,
};
use meshspan_secret_envelope::{WrappingPrivateKey, WrappingPublicKey};

use crate::{
    BrowserSessionAuthority, BrowserSessionAuthorityError, GatewaySessionIdentity,
    IdentityAdministrator, NativeApiKeyAuthority, NativeApiKeyAuthorityError,
    VolumeAdministrationAuthority, VolumeAdministrationAuthorityError, VolumeAdministrationCommit,
    VolumeAdministrationController, VolumeAdministrationError, VolumeAdministrationService,
};

#[test]
fn exact_replay_resolves_before_requesting_entropy_or_recipients()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(Mutex::new(None));
    let authority = MockAuthority::new(Arc::clone(&state))?;
    let administrator = PrincipalId::from_bytes(uuid_v8([11; 16]))?;
    let operation = OperationId::from_bytes(uuid_v8([12; 16]))?;
    let owners = [PrincipalId::from_bytes(uuid_v8([14; 16]))?, administrator];
    let request = request(operation, "Shared files", &owners)?;
    let entropy_calls = Arc::new(Mutex::new(0_usize));
    let mut first = VolumeAdministrationService::new(
        authority.clone(),
        gateway()?,
        CountingRandom::new(Arc::clone(&entropy_calls)),
    );
    let administrator = IdentityAdministrator {
        principal_id: administrator,
        now: UnixMicros::new(100),
    };
    let created = first.create_volume(administrator, request.clone())?;
    assert!(*entropy_calls.lock().map_err(|_| "entropy lock")? > 0);
    assert_eq!(created.owner_principal_ids.len(), 2);

    let recipients_before = authority.recipient_reads();
    let observer = authority.clone();
    let mut replay = VolumeAdministrationService::new(authority, gateway()?, FailingRandom);
    let resolved = replay.create_volume(administrator, request)?;
    assert_eq!(resolved, created);
    assert_eq!(recipients_before, observer.recipient_reads());
    Ok(())
}

#[test]
fn changed_public_input_conflicts_without_generating_another_key()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(Mutex::new(None));
    let authority = MockAuthority::new(Arc::clone(&state))?;
    let administrator = PrincipalId::from_bytes(uuid_v8([21; 16]))?;
    let operation = OperationId::from_bytes(uuid_v8([22; 16]))?;
    let original = request(operation, "Original", &[administrator])?;
    let mut first = VolumeAdministrationService::new(
        authority.clone(),
        gateway()?,
        CountingRandom::new(Arc::new(Mutex::new(0))),
    );
    let identity = IdentityAdministrator {
        principal_id: administrator,
        now: UnixMicros::new(200),
    };
    first.create_volume(identity, original)?;

    let mut replay = VolumeAdministrationService::new(authority, gateway()?, FailingRandom);
    assert_eq!(
        replay.create_volume(identity, request(operation, "Changed", &[administrator])?),
        Err(VolumeAdministrationError::Conflict)
    );
    Ok(())
}

#[test]
fn concurrent_hidden_key_race_resolves_the_committed_public_request()
-> Result<(), Box<dyn std::error::Error>> {
    let state = Arc::new(Mutex::new(None));
    let authority = MockAuthority::new(state)?.with_commit_conflict();
    let administrator = PrincipalId::from_bytes(uuid_v8([25; 16]))?;
    let operation = OperationId::from_bytes(uuid_v8([26; 16]))?;
    let mut service = VolumeAdministrationService::new(
        authority,
        gateway()?,
        CountingRandom::new(Arc::new(Mutex::new(0))),
    );
    let response = service.create_volume(
        IdentityAdministrator {
            principal_id: administrator,
            now: UnixMicros::new(300),
        },
        request(operation, "Concurrent", &[administrator])?,
    )?;
    assert_eq!(response.name, "Concurrent");
    Ok(())
}

#[derive(Clone)]
struct MockAuthority {
    state: Arc<Mutex<Option<(OperationId, VolumeAdministrationCommit)>>>,
    recipient: WrappingPublicKey,
    recipient_reads: Arc<Mutex<usize>>,
    commit_conflict: bool,
}

impl MockAuthority {
    fn new(
        state: Arc<Mutex<Option<(OperationId, VolumeAdministrationCommit)>>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            state,
            recipient: WrappingPrivateKey::from_bytes([31; 32])?.public_key(),
            recipient_reads: Arc::new(Mutex::new(0)),
            commit_conflict: false,
        })
    }

    fn with_commit_conflict(mut self) -> Self {
        self.commit_conflict = true;
        self
    }

    fn recipient_reads(&self) -> usize {
        self.recipient_reads
            .lock()
            .map_or(usize::MAX, |value| *value)
    }
}

impl VolumeAdministrationAuthority for MockAuthority {
    fn is_system_manager(
        &self,
        _principal_id: PrincipalId,
        _now: UnixMicros,
    ) -> Result<bool, VolumeAdministrationAuthorityError> {
        Ok(true)
    }

    fn resolve_volume_creation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<VolumeAdministrationCommit>, VolumeAdministrationAuthorityError> {
        let state = self
            .state
            .lock()
            .map_err(|_| VolumeAdministrationAuthorityError::Failed)?;
        Ok(state
            .as_ref()
            .filter(|(stored, _)| *stored == operation_id)
            .map(|(_, commit)| commit.clone()))
    }

    fn volume_key_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, VolumeAdministrationAuthorityError> {
        let mut reads = self
            .recipient_reads
            .lock()
            .map_err(|_| VolumeAdministrationAuthorityError::Failed)?;
        *reads = reads.saturating_add(1);
        Ok(vec![self.recipient])
    }

    fn commit_or_resolve_volume_creation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<VolumeAdministrationCommit, VolumeAdministrationAuthorityError> {
        let AuthoritativeCommand::CreateVolume(value) = command else {
            return Err(VolumeAdministrationAuthorityError::Failed);
        };
        let commit = VolumeAdministrationCommit {
            request_digest: if self.commit_conflict {
                [33; 32]
            } else {
                command.request_digest(context)
            },
            result_digest: [32; 32],
            record: VolumeInventoryRecord {
                volume_id: value.volume_id,
                root_object_id: value.root_object_id,
                display_name: value.name.display().to_owned(),
                canonical_name: value.name.canonical().to_owned(),
                state: 1,
                created_at: context.occurred_at,
                revision: Revision::new(1),
            },
            owners: value.owners.as_slice().to_vec(),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| VolumeAdministrationAuthorityError::Failed)?;
        *state = Some((context.operation_id, commit.clone()));
        if self.commit_conflict {
            Err(VolumeAdministrationAuthorityError::Conflict)
        } else {
            Ok(commit)
        }
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

fn gateway() -> Result<GatewaySessionIdentity, Box<dyn std::error::Error>> {
    Ok(GatewaySessionIdentity::new(
        meshspan_domain::NodeId::from_bytes([50; 16])?,
        1,
    )?)
}

fn request(
    operation_id: OperationId,
    name: &str,
    owners: &[PrincipalId],
) -> Result<meshspan_api_contract::CreateVolumeRequest, Box<dyn std::error::Error>> {
    let owner_ids = owners
        .iter()
        .map(|owner| format!("\"{}\"", uuid_text(owner.as_bytes())))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!(
        "{{\"operation_id\":\"{}\",\"name\":\"{name}\",\"owner_principal_ids\":[{owner_ids}]}}",
        uuid_text(operation_id.as_bytes()),
    );
    Ok(meshspan_api_contract::decode_create_volume_request(
        body.as_bytes(),
    )?)
}

fn uuid_text(bytes: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
