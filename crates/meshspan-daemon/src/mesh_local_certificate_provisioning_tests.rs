// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use meshspan_api_contract::{
    ProvisionMeshLocalCertificateRequest, decode_provision_mesh_local_certificate_request,
};
use meshspan_domain::{
    ApiKeyId, AssuranceLevel, EntropyError, OperationId, PrincipalId, RandomSource, Revision,
    UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, AuthoritativeCommand, BrowserSessionAccessRequest, CommandContext,
    MeshLocalCertificateAuthorityRecord, MeshLocalCertificateIssuanceRecord,
    SecretGenerationRecord, SessionAccessDecision, SessionAccessDenial,
};
use meshspan_secret_envelope::{
    EncryptedSecret, RecipientKeyEnvelope, SecretContext, WrappingPublicKey,
};

use crate::{
    BrowserSessionAuthority, BrowserSessionAuthorityError, GatewaySessionIdentity,
    IdentityAdministrator, LocalWrappingKey, MeshLocalAuthorityCommit,
    MeshLocalCertificateAuthorityError, MeshLocalCertificateCommit,
    MeshLocalCertificateProvisioningAuthority, MeshLocalCertificateProvisioningController,
    MeshLocalCertificateProvisioningService, NativeApiKeyAuthority, NativeApiKeyAuthorityError,
    SecretGenerationAuthority, SecretGenerationAuthorityError, SystemManagerAuthenticationError,
    SystemManagerAuthority,
};

#[test]
fn authority_is_created_once_reloaded_for_rotation_and_exactly_replayed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let wrapping_key = Arc::new(LocalWrappingKey::open_or_create(
        &directory.path().join("wrapping.key"),
    )?);
    let authority = MockAuthority::new(wrapping_key.public_key());
    let administrator = IdentityAdministrator {
        principal_id: PrincipalId::from_bytes([41; 16])?,
        now: UnixMicros::new(1_800_000_000_000_000),
    };

    let mut first = MeshLocalCertificateProvisioningService::new(
        authority.clone(),
        Arc::clone(&wrapping_key),
        gateway()?,
        FixedRandom(42),
    );
    let created = first.provision(administrator, request(1, "files.mesh.test")?)?;
    assert_eq!(created.generation.value(), Some(1));
    assert_eq!(created.certificate_names, ["files.mesh.test"]);
    assert!(
        created
            .trust_anchor_pem
            .starts_with("-----BEGIN CERTIFICATE-----\n")
    );

    let mut second = MeshLocalCertificateProvisioningService::new(
        authority.clone(),
        Arc::clone(&wrapping_key),
        gateway()?,
        FixedRandom(90),
    );
    let rotated = second.provision(administrator, request(2, "node.mesh.test")?)?;
    assert_eq!(rotated.generation.value(), Some(2));
    assert_eq!(rotated.authority_id, created.authority_id);
    assert_eq!(rotated.trust_anchor_pem, created.trust_anchor_pem);

    let mut replay = MeshLocalCertificateProvisioningService::new(
        authority.clone(),
        Arc::clone(&wrapping_key),
        gateway()?,
        FailingRandom,
    );
    assert_eq!(
        replay.provision(administrator, request(2, "node.mesh.test")?)?,
        rotated
    );
    assert_eq!(authority.commit_counts(), (1, 2));
    Ok(())
}

fn request(
    suffix: u8,
    name: &str,
) -> Result<ProvisionMeshLocalCertificateRequest, meshspan_api_contract::BoundaryError> {
    let value = serde_json::json!({
        "operation_id": format!("00000000-0000-4000-8000-{suffix:012x}"),
        "certificate_names": [name]
    });
    decode_provision_mesh_local_certificate_request(&serde_json::to_vec(&value).unwrap_or_default())
}

fn gateway() -> Result<GatewaySessionIdentity, meshspan_domain::IdentifierError> {
    Ok(GatewaySessionIdentity {
        node_id: meshspan_domain::NodeId::from_bytes([43; 16])?,
        incarnation: 1,
    })
}

#[derive(Clone)]
struct MockAuthority {
    state: Arc<Mutex<MockState>>,
    recipient: WrappingPublicKey,
}

#[derive(Default)]
struct MockState {
    authority: Option<MeshLocalCertificateAuthorityRecord>,
    authority_secret: Option<SecretGenerationRecord>,
    issuances: Vec<(OperationId, MeshLocalCertificateCommit)>,
    authority_commits: usize,
    issuance_commits: usize,
}

impl MockAuthority {
    fn new(recipient: WrappingPublicKey) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState::default())),
            recipient,
        }
    }

    fn commit_counts(&self) -> (usize, usize) {
        self.state.lock().map_or((usize::MAX, usize::MAX), |state| {
            (state.authority_commits, state.issuance_commits)
        })
    }
}

impl MeshLocalCertificateProvisioningAuthority for MockAuthority {
    fn mesh_local_authority(
        &self,
    ) -> Result<Option<MeshLocalCertificateAuthorityRecord>, MeshLocalCertificateAuthorityError>
    {
        Ok(self
            .state
            .lock()
            .map_err(|_| MeshLocalCertificateAuthorityError::Failed)?
            .authority
            .clone())
    }

    fn next_mesh_local_generation(&self) -> Result<u64, MeshLocalCertificateAuthorityError> {
        self.state
            .lock()
            .map_err(|_| MeshLocalCertificateAuthorityError::Failed)?
            .issuances
            .last()
            .map_or(Ok(1), |(_, value)| {
                value
                    .issuance
                    .generation
                    .checked_add(1)
                    .ok_or(MeshLocalCertificateAuthorityError::Failed)
            })
    }

    fn resolve_mesh_local_certificate(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<MeshLocalCertificateCommit>, MeshLocalCertificateAuthorityError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| MeshLocalCertificateAuthorityError::Failed)?
            .issuances
            .iter()
            .find(|(stored, _)| *stored == operation_id)
            .map(|(_, value)| value.clone()))
    }

    fn mesh_local_secret_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, MeshLocalCertificateAuthorityError> {
        Ok(vec![self.recipient])
    }

    fn commit_or_resolve_mesh_local_authority(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<MeshLocalAuthorityCommit, MeshLocalCertificateAuthorityError> {
        let AuthoritativeCommand::CreateMeshLocalCertificateAuthority(value) = command else {
            return Err(MeshLocalCertificateAuthorityError::Failed);
        };
        let revision = Revision::new(1);
        let record = MeshLocalCertificateAuthorityRecord {
            authority_id: value.authority_id,
            generation: value.generation,
            certificate_der: value.certificate_der.clone(),
            certificate_digest: value.certificate_digest,
            authority_key: secret_reference(&value.authority_key),
            created_by: context.actor_principal_id,
            not_before: value.not_before,
            not_after: value.not_after,
            created_at: context.occurred_at,
            revision,
        };
        let secret = secret_record(&value.authority_key, revision)?;
        let commit = MeshLocalAuthorityCommit {
            request_digest: command.request_digest(context),
            result_digest: [44; 32],
            committed_revision: revision,
            authority: record.clone(),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| MeshLocalCertificateAuthorityError::Failed)?;
        state.authority = Some(record);
        state.authority_secret = Some(secret);
        state.authority_commits = state.authority_commits.saturating_add(1);
        Ok(commit)
    }

    fn commit_or_resolve_mesh_local_certificate(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<MeshLocalCertificateCommit, MeshLocalCertificateAuthorityError> {
        let AuthoritativeCommand::IssueMeshLocalCertificate(value) = command else {
            return Err(MeshLocalCertificateAuthorityError::Failed);
        };
        let revision = Revision::new(value.generation + 1);
        let issuance = MeshLocalCertificateIssuanceRecord {
            issuance_id: value.issuance_id,
            authority_id: value.authority_id,
            authority_generation: value.authority_generation,
            authority_certificate_digest: value.authority_certificate_digest,
            certificate_id: value.certificate_id,
            generation: value.generation,
            certificate_names: value.certificate_names.as_slice().to_vec(),
            certificate: secret_reference(&value.certificate),
            bundle_digest: value.bundle_digest,
            public_key_fingerprint: value.public_key_fingerprint,
            not_before: value.not_before,
            not_after: value.not_after,
            created_by: context.actor_principal_id,
            created_at: context.occurred_at,
            revision,
        };
        let commit = MeshLocalCertificateCommit {
            request_digest: command.request_digest(context),
            result_digest: [45; 32],
            committed_revision: revision,
            issuance,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| MeshLocalCertificateAuthorityError::Failed)?;
        state.issuances.push((context.operation_id, commit.clone()));
        state.issuance_commits = state.issuance_commits.saturating_add(1);
        Ok(commit)
    }
}

fn secret_record(
    value: &meshspan_metadata::CommitSecretGeneration,
    revision: Revision,
) -> Result<SecretGenerationRecord, MeshLocalCertificateAuthorityError> {
    let secret = EncryptedSecret::from_parts(value.secret.clone())
        .map_err(|_| MeshLocalCertificateAuthorityError::Failed)?;
    let recipients = value
        .recipients
        .iter()
        .cloned()
        .map(RecipientKeyEnvelope::from_parts)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| MeshLocalCertificateAuthorityError::Failed)?;
    Ok(SecretGenerationRecord {
        secret,
        recipients,
        revision,
    })
}

fn secret_reference(
    value: &meshspan_metadata::CommitSecretGeneration,
) -> meshspan_metadata::SecretGenerationReference {
    meshspan_metadata::SecretGenerationReference {
        secret_id: value.secret.context.id(),
        generation: value.secret.context.generation(),
    }
}

impl SecretGenerationAuthority for MockAuthority {
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| SecretGenerationAuthorityError::Unavailable)?
            .authority_secret
            .as_ref()
            .filter(|record| record.secret.context() == context)
            .cloned())
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

struct FixedRandom(u8);

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
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
