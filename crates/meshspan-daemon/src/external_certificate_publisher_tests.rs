// SPDX-License-Identifier: GPL-2.0-only

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use meshspan_api_contract::{
    PublishExternalCertificateRequest, decode_publish_external_certificate_request,
};
use meshspan_certificates::{CertificateAuthority, ExternalCertificateRequestKey};
use meshspan_domain::{
    ApiKeyId, AssuranceLevel, EntropyError, OperationId, PrincipalId, RandomSource, Revision,
    UnixMicros,
};
use meshspan_metadata::{
    ApiKeyAuthentication, AuthoritativeCommand, CommandContext,
    ExternalCertificatePublicationRecord, SecretGenerationReference,
};
use meshspan_secret_envelope::WrappingPrivateKey;

use crate::{
    ExternalCertificatePublisherAuthority, ExternalCertificatePublisherAuthorityError,
    ExternalCertificatePublisherCommit, ExternalCertificatePublisherController,
    ExternalCertificatePublisherService, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthority, NativeApiKeyAuthorityError,
};

#[test]
fn external_publication_validates_encrypts_commits_and_replays_without_entropy()
-> Result<(), Box<dyn std::error::Error>> {
    let now = current_time()?;
    let request_material = RequestMaterial::new()?;
    let state = Arc::new(Mutex::new(None));
    let authority = MockAuthority {
        state: Arc::clone(&state),
        recipient: WrappingPrivateKey::from_bytes([42; 32])?.public_key(),
    };
    let administrator = IdentityAdministrator {
        principal_id: PrincipalId::from_bytes([43; 16])?,
        now,
    };
    let mut first =
        ExternalCertificatePublisherService::new(authority.clone(), gateway()?, FixedRandom(44));
    let response = first.publish(administrator, request_material.request()?)?;
    assert_eq!(response.generation.value(), Some(7));
    assert_eq!(response.certificate_names, ["files.example.test"]);
    assert_eq!(response.revision, 5);

    let mut replay = ExternalCertificatePublisherService::new(authority, gateway()?, FailingRandom);
    let replayed = replay.publish(administrator, request_material.request()?)?;
    assert_eq!(replayed, response);
    Ok(())
}

#[derive(Clone)]
struct MockAuthority {
    state: Arc<Mutex<Option<ExternalCertificatePublisherCommit>>>,
    recipient: meshspan_secret_envelope::WrappingPublicKey,
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

impl ExternalCertificatePublisherAuthority for MockAuthority {
    fn is_system_manager(
        &self,
        _principal_id: PrincipalId,
        _now: UnixMicros,
    ) -> Result<bool, ExternalCertificatePublisherAuthorityError> {
        Ok(true)
    }

    fn resolve_external_certificate_publication(
        &self,
        _operation_id: OperationId,
    ) -> Result<
        Option<ExternalCertificatePublisherCommit>,
        ExternalCertificatePublisherAuthorityError,
    > {
        self.state
            .lock()
            .map_err(|_| ExternalCertificatePublisherAuthorityError::Failed)
            .map(|state| state.clone())
    }

    fn certificate_secret_recipients(
        &self,
    ) -> Result<
        Vec<meshspan_secret_envelope::WrappingPublicKey>,
        ExternalCertificatePublisherAuthorityError,
    > {
        Ok(vec![self.recipient])
    }

    fn commit_or_resolve_external_certificate_publication(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<ExternalCertificatePublisherCommit, ExternalCertificatePublisherAuthorityError>
    {
        let AuthoritativeCommand::PublishExternalCertificate(value) = command else {
            return Err(ExternalCertificatePublisherAuthorityError::Failed);
        };
        let committed_revision = Revision::new(5);
        let commit = ExternalCertificatePublisherCommit {
            request_digest: command.request_digest(context),
            result_digest: [45; 32],
            committed_revision,
            publication: ExternalCertificatePublicationRecord {
                publication_id: value.publication_id,
                certificate_id: value.certificate_id,
                generation: value.generation,
                publisher_principal_id: context.actor_principal_id,
                certificate_names: value.certificate_names.as_slice().to_vec(),
                certificate: SecretGenerationReference {
                    secret_id: value.certificate_id.as_bytes(),
                    generation: value.generation,
                },
                bundle_digest: value.bundle_digest,
                chain_digest: value.chain_digest,
                public_key_fingerprint: value.public_key_fingerprint,
                not_before: value.not_before,
                not_after: value.not_after,
                created_at: context.occurred_at,
                revision: committed_revision,
            },
        };
        *self
            .state
            .lock()
            .map_err(|_| ExternalCertificatePublisherAuthorityError::Failed)? =
            Some(commit.clone());
        Ok(commit)
    }
}

struct RequestMaterial {
    certificate_chain_pem: String,
    private_key_pem: String,
}

impl RequestMaterial {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let authority = CertificateAuthority::new()?;
        let key = ExternalCertificateRequestKey::generate()?;
        let names = vec!["files.example.test".to_owned()];
        let leaf = authority.issue_public_endpoint(&names, &key)?;
        Ok(Self {
            certificate_chain_pem: format!(
                "{}{}",
                pem("CERTIFICATE", &leaf),
                pem("CERTIFICATE", authority.certificate_der())
            ),
            private_key_pem: pem("PRIVATE KEY", key.private_key_pkcs8()),
        })
    }

    fn request(
        &self,
    ) -> Result<PublishExternalCertificateRequest, meshspan_api_contract::BoundaryError> {
        let value = serde_json::json!({
            "operation_id": "01010101-0101-8101-8101-010101010101",
            "generation": "7",
            "certificate_names": ["files.example.test"],
            "certificate_chain_pem": self.certificate_chain_pem,
            "private_key_pkcs8_pem": self.private_key_pem,
        });
        let encoded = serde_json::to_vec(&value)
            .map_err(|_| meshspan_api_contract::BoundaryError::EncodeMismatch)?;
        decode_publish_external_certificate_request(&encoded)
    }
}

fn gateway() -> Result<GatewaySessionIdentity, meshspan_domain::IdentifierError> {
    Ok(GatewaySessionIdentity {
        node_id: meshspan_domain::NodeId::from_bytes([46; 16])?,
        incarnation: 1,
    })
}

fn current_time() -> Result<UnixMicros, Box<dyn std::error::Error>> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_micros()
        .try_into()?;
    Ok(UnixMicros::new(micros))
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = base64(der);
    let mut value = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        value.push_str(std::str::from_utf8(line).unwrap_or_default());
        value.push('\n');
    }
    let _ = writeln!(value, "-----END {label}-----");
    value
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(ALPHABET[((value >> 18) & 63) as usize]);
        encoded.push(ALPHABET[((value >> 12) & 63) as usize]);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 63) as usize]
        } else {
            b'='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[(value & 63) as usize]
        } else {
            b'='
        });
    }
    String::from_utf8(encoded).unwrap_or_default()
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
