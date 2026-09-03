// SPDX-License-Identifier: GPL-2.0-only

//! Conversion of a validated public request into one authoritative encrypted command.

use std::net::SocketAddr;

use meshspan_acme::{
    AcmeAccountKey, CloudflareDnsSettings, DnsProviderSettings, Rfc2136DnsSettings,
    Rfc2136TsigAlgorithm as DomainTsigAlgorithm, WebhookDnsSettings,
};
use meshspan_api_contract::{
    CertificateChallenge, ProvisionCertificateRequest, Rfc2136TsigAlgorithm as ApiTsigAlgorithm,
};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AcmeConfigurationId, AuditEventId, CertificateOrderId, OperationId, RandomSource, uuid_v8,
};
use meshspan_metadata::{
    ACME_ACCOUNT_KEY_SECRET_KIND, ACME_CHALLENGE_SETTINGS_SECRET_KIND, AcmeChallengeKind,
    AuthoritativeCommand, CommandContext, CommitSecretGeneration, ConfigureAcme, ProvisionAcme,
    QueueCertificateOrder, SecretGenerationReference,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::CertificateProvisioningError;
use crate::IdentityAdministrator;
use crate::create_mesh_setup::parse_uuid;

const CONFIGURATION_ID_DOMAIN: &[u8] = b"meshspan.certificate.configuration-id.v1\0";
const ORDER_ID_DOMAIN: &[u8] = b"meshspan.certificate.order-id.v1\0";
const ACCOUNT_SECRET_ID_DOMAIN: &[u8] = b"meshspan.certificate.account-secret-id.v1\0";
const SETTINGS_SECRET_ID_DOMAIN: &[u8] = b"meshspan.certificate.settings-secret-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.certificate.audit-id.v1\0";
const INTENT_DIGEST_DOMAIN: &[u8] = b"meshspan.certificate.provisioning-intent.v1\0";
const INITIAL_SECRET_GENERATION: u64 = 1;
const ACCOUNT_KEY_BYTES: usize = 32;
const MAXIMUM_ACCOUNT_KEY_ATTEMPTS: usize = 8;

/// Stable identity of one provisioning intent, derived without reading entropy or recipients.
#[derive(Clone, Copy)]
pub(super) struct ProvisioningIdentity {
    pub(super) operation_id: OperationId,
    pub(super) configuration_id: AcmeConfigurationId,
    pub(super) order_id: CertificateOrderId,
    pub(super) intent_digest: [u8; 32],
}

impl ProvisioningIdentity {
    pub(super) fn from_request(
        request: &ProvisionCertificateRequest,
    ) -> Result<Self, CertificateProvisioningError> {
        let operation_id = domain_operation(&request.operation_id)?;
        Ok(Self {
            operation_id,
            configuration_id: derived_id(CONFIGURATION_ID_DOMAIN, operation_id)?,
            order_id: derived_id(ORDER_ID_DOMAIN, operation_id)?,
            intent_digest: intent_digest(request),
        })
    }
}

/// Creates the command only after an exact-retry lookup has missed.
pub(super) fn prepare_command(
    request: ProvisionCertificateRequest,
    identity: ProvisioningIdentity,
    administrator: IdentityAdministrator,
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<(CommandContext, AuthoritativeCommand), CertificateProvisioningError> {
    let challenge = challenge_material(request.challenge)?;
    let account_reference = secret_reference(ACCOUNT_SECRET_ID_DOMAIN, identity.operation_id);
    let settings_reference = challenge
        .settings
        .as_ref()
        .map(|_| secret_reference(SETTINGS_SECRET_ID_DOMAIN, identity.operation_id));
    let account_key_generation = account_key_generation(account_reference, recipients, random)?;
    let challenge_settings_generation = challenge
        .settings
        .as_deref()
        .zip(settings_reference)
        .map(|(plaintext, reference)| {
            encrypted_generation(
                ACME_CHALLENGE_SETTINGS_SECRET_KIND,
                reference,
                plaintext,
                recipients,
                random,
            )
            .map(Box::new)
        })
        .transpose()?;
    let command = AuthoritativeCommand::ProvisionAcme(Box::new(ProvisionAcme {
        intent_digest: identity.intent_digest,
        configuration: ConfigureAcme {
            config_id: identity.configuration_id,
            directory_url: request.directory_url,
            account_key: account_reference,
            challenge_kind: challenge.kind,
            challenge_settings: settings_reference,
            certificate_names: BoundedItems::new(request.certificate_names, 256)
                .map_err(|_| CertificateProvisioningError::InvalidInput)?,
        },
        account_key_generation,
        challenge_settings_generation,
        initial_order: QueueCertificateOrder {
            order_id: identity.order_id,
            config_id: identity.configuration_id,
            next_attempt_at: administrator.now,
        },
    }));
    Ok((
        command_context(identity.operation_id, administrator)?,
        command,
    ))
}

struct ChallengeMaterial {
    kind: AcmeChallengeKind,
    settings: Option<Zeroizing<Vec<u8>>>,
}

fn challenge_material(
    challenge: CertificateChallenge,
) -> Result<ChallengeMaterial, CertificateProvisioningError> {
    let settings = match challenge {
        CertificateChallenge::Http01 => {
            return Ok(ChallengeMaterial {
                kind: AcmeChallengeKind::Http01,
                settings: None,
            });
        }
        CertificateChallenge::Dns01Manual => None,
        CertificateChallenge::Dns01Rfc2136 {
            server,
            zone,
            key_name,
            algorithm,
            secret,
        } => Some(DnsProviderSettings::Rfc2136(
            Rfc2136DnsSettings::new(
                server
                    .parse::<SocketAddr>()
                    .map_err(|_| CertificateProvisioningError::InvalidInput)?,
                zone,
                key_name,
                match algorithm {
                    ApiTsigAlgorithm::HmacSha256 => DomainTsigAlgorithm::HmacSha256,
                    ApiTsigAlgorithm::HmacSha512 => DomainTsigAlgorithm::HmacSha512,
                },
                secret.into_bytes(),
            )
            .map_err(|_| CertificateProvisioningError::InvalidInput)?,
        )),
        CertificateChallenge::Dns01Cloudflare { zone_id, api_token } => {
            Some(DnsProviderSettings::Cloudflare(
                CloudflareDnsSettings::new(zone_id, api_token.into_bytes())
                    .map_err(|_| CertificateProvisioningError::InvalidInput)?,
            ))
        }
        CertificateChallenge::Dns01Webhook {
            endpoint,
            bearer_token,
        } => Some(DnsProviderSettings::Webhook(
            WebhookDnsSettings::new(endpoint, bearer_token.into_bytes())
                .map_err(|_| CertificateProvisioningError::InvalidInput)?,
        )),
    };
    let encoded = settings
        .map(|value| value.encode())
        .transpose()
        .map_err(|_| CertificateProvisioningError::InvalidInput)?;
    Ok(ChallengeMaterial {
        kind: AcmeChallengeKind::Dns01,
        settings: encoded,
    })
}

fn account_key_generation(
    reference: SecretGenerationReference,
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<Box<CommitSecretGeneration>, CertificateProvisioningError> {
    let mut plaintext = Zeroizing::new([0_u8; ACCOUNT_KEY_BYTES]);
    for _ in 0..MAXIMUM_ACCOUNT_KEY_ATTEMPTS {
        random
            .fill_bytes(plaintext.as_mut())
            .map_err(|_| CertificateProvisioningError::Unavailable)?;
        if AcmeAccountKey::from_secret_bytes(plaintext.as_ref()).is_ok() {
            return encrypted_generation(
                ACME_ACCOUNT_KEY_SECRET_KIND,
                reference,
                plaintext.as_ref(),
                recipients,
                random,
            )
            .map(Box::new);
        }
    }
    Err(CertificateProvisioningError::Unavailable)
}

fn encrypted_generation(
    kind: u16,
    reference: SecretGenerationReference,
    plaintext: &[u8],
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<CommitSecretGeneration, CertificateProvisioningError> {
    let context = SecretContext::new(kind, reference.secret_id, reference.generation)
        .map_err(|_| CertificateProvisioningError::Failed)?;
    let (secret, envelopes) = encrypt_secret(context, plaintext, recipients, random)
        .map_err(|_| CertificateProvisioningError::Unavailable)?;
    Ok(CommitSecretGeneration {
        secret: secret.parts(),
        recipients: envelopes.into_iter().map(|value| value.parts()).collect(),
    })
}

fn intent_digest(request: &ProvisionCertificateRequest) -> [u8; 32] {
    let mut digest = Sha256::new();
    field(&mut digest, INTENT_DIGEST_DOMAIN);
    field(&mut digest, request.operation_id.as_str().as_bytes());
    field(&mut digest, request.directory_url.as_bytes());
    for name in &request.certificate_names {
        field(&mut digest, name.as_bytes());
    }
    match &request.challenge {
        CertificateChallenge::Http01 => field(&mut digest, b"http-01"),
        CertificateChallenge::Dns01Manual => field(&mut digest, b"dns-01-manual"),
        CertificateChallenge::Dns01Rfc2136 {
            server,
            zone,
            key_name,
            algorithm,
            secret,
        } => {
            field(&mut digest, b"dns-01-rfc2136");
            field(&mut digest, server.as_bytes());
            field(&mut digest, zone.as_bytes());
            field(&mut digest, key_name.as_bytes());
            field(
                &mut digest,
                match algorithm {
                    ApiTsigAlgorithm::HmacSha256 => b"hmac-sha256",
                    ApiTsigAlgorithm::HmacSha512 => b"hmac-sha512",
                },
            );
            field(&mut digest, secret.as_bytes());
        }
        CertificateChallenge::Dns01Cloudflare { zone_id, api_token } => {
            field(&mut digest, b"dns-01-cloudflare");
            field(&mut digest, zone_id.as_bytes());
            field(&mut digest, api_token.as_bytes());
        }
        CertificateChallenge::Dns01Webhook {
            endpoint,
            bearer_token,
        } => {
            field(&mut digest, b"dns-01-webhook");
            field(&mut digest, endpoint.as_bytes());
            field(&mut digest, bearer_token.as_bytes());
        }
    }
    digest.finalize().into()
}

fn field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn secret_reference(domain: &[u8], operation_id: OperationId) -> SecretGenerationReference {
    SecretGenerationReference {
        secret_id: derived_bytes(domain, operation_id),
        generation: INITIAL_SECRET_GENERATION,
    }
}

fn derived_id<T: DerivedIdentifier>(
    domain: &[u8],
    operation_id: OperationId,
) -> Result<T, CertificateProvisioningError> {
    T::from_derived_bytes(derived_bytes(domain, operation_id))
        .map_err(|_| CertificateProvisioningError::Failed)
}

fn derived_bytes(domain: &[u8], operation_id: OperationId) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(operation_id.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    uuid_v8(bytes)
}

fn domain_operation(
    value: &meshspan_api_contract::OperationId,
) -> Result<OperationId, CertificateProvisioningError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| CertificateProvisioningError::InvalidInput)?,
    )
    .map_err(|_| CertificateProvisioningError::InvalidInput)
}

fn command_context(
    operation_id: OperationId,
    administrator: IdentityAdministrator,
) -> Result<CommandContext, CertificateProvisioningError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(administrator.principal_id.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(uuid_v8(bytes))
            .map_err(|_| CertificateProvisioningError::Failed)?,
        occurred_at: administrator.now,
        expected_revision: None,
    })
}

trait DerivedIdentifier: Sized {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError>;
}

impl DerivedIdentifier for AcmeConfigurationId {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

impl DerivedIdentifier for CertificateOrderId {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}
