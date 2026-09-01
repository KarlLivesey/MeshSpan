// SPDX-License-Identifier: GPL-2.0-only

//! Re-encryption of mesh-wide gateway secrets after the gateway set changes.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{AuditEventId, OperationId, PrincipalId, UnixMicros, uuid_v8};
use meshspan_metadata::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, AuthoritativeCommand, CommandContext,
    CommitSecretGeneration, EntityKind, ONLINE_AUTHORITY_KEY_SECRET_KIND,
    STORAGE_PERMIT_KEY_SECRET_KIND,
};
use meshspan_secret_envelope::{SecretContext, SecretEnvelopeError, encrypt_secret};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ConsensusAuthenticationAuthority, LocalWrappingKey, LocalWrappingKeyError, NodeActivationError,
    OperatingSystemRandom, SecretGenerationLoadingError,
};

const OPERATION_ID_DOMAIN: &[u8] = b"meshspan.cluster-secret-redistribution.operation.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.cluster-secret-redistribution.audit.v1\0";

/// Adds every active gateway recipient to each existing mesh-wide secret generation.
///
/// The underlying secret value is preserved. Only its authenticated ciphertext generation and
/// complete recipient-envelope set change, so already-running capabilities remain valid while a
/// newly activated gateway can open the same cluster authority.
pub(crate) fn redistribute_cluster_secrets(
    authority: &ConsensusAuthenticationAuthority,
    decryptor: &LocalWrappingKey,
    actor_principal_id: PrincipalId,
    occurred_at: UnixMicros,
) -> Result<(), ClusterSecretRedistributionError> {
    let mesh_id = authority
        .reader()
        .local_mesh_id()?
        .ok_or(ClusterSecretRedistributionError::MissingState)?;
    let recipients = authority.reader().volume_key_recipients()?;
    let generations = [
        (
            STORAGE_PERMIT_KEY_SECRET_KIND,
            authority
                .reader()
                .latest_storage_permit_generation(mesh_id)?,
        ),
        (
            AUTHENTICATION_ROOT_KEY_SECRET_KIND,
            authority
                .reader()
                .latest_authentication_root_generation(mesh_id)?,
        ),
        (
            ONLINE_AUTHORITY_KEY_SECRET_KIND,
            authority
                .reader()
                .latest_online_authority_generation(mesh_id)?,
        ),
    ];

    for (kind, generation) in generations {
        let generation = generation.ok_or(ClusterSecretRedistributionError::MissingState)?;
        redistribute_generation(
            authority,
            decryptor,
            actor_principal_id,
            occurred_at,
            kind,
            mesh_id.as_bytes(),
            generation,
            &recipients,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn redistribute_generation(
    authority: &ConsensusAuthenticationAuthority,
    decryptor: &LocalWrappingKey,
    actor_principal_id: PrincipalId,
    occurred_at: UnixMicros,
    kind: u16,
    secret_id: [u8; 16],
    generation: u64,
    recipients: &[meshspan_secret_envelope::WrappingPublicKey],
) -> Result<(), ClusterSecretRedistributionError> {
    let current_context = SecretContext::new(kind, secret_id, generation)?;
    let current = authority
        .reader()
        .secret_generation(current_context)?
        .ok_or(ClusterSecretRedistributionError::MissingState)?;
    let current_recipients = current
        .recipients
        .iter()
        .map(meshspan_secret_envelope::RecipientKeyEnvelope::recipient_public_key)
        .collect::<Result<Vec<_>, _>>()?;
    if current_recipients == recipients {
        return Ok(());
    }

    let plaintext =
        crate::volume_key_loading::load_secret_generation(authority, decryptor, current_context)?;
    let next_generation = generation
        .checked_add(1)
        .ok_or(ClusterSecretRedistributionError::MissingState)?;
    let next_context = SecretContext::new(kind, secret_id, next_generation)?;
    let (secret, envelopes) = encrypt_secret(
        next_context,
        plaintext.expose(),
        recipients,
        &mut OperatingSystemRandom,
    )?;
    let command = AuthoritativeCommand::CommitSecretGeneration(CommitSecretGeneration {
        secret: secret.parts(),
        recipients: envelopes
            .into_iter()
            .map(|envelope| envelope.parts())
            .collect(),
    });
    let (operation_id, audit_event_id) = command_identities(&command)?;
    let context = CommandContext {
        operation_id,
        actor_principal_id,
        audit_event_id,
        occurred_at,
        expected_revision: None,
    };
    let receipt = authority.commit_authoritative(context, &command)?;
    if receipt.operation_id != operation_id
        || receipt.request_digest != command.request_digest(context)
        || receipt.result_digest == [0; 32]
        || receipt.entity.kind != EntityKind::SecretGeneration
        || receipt.entity.id != secret_id
    {
        return Err(ClusterSecretRedistributionError::Conflict);
    }
    Ok(())
}

fn command_identities(
    command: &AuthoritativeCommand,
) -> Result<(OperationId, AuditEventId), ClusterSecretRedistributionError> {
    let AuthoritativeCommand::CommitSecretGeneration(generation) = command else {
        return Err(ClusterSecretRedistributionError::Conflict);
    };
    let operation = identifier(OPERATION_ID_DOMAIN, generation)?;
    let audit = identifier(AUDIT_ID_DOMAIN, generation)?;
    Ok((
        OperationId::from_bytes(operation)?,
        AuditEventId::from_bytes(audit)?,
    ))
}

fn identifier(
    domain: &[u8],
    generation: &CommitSecretGeneration,
) -> Result<[u8; 16], ClusterSecretRedistributionError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(generation.secret.context.kind().to_be_bytes());
    digest.update(generation.secret.context.id());
    digest.update(generation.secret.context.generation().to_be_bytes());
    digest.update(generation.secret.digest);
    for recipient in &generation.recipients {
        digest.update(recipient.recipient_public_key);
        digest.update(recipient.digest);
    }
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map_err(|_| ClusterSecretRedistributionError::Conflict)?;
    Ok(uuid_v8(bytes))
}

/// Closed redistribution failure which never exposes secret material.
#[derive(Debug, Error)]
pub(crate) enum ClusterSecretRedistributionError {
    /// Required replicated or local key state is absent or malformed.
    #[error("cluster secret redistribution state is invalid")]
    MissingState,
    /// Durable receipt evidence did not match the attempted generation.
    #[error("cluster secret redistribution conflicts with durable state")]
    Conflict,
    /// Root metadata could not be read safely.
    #[error("cluster secret redistribution metadata failed")]
    Repository(#[from] meshspan_metadata::RepositoryError),
    /// The node-local wrapping key could not open existing secret material.
    #[error("cluster secret redistribution key failed")]
    LocalKey(#[from] LocalWrappingKeyError),
    /// Existing encrypted secret evidence could not be loaded safely.
    #[error("cluster secret redistribution load failed")]
    Loading(#[from] SecretGenerationLoadingError),
    /// A replacement authenticated envelope generation could not be created.
    #[error("cluster secret redistribution envelope failed")]
    Envelope(#[from] SecretEnvelopeError),
    /// Consensus did not durably accept or resolve the replacement generation.
    #[error("cluster secret redistribution authority failed")]
    Authority(#[from] MetadataAuthorityRequestError),
    /// A derived identifier was invalid.
    #[error("cluster secret redistribution identifier failed")]
    Identifier(#[from] meshspan_domain::IdentifierError),
}

impl ClusterSecretRedistributionError {
    pub(crate) const fn activation_error(&self) -> NodeActivationError {
        match self {
            Self::Authority(
                MetadataAuthorityRequestError::NotLeader { .. }
                | MetadataAuthorityRequestError::Unavailable,
            )
            | Self::Envelope(SecretEnvelopeError::Entropy) => NodeActivationError::Unavailable,
            Self::Conflict | Self::Authority(MetadataAuthorityRequestError::Conflict) => {
                NodeActivationError::Conflict
            }
            Self::MissingState
            | Self::Repository(_)
            | Self::LocalKey(_)
            | Self::Loading(_)
            | Self::Envelope(_)
            | Self::Authority(_)
            | Self::Identifier(_) => NodeActivationError::Failed,
        }
    }
}
