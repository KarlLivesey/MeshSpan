// SPDX-License-Identifier: GPL-2.0-only

//! Readdress each retained volume-key generation to newly admitted gateways.

use super::{
    AuthoritativeCommand, ClusterSecretRedistributionError, CommandContext, CommitSecretGeneration,
    EntityKind, command_identities,
};
use crate::{ConsensusAuthenticationAuthority, LocalWrappingKey};
use meshspan_domain::{PrincipalId, UnixMicros};
use meshspan_metadata::{PageLimit, SecretGenerationRecord, VOLUME_CONTENT_KEY_SECRET_KIND};
use meshspan_secret_envelope::WrappingPublicKey;

pub(super) fn redistribute(
    authority: &ConsensusAuthenticationAuthority,
    decryptor: &LocalWrappingKey,
    actor: PrincipalId,
    now: UnixMicros,
    recipients: &[WrappingPublicKey],
) -> Result<(), ClusterSecretRedistributionError> {
    let mut after = None;
    loop {
        let page = authority
            .reader()
            .secret_generation_contexts(after, PageLimit::new(128)?)?;
        for context in page.items {
            if context.kind() > VOLUME_CONTENT_KEY_SECRET_KIND {
                return Ok(());
            }
            if context.kind() != VOLUME_CONTENT_KEY_SECRET_KIND {
                continue;
            }
            let current = authority
                .reader()
                .secret_generation(context)?
                .ok_or(ClusterSecretRedistributionError::MissingState)?;
            let Some(command) = extension(&current, decryptor, recipients)? else {
                continue;
            };
            let (operation_id, audit_event_id) = command_identities(&command)?;
            let request = CommandContext {
                operation_id,
                actor_principal_id: actor,
                audit_event_id,
                occurred_at: now,
                expected_revision: None,
            };
            let receipt = authority.commit_authoritative(request, &command)?;
            if receipt.operation_id != operation_id
                || receipt.request_digest != command.request_digest(request)
                || receipt.entity.kind != EntityKind::SecretGeneration
                || receipt.entity.id != context.id()
                || receipt.result_digest == [0; 32]
            {
                return Err(ClusterSecretRedistributionError::Conflict);
            }
        }
        let Some(next) = page.next else {
            return Ok(());
        };
        after = Some(next);
    }
}

fn extension(
    current: &SecretGenerationRecord,
    decryptor: &LocalWrappingKey,
    recipients: &[WrappingPublicKey],
) -> Result<Option<AuthoritativeCommand>, ClusterSecretRedistributionError> {
    let existing = current
        .recipients
        .iter()
        .map(|envelope| Ok((envelope.recipient_public_key()?, envelope)))
        .collect::<Result<Vec<_>, meshspan_secret_envelope::SecretEnvelopeError>>()?;
    let missing = recipients
        .iter()
        .filter(|recipient| !existing.iter().any(|(key, _)| key == *recipient));
    let mut additions = Vec::new();
    for recipient in missing {
        let local = existing
            .iter()
            .find(|(key, _)| *key == decryptor.public_key())
            .map(|(_, envelope)| *envelope)
            .ok_or(ClusterSecretRedistributionError::MissingState)?;
        additions.push(
            decryptor
                .rewrap_secret(&current.secret, local, *recipient)?
                .parts(),
        );
    }
    if additions.is_empty() {
        return Ok(None);
    }
    Ok(Some(AuthoritativeCommand::ExtendVolumeKeyRecipients(
        CommitSecretGeneration {
            secret: current.secret.parts(),
            recipients: additions,
        },
    )))
}
