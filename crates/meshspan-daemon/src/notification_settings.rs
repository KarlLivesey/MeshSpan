// SPDX-License-Identifier: GPL-2.0-only

//! Private settings envelopes retain their binding when gateway recipients change.

use meshspan_api_contract::{NotificationDestination, decode_notification_destination};
use meshspan_domain::RandomSource;
use meshspan_metadata::{CommitSecretGeneration, SecretGenerationReference};
use meshspan_metadata::{NOTIFICATION_SETTINGS_SECRET_KIND, NotificationChannelRecord};
use meshspan_secret_envelope::SecretContext;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{ConsensusAuthenticationAuthority, LocalWrappingKey};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("notification settings are unavailable or failed validation")]
pub(crate) struct NotificationSettingsError;

pub(crate) struct PreparedSettings {
    pub reference: SecretGenerationReference,
    pub commitment: [u8; 32],
    pub generation: Box<CommitSecretGeneration>,
}

pub(crate) fn prepare(
    authority: &ConsensusAuthenticationAuthority,
    id: [u8; 16],
    destination: &NotificationDestination,
) -> Result<PreparedSettings, NotificationSettingsError> {
    let json =
        Zeroizing::new(serde_json::to_vec(destination).map_err(|_| NotificationSettingsError)?);
    decode_notification_destination(&json).map_err(|_| NotificationSettingsError)?;
    let mut plaintext = Zeroizing::new(vec![0; 33]);
    plaintext[0] = 1;
    crate::OperatingSystemRandom
        .fill_bytes(&mut plaintext[1..33])
        .map_err(|_| NotificationSettingsError)?;
    plaintext.extend_from_slice(&json);
    let commitment = Sha256::digest(&plaintext).into();
    let recipients = authority
        .reader()
        .volume_key_recipients()
        .map_err(|_| NotificationSettingsError)?;
    let context = SecretContext::new(NOTIFICATION_SETTINGS_SECRET_KIND, id, 1)
        .map_err(|_| NotificationSettingsError)?;
    let (secret, envelopes) = meshspan_secret_envelope::encrypt_secret(
        context,
        &plaintext,
        &recipients,
        &mut crate::OperatingSystemRandom,
    )
    .map_err(|_| NotificationSettingsError)?;
    Ok(PreparedSettings {
        reference: SecretGenerationReference {
            secret_id: id,
            generation: 1,
        },
        commitment,
        generation: Box::new(CommitSecretGeneration {
            secret: secret.parts(),
            recipients: envelopes.into_iter().map(|value| value.parts()).collect(),
        }),
    })
}

pub(crate) fn load(
    authority: &ConsensusAuthenticationAuthority,
    key: &LocalWrappingKey,
    channel: &NotificationChannelRecord,
) -> Result<NotificationDestination, NotificationSettingsError> {
    let settings = authority
        .reader()
        .notification_settings_generation(channel.settings)
        .map_err(|_| NotificationSettingsError)?;
    let context = SecretContext::new(
        NOTIFICATION_SETTINGS_SECRET_KIND,
        settings.secret_id,
        settings.generation,
    )
    .map_err(|_| NotificationSettingsError)?;
    let plaintext = crate::volume_key_loading::load_secret_generation(authority, key, context)
        .map_err(|_| NotificationSettingsError)?;
    decode(plaintext.expose(), channel.settings_commitment)
}

pub(crate) fn decode(
    plaintext: &[u8],
    commitment: [u8; 32],
) -> Result<NotificationDestination, NotificationSettingsError> {
    // Version byte, 32-byte private random nonce, then strict destination JSON.
    if !(34..=16 * 1024 + 33).contains(&plaintext.len())
        || plaintext.first() != Some(&1)
        || commitment == [0; 32]
        || <[u8; 32]>::from(Sha256::digest(plaintext)) != commitment
    {
        return Err(NotificationSettingsError);
    }
    decode_notification_destination(&plaintext[33..]).map_err(|_| NotificationSettingsError)
}
