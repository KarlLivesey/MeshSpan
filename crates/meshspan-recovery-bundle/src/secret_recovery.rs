// SPDX-License-Identifier: GPL-2.0-only

//! Offline recovery produces encrypted material only; installation requires a signed plan.

use meshspan_domain::RandomSource;
use meshspan_secret_envelope::{
    EncryptedSecret, MAXIMUM_SECRET_RECIPIENTS, RecipientKeyEnvelope, SecretContext,
    WrappingPublicKey, encrypt_secret,
};
use zeroize::Zeroizing;

use crate::{RecoveredAuthority, RecoveryBundleError};

/// A ciphertext generation and its complete replacement recipient set.
/// This is prepared material, not committed permission or a service-admission receipt.
pub struct RecoveredSecret {
    /// Ciphertext with its exact immutable context and authenticated digest.
    pub secret: EncryptedSecret,
    /// Canonically ordered recipients, always including the offline recovery key.
    pub recipients: Vec<RecipientKeyEnvelope>,
}

impl RecoveredAuthority {
    /// Opens one exact secret through its validated offline recipient envelope.
    /// The returned plaintext is protected and zeroised on drop; use it only within
    /// the explicit offline verification/recovery operation, never in reports or logs.
    /// # Errors
    /// Rejects malformed recipient sets, missing offline access or failed authentication.
    pub fn open_secret(
        &self,
        secret: &EncryptedSecret,
        envelopes: &[RecipientKeyEnvelope],
    ) -> Result<meshspan_secret_envelope::SecretPlaintext, RecoveryBundleError> {
        let key = self
            .recovery_envelope(secret, envelopes)?
            .open(self.wrapping_key())
            .map_err(|_| RecoveryBundleError::Corrupt)?;
        secret
            .decrypt(&key)
            .map_err(|_| RecoveryBundleError::Corrupt)
    }

    /// Recovers an existing generation without changing its ciphertext, key or context.
    /// Historical volume keys and long-lived authentication material use this path.
    /// Old online recipients are not copied implicitly. Previously learned keys cannot
    /// be erased from old nodes by replacing envelopes.
    /// # Errors
    /// Rejects missing/duplicate recovery envelopes, malformed recipient evidence,
    /// substituted ciphertext/context, invalid replacements or unavailable entropy.
    pub fn recover_secret(
        &self,
        secret: &EncryptedSecret,
        envelopes: &[RecipientKeyEnvelope],
        online_recipients: &[WrappingPublicKey],
        random: &mut impl RandomSource,
    ) -> Result<RecoveredSecret, RecoveryBundleError> {
        let recipients = self.replacement_recipients(online_recipients)?;
        let envelope = self.recovery_envelope(secret, envelopes)?;
        let recipients = envelope
            .rewrap_recipients(secret, self.wrapping_key(), &recipients, random)
            .map_err(|_| RecoveryBundleError::Corrupt)?;
        Ok(RecoveredSecret {
            secret: secret.clone(),
            recipients,
        })
    }

    /// Generates a fresh encrypted 32-byte operational key, for example a permit MAC key.
    /// The caller chooses the correct kind and next generation from verified metadata.
    /// # Errors
    /// Rejects another mesh context, invalid recipients or unavailable/reserved entropy.
    pub fn fresh_operational_key(
        &self,
        context: SecretContext,
        online_recipients: &[WrappingPublicKey],
        random: &mut impl RandomSource,
    ) -> Result<RecoveredSecret, RecoveryBundleError> {
        self.require_mesh_context(context)?;
        let recipients = self.replacement_recipients(online_recipients)?;
        let key = random_key(random)?;
        let (secret, recipients) = encrypt_secret(context, key.as_ref(), &recipients, random)
            .map_err(|_| RecoveryBundleError::Unavailable)?;
        Ok(RecoveredSecret { secret, recipients })
    }

    /// Issues a new root-signed online authority and encrypts its private key for replacements.
    /// Only its public certificate and encrypted key leave this operation. Node identity
    /// private keys are neither accepted nor produced by this method.
    /// # Errors
    /// Rejects another mesh context, invalid recipients or key/certificate/encryption failure.
    pub fn fresh_online_authority(
        &self,
        context: SecretContext,
        online_recipients: &[WrappingPublicKey],
        random: &mut impl RandomSource,
    ) -> Result<(Vec<u8>, RecoveredSecret), RecoveryBundleError> {
        self.require_mesh_context(context)?;
        let recipients = self.replacement_recipients(online_recipients)?;
        let seed = random_key(random)?;
        let authority = self.issue_online_authority_from_seed(*seed)?;
        let (secret, recipients) =
            encrypt_secret(context, authority.private_key_pkcs8(), &recipients, random)
                .map_err(|_| RecoveryBundleError::Unavailable)?;
        Ok((
            authority.certificate_der().to_vec(),
            RecoveredSecret { secret, recipients },
        ))
    }

    fn require_mesh_context(&self, context: SecretContext) -> Result<(), RecoveryBundleError> {
        if context.id() == self.mesh_id.as_bytes() {
            Ok(())
        } else {
            Err(RecoveryBundleError::InvalidInput)
        }
    }

    fn replacement_recipients(
        &self,
        online: &[WrappingPublicKey],
    ) -> Result<Vec<WrappingPublicKey>, RecoveryBundleError> {
        if online.is_empty() || online.len() >= MAXIMUM_SECRET_RECIPIENTS {
            return Err(RecoveryBundleError::InvalidInput);
        }
        let mut recipients = online.to_vec();
        recipients.push(self.public_wrapping_key());
        recipients.sort_by_key(|recipient| recipient.fingerprint());
        if recipients
            .windows(2)
            .any(|pair| pair[0].fingerprint() == pair[1].fingerprint())
        {
            return Err(RecoveryBundleError::InvalidInput);
        }
        Ok(recipients)
    }

    fn recovery_envelope<'a>(
        &self,
        secret: &EncryptedSecret,
        envelopes: &'a [RecipientKeyEnvelope],
    ) -> Result<&'a RecipientKeyEnvelope, RecoveryBundleError> {
        if envelopes.is_empty() || envelopes.len() > MAXIMUM_SECRET_RECIPIENTS {
            return Err(RecoveryBundleError::Corrupt);
        }
        let mut previous = None;
        let mut recovery = None;
        for envelope in envelopes {
            let public = envelope
                .recipient_public_key()
                .map_err(|_| RecoveryBundleError::Corrupt)?;
            let fingerprint = public.fingerprint();
            if envelope.context() != secret.context()
                || previous.is_some_and(|prior| prior >= fingerprint)
            {
                return Err(RecoveryBundleError::Corrupt);
            }
            previous = Some(fingerprint);
            if public == self.public_wrapping_key() {
                recovery = Some(envelope);
            }
        }
        recovery.ok_or(RecoveryBundleError::Corrupt)
    }
}

fn random_key(random: &mut impl RandomSource) -> Result<Zeroizing<[u8; 32]>, RecoveryBundleError> {
    let mut bytes = Zeroizing::new([0; 32]);
    random
        .fill_bytes(bytes.as_mut())
        .map_err(|_| RecoveryBundleError::Entropy)?;
    if *bytes == [0; 32] {
        return Err(RecoveryBundleError::Entropy);
    }
    Ok(bytes)
}
