// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{EntropyError, RandomSource};
use meshspan_secret_envelope::{
    SecretContext, SecretEnvelopeError, WrappingPrivateKey, encrypt_secret,
};

use crate::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, BootstrapAppliance, BootstrapMesh,
    BootstrapRecoveryIdentity, CommitSecretGeneration, CreateAuthenticationMethod,
    ONLINE_AUTHORITY_KEY_SECRET_KIND, RegisterNodeWrappingKey, STORAGE_PERMIT_KEY_SECRET_KIND,
};

pub(crate) fn bootstrap_appliance(
    mesh: BootstrapMesh,
    authentication: CreateAuthenticationMethod,
    recovery: Box<BootstrapRecoveryIdentity>,
) -> Result<BootstrapAppliance, SecretEnvelopeError> {
    let wrapping_public_key = node_wrapping_private_key()?.public_key();
    let recovery_public_key =
        meshspan_secret_envelope::WrappingPublicKey::from_bytes(recovery.public_wrapping_key)?;
    let context = SecretContext::new(STORAGE_PERMIT_KEY_SECRET_KIND, mesh.mesh_id.as_bytes(), 1)?;
    let (secret, recipients) = encrypt_secret(
        context,
        &[202; 32],
        &[wrapping_public_key, recovery_public_key],
        &mut SequentialRandom(11),
    )?;
    let authentication_context = SecretContext::new(
        AUTHENTICATION_ROOT_KEY_SECRET_KIND,
        mesh.mesh_id.as_bytes(),
        1,
    )?;
    let (authentication_secret, authentication_recipients) = encrypt_secret(
        authentication_context,
        &[203; 32],
        &[wrapping_public_key, recovery_public_key],
        &mut SequentialRandom(21),
    )?;
    let (online_authority_secret, online_authority_recipients) = encrypt_secret(
        SecretContext::new(ONLINE_AUTHORITY_KEY_SECRET_KIND, mesh.mesh_id.as_bytes(), 1)?,
        &[204; 96],
        &[wrapping_public_key, recovery_public_key],
        &mut SequentialRandom(31),
    )?;
    Ok(BootstrapAppliance {
        node_wrapping_key: RegisterNodeWrappingKey {
            node_id: mesh.node_id,
            generation: 1,
            public_key: wrapping_public_key.as_bytes(),
            key_fingerprint: wrapping_public_key.fingerprint(),
        },
        storage_permit_key_generation: Box::new(CommitSecretGeneration {
            secret: secret.parts(),
            recipients: recipients
                .iter()
                .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                .collect(),
        }),
        authentication_root_key_generation: Box::new(CommitSecretGeneration {
            secret: authentication_secret.parts(),
            recipients: authentication_recipients
                .iter()
                .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                .collect(),
        }),
        online_authority_key_generation: Box::new(CommitSecretGeneration {
            secret: online_authority_secret.parts(),
            recipients: online_authority_recipients
                .iter()
                .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                .collect(),
        }),
        mesh,
        authentication,
        recovery,
    })
}

pub(crate) fn node_wrapping_private_key() -> Result<WrappingPrivateKey, SecretEnvelopeError> {
    WrappingPrivateKey::from_bytes([201; 32])
}

struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}
