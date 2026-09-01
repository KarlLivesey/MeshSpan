// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{EntropyError, RandomSource, UnixMicros};
use meshspan_metadata::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, BootstrapAppliance, BootstrapMesh,
    BootstrapNodeCertificate, BootstrapRecoveryIdentity, CommitSecretGeneration,
    CreateAuthenticationMethod, ONLINE_AUTHORITY_KEY_SECRET_KIND, RegisterNodeWrappingKey,
    STORAGE_PERMIT_KEY_SECRET_KIND,
};
use meshspan_secret_envelope::{
    SecretContext, SecretEnvelopeError, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};
use sha2::{Digest, Sha256};

pub(crate) fn bootstrap_appliance(
    mesh: BootstrapMesh,
    authentication: CreateAuthenticationMethod,
    recovery: Box<BootstrapRecoveryIdentity>,
) -> Result<BootstrapAppliance, SecretEnvelopeError> {
    let node_key = WrappingPrivateKey::from_bytes([92; 32])?.public_key();
    bootstrap_appliance_with_node_key(mesh, authentication, recovery, node_key)
}

pub(crate) fn bootstrap_appliance_with_node_key(
    mesh: BootstrapMesh,
    authentication: CreateAuthenticationMethod,
    recovery: Box<BootstrapRecoveryIdentity>,
    node_key: WrappingPublicKey,
) -> Result<BootstrapAppliance, SecretEnvelopeError> {
    let recovery_key = WrappingPublicKey::from_bytes(recovery.public_wrapping_key)?;
    let (secret, recipients) = encrypt_secret(
        SecretContext::new(STORAGE_PERMIT_KEY_SECRET_KIND, mesh.mesh_id.as_bytes(), 1)?,
        &[93; 32],
        &[node_key, recovery_key],
        &mut TestRandom(94),
    )?;
    let (authentication_secret, authentication_recipients) = encrypt_secret(
        SecretContext::new(
            AUTHENTICATION_ROOT_KEY_SECRET_KIND,
            mesh.mesh_id.as_bytes(),
            1,
        )?,
        &[95; 32],
        &[node_key, recovery_key],
        &mut TestRandom(96),
    )?;
    let (online_authority_secret, online_authority_recipients) = encrypt_secret(
        SecretContext::new(ONLINE_AUTHORITY_KEY_SECRET_KIND, mesh.mesh_id.as_bytes(), 1)?,
        &[97; 96],
        &[node_key, recovery_key],
        &mut TestRandom(98),
    )?;
    Ok(BootstrapAppliance {
        node_wrapping_key: RegisterNodeWrappingKey {
            node_id: mesh.node_id,
            generation: 1,
            public_key: node_key.as_bytes(),
            key_fingerprint: node_key.fingerprint(),
        },
        node_certificate: BootstrapNodeCertificate {
            certificate_der: vec![99; 64],
            certificate_fingerprint: Sha256::digest([99; 64]).into(),
            certificate_valid_until: UnixMicros::new(i64::MAX),
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

struct TestRandom(u8);

impl RandomSource for TestRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}
