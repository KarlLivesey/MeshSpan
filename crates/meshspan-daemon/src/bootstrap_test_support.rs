// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{EntropyError, RandomSource};
use meshspan_metadata::{
    BootstrapAppliance, BootstrapMesh, BootstrapRecoveryIdentity, CommitSecretGeneration,
    CreateAuthenticationMethod, RegisterNodeWrappingKey, STORAGE_PERMIT_KEY_SECRET_KIND,
};
use meshspan_secret_envelope::{
    SecretContext, SecretEnvelopeError, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};

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
    Ok(BootstrapAppliance {
        node_wrapping_key: RegisterNodeWrappingKey {
            node_id: mesh.node_id,
            generation: 1,
            public_key: node_key.as_bytes(),
            key_fingerprint: node_key.fingerprint(),
        },
        storage_permit_key_generation: Box::new(CommitSecretGeneration {
            secret: secret.parts(),
            recipients: recipients
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
