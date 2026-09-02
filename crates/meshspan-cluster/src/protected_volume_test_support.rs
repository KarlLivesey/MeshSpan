// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{
    ApiKeyId, AuthenticationMethodId, EntropyError, MeshId, RandomSource, UnixMicros, VolumeId,
};
use meshspan_metadata::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, AuthoritativeCommand, BootstrapAppliance, BootstrapMesh,
    BootstrapNodeCertificate, BootstrapRecoveryIdentity, CommitSecretGeneration,
    ConfirmRecoveryBundleSaved, CreateAuthenticationMethod, NewAuthenticationCredential,
    ONLINE_AUTHORITY_KEY_SECRET_KIND, RegisterNodeWrappingKey, STORAGE_PERMIT_KEY_SECRET_KIND,
    VOLUME_CONTENT_KEY_SECRET_KIND,
};
use meshspan_secret_envelope::{
    SecretContext, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};
use sha2::{Digest, Sha256};

const RECOVERY_PUBLIC_KEY: [u8; 32] = [201; 32];
const BUNDLE_DIGEST: [u8; 32] = [202; 32];
const SAVE_CHALLENGE_COMMITMENT: [u8; 32] = [203; 32];
const GATEWAY_PRIVATE_KEY: [u8; 32] = [210; 32];

pub(crate) fn protected_bootstrap(
    mesh: BootstrapMesh,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    let recovery_key = WrappingPublicKey::from_bytes(RECOVERY_PUBLIC_KEY)?;
    let gateway_key = WrappingPrivateKey::from_bytes(GATEWAY_PRIVATE_KEY)?.public_key();
    let certificate = vec![204; 64];
    let (permit_secret, permit_recipients) = encrypt_secret(
        SecretContext::new(STORAGE_PERMIT_KEY_SECRET_KIND, mesh.mesh_id.as_bytes(), 1)?,
        &[211; 32],
        &[gateway_key, recovery_key],
        &mut TestRandom(212),
    )?;
    let (authentication_secret, authentication_recipients) = encrypt_secret(
        SecretContext::new(
            AUTHENTICATION_ROOT_KEY_SECRET_KIND,
            mesh.mesh_id.as_bytes(),
            1,
        )?,
        &[213; 32],
        &[gateway_key, recovery_key],
        &mut TestRandom(214),
    )?;
    let (online_authority_secret, online_authority_recipients) = encrypt_secret(
        SecretContext::new(ONLINE_AUTHORITY_KEY_SECRET_KIND, mesh.mesh_id.as_bytes(), 1)?,
        &[215; 96],
        &[gateway_key, recovery_key],
        &mut TestRandom(216),
    )?;
    let online_certificate = vec![217; 64];
    let administrator_id = mesh.administrator_id;
    let node_id = mesh.node_id;
    Ok(AuthoritativeCommand::BootstrapAppliance(Box::new(
        BootstrapAppliance {
            authentication: CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([205; 16])?,
                principal_id: administrator_id,
                label: "Test bootstrap key".to_owned(),
                service_scope: 7,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([206; 16])?,
                    key_digest: [207; 32],
                    smb_verifier_ciphertext: Some(vec![208; 65]),
                    scopes: 7,
                    valid_from: UnixMicros::new(100),
                },
            },
            recovery: Box::new(BootstrapRecoveryIdentity {
                public_wrapping_key: recovery_key.as_bytes(),
                key_fingerprint: recovery_key.fingerprint(),
                root_certificate_digest: Sha256::digest(&certificate).into(),
                root_certificate_der: certificate,
                online_authority_certificate_digest: Sha256::digest(&online_certificate).into(),
                online_authority_certificate_der: online_certificate,
                bundle_digest: BUNDLE_DIGEST,
                save_challenge_commitment: SAVE_CHALLENGE_COMMITMENT,
            }),
            node_wrapping_key: RegisterNodeWrappingKey {
                node_id,
                generation: 1,
                public_key: gateway_key.as_bytes(),
                key_fingerprint: gateway_key.fingerprint(),
            },
            node_certificate: BootstrapNodeCertificate {
                certificate_der: vec![218; 64],
                certificate_fingerprint: Sha256::digest([218; 64]).into(),
                certificate_valid_until: UnixMicros::new(10_000_000),
            },
            storage_permit_key_generation: Box::new(CommitSecretGeneration {
                secret: permit_secret.parts(),
                recipients: permit_recipients
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
        },
    )))
}

pub(crate) fn confirm_recovery(mesh_id: MeshId) -> AuthoritativeCommand {
    AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
        mesh_id,
        bundle_digest: BUNDLE_DIGEST,
        save_challenge_commitment: SAVE_CHALLENGE_COMMITMENT,
    })
}

pub(crate) fn initial_volume_key(
    volume_id: VolumeId,
) -> Result<Box<CommitSecretGeneration>, Box<dyn std::error::Error>> {
    let recipients = [
        WrappingPublicKey::from_bytes(RECOVERY_PUBLIC_KEY)?,
        WrappingPrivateKey::from_bytes(GATEWAY_PRIVATE_KEY)?.public_key(),
    ];
    let (secret, recipients) = encrypt_secret(
        SecretContext::new(VOLUME_CONTENT_KEY_SECRET_KIND, volume_id.as_bytes(), 1)?,
        &[208; 32],
        &recipients,
        &mut TestRandom(209),
    )?;
    Ok(Box::new(CommitSecretGeneration {
        secret: secret.parts(),
        recipients: recipients
            .into_iter()
            .map(|recipient| recipient.parts())
            .collect(),
    }))
}

struct TestRandom(u8);

impl RandomSource for TestRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
