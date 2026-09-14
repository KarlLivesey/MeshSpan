// SPDX-License-Identifier: GPL-2.0-only

//! Builds encrypted recovery material from verified source state, without admitting it.

use meshspan_domain::{MeshId, RandomSource};
use meshspan_recovery_bundle::{RecoveredAuthority, RecoveredSecret};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey};
use std::collections::BTreeSet;

use crate::{
    AuthoritativeRepository, CommitSecretGeneration, ONLINE_AUTHORITY_KEY_SECRET_KIND,
    RepositoryError, STORAGE_PERMIT_KEY_SECRET_KIND,
};

/// Fresh operational authority to bind into the signed replacement manifest before installation.
/// Authentication roots and content generations are deliberately not replaced by this operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryControlKeys {
    /// New offline-root-signed online intermediate certificate, containing no private key.
    pub online_certificate_der: Vec<u8>,
    /// Exact successor encrypted online-authority key and complete replacement recipients.
    pub online_authority_key: CommitSecretGeneration,
    /// Exact successor encrypted permit-MAC key and complete replacement recipients.
    pub storage_permit_key: CommitSecretGeneration,
}

impl RecoveryControlKeys {
    /// Encodes bounded encrypted planning material for an offline operator workspace.
    /// Encoding is not authority to install or activate these keys.
    /// # Errors
    /// Rejects malformed or oversized material.
    pub fn encode(&self) -> Result<Vec<u8>, crate::MetadataCommandCodecError> {
        crate::command_codec::recovery_material::encode(self)
    }

    /// Decodes untrusted offline material; repository staging still revalidates its authority.
    /// # Errors
    /// Rejects malformed, excessive or incomplete framing.
    pub fn decode(bytes: &[u8]) -> Result<Self, crate::MetadataCommandCodecError> {
        crate::command_codec::recovery_material::decode(bytes)
    }
}

impl AuthoritativeRepository {
    /// Generates new online-certificate and permit-key material for an offline recovery plan.
    /// CA keys go only to gateways; the fresh permit key also goes to storage providers. The
    /// offline recipient is always retained; no old online recipient is implicitly reused.
    /// This is read-only preparation: bind the exact outputs into the root-signed replacement
    /// manifest before installing them. Retrying generates new material, not a replay receipt.
    /// # Errors
    /// Rejects another offline authority, missing/malformed source heads, generation overflow,
    /// invalid recipient sets, failed entropy or cryptographic construction.
    pub fn prepare_recovery_control_keys(
        &self,
        recovery: &RecoveredAuthority,
        replacement_gateways: &[WrappingPublicKey],
        replacement_storage: &[WrappingPublicKey],
        random: &mut impl RandomSource,
    ) -> Result<RecoveryControlKeys, RepositoryError> {
        let mesh = self.require_recovery_identity(recovery)?;
        let (online_context, permit_context) = self.recovery_control_contexts(mesh)?;
        if replacement_storage.len() >= meshspan_secret_envelope::MAXIMUM_SECRET_RECIPIENTS {
            return Err(RepositoryError::InvalidCommand);
        }
        let mut permit_recipients: BTreeSet<_> = replacement_storage.iter().copied().collect();
        if permit_recipients.len() != replacement_storage.len() {
            return Err(RepositoryError::InvalidCommand);
        }
        let (online_certificate_der, online) = recovery
            .fresh_online_authority(online_context, replacement_gateways, random)
            .map_err(|_| RepositoryError::InvalidCommand)?;
        permit_recipients.extend(replacement_gateways.iter().copied());
        let permit = recovery
            .fresh_operational_key(
                permit_context,
                &permit_recipients.into_iter().collect::<Vec<_>>(),
                random,
            )
            .map_err(|_| RepositoryError::InvalidCommand)?;
        Ok(RecoveryControlKeys {
            online_certificate_der,
            online_authority_key: command(online),
            storage_permit_key: command(permit),
        })
    }

    pub(super) fn recovery_control_contexts(
        &self,
        mesh: MeshId,
    ) -> Result<(SecretContext, SecretContext), RepositoryError> {
        let current = self
            .online_certificate_authority(mesh)?
            .ok_or(RepositoryError::CorruptState)?;
        let online_head = self
            .latest_online_authority_generation(mesh)?
            .ok_or(RepositoryError::CorruptState)?;
        let permit_head = self
            .latest_storage_permit_generation(mesh)?
            .ok_or(RepositoryError::CorruptState)?;
        let online_context = next_context(
            ONLINE_AUTHORITY_KEY_SECRET_KIND,
            mesh,
            online_head.max(current.generation),
        )?;
        let permit_context = next_context(STORAGE_PERMIT_KEY_SECRET_KIND, mesh, permit_head)?;
        Ok((online_context, permit_context))
    }

    /// Rewraps one retained generation for replacement gateways without changing its ciphertext.
    /// Iterate the existing bounded secret inventory to include history. Preserving an
    /// authentication root preserves API-key/TOTP/SMB material; session/grant revocation is a
    /// separate activation obligation. The result is not installed or an access grant.
    /// # Errors
    /// Rejects another recovery authority, missing generations, absent or corrupt offline
    /// envelopes, invalid replacements and unavailable entropy.
    pub fn prepare_recovery_secret(
        &self,
        recovery: &RecoveredAuthority,
        context: SecretContext,
        replacement_gateways: &[WrappingPublicKey],
        random: &mut impl RandomSource,
    ) -> Result<CommitSecretGeneration, RepositoryError> {
        self.require_recovery_identity(recovery)?;
        let current = self
            .secret_generation(context)?
            .ok_or(RepositoryError::CorruptState)?;
        let recovered = recovery
            .recover_secret(
                &current.secret,
                &current.recipients,
                replacement_gateways,
                random,
            )
            .map_err(|_| RepositoryError::InvalidCommand)?;
        Ok(command(recovered))
    }

    pub(super) fn require_recovery_identity(
        &self,
        recovery: &RecoveredAuthority,
    ) -> Result<MeshId, RepositoryError> {
        let mesh = self.local_mesh_id()?.ok_or(RepositoryError::CorruptState)?;
        let expected = self
            .mesh_recovery_authority(mesh)?
            .ok_or(RepositoryError::CorruptState)?;
        if mesh != recovery.mesh_id()
            || expected.root_certificate_der != recovery.root_certificate_der()
            || expected.public_wrapping_key != recovery.public_wrapping_key()
        {
            return Err(RepositoryError::InvalidCommand);
        }
        Ok(mesh)
    }
}

fn next_context(kind: u16, mesh: MeshId, previous: u64) -> Result<SecretContext, RepositoryError> {
    let next = previous
        .checked_add(1)
        .filter(|next| *next <= i64::MAX.unsigned_abs())
        .ok_or(RepositoryError::InvalidCommand)?;
    SecretContext::new(kind, mesh.as_bytes(), next).map_err(|_| RepositoryError::InvalidCommand)
}

fn command(recovered: RecoveredSecret) -> CommitSecretGeneration {
    CommitSecretGeneration {
        secret: recovered.secret.parts(),
        recipients: recovered
            .recipients
            .into_iter()
            .map(|envelope| envelope.parts())
            .collect(),
    }
}
