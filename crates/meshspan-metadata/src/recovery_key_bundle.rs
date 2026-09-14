// SPDX-License-Identifier: GPL-2.0-only

//! Streaming recovery-key transfer. The recipient never receives the offline private root.

use std::io::{Read, Write};

use meshspan_certificates::{OnlineCertificateAuthority, validate_online_authority_certificate};
use meshspan_domain::{MeshId, NodeId, OperationId, PartitionId};
use meshspan_recovery_bundle::RecoveryAuthorization;
use meshspan_secret_envelope::{
    EncryptedSecret, RecipientKeyEnvelope, SecretPlaintext, WrappingPublicKey,
};
use sha2::{Digest as _, Sha256};

use crate::command_codec::recovery_material;
use crate::{
    CommitSecretGeneration, JoinRoles, ONLINE_AUTHORITY_KEY_SECRET_KIND, RecoveryControlKeys,
    RecoveryNodeCertificate, RecoveryReplacementPlan, RecoverySecretInventoryBuilder,
    RepositoryError, STORAGE_PERMIT_KEY_SECRET_KIND,
};

pub(crate) const BUNDLE_MAGIC: [u8; 7] = *b"MSRKBN\x03";
const MAXIMUM_MATERIAL_BYTES: usize = 1024 * 1024;

/// Writes one bounded encrypted planning record without a fabricated command actor.
/// The enclosing operator spool owns its record count and durable publication.
/// # Errors
/// Rejects invalid/oversized material and output failure; partial output must be discarded.
pub fn write_prepared_recovery_secret(
    output: &mut impl Write,
    material: &CommitSecretGeneration,
) -> Result<(), RecoveryKeyBundleError> {
    write_frame(
        output,
        &recovery_material::encode_secret(material).map_err(|_| RecoveryKeyBundleError::Invalid)?,
    )
}

/// Reads one bounded encrypted planning record. This grants no installation authority.
/// The caller enforces exact inventory count and EOF; staging revalidates source/key bindings.
/// # Errors
/// Rejects malformed, excessive, truncated or invalid records before unbounded allocation.
pub fn read_prepared_recovery_secret(
    input: &mut impl Read,
) -> Result<CommitSecretGeneration, RecoveryKeyBundleError> {
    recovery_material::decode_secret(&read_frame(input, MAXIMUM_MATERIAL_BYTES)?)
        .map_err(|_| RecoveryKeyBundleError::Invalid)
}

/// Public identities read from existing protected node-local keys, not from the bundle.
#[derive(Clone, Copy)]
pub struct RecoveryKeyRecipient {
    /// Exact replacement node to install.
    pub node_id: NodeId,
    /// Canonical P-256 identity of the node's existing private signing key.
    pub identity_public_key: [u8; 65],
    /// Public half of the node's existing private wrapping key.
    pub wrapping_public_key: WrappingPublicKey,
}

/// Successful complete-stream verification, not proof of durable installation or admission.
/// Only this module constructs it. A node may sign its message after durable local publication.
pub struct RecoveryKeyBundleVerification {
    mesh_id: MeshId,
    partition_id: PartitionId,
    recovery_id: OperationId,
    recovery_epoch: u64,
    node_id: NodeId,
    incarnation: u64,
    manifest_digest: [u8; 32],
    bundle_digest: [u8; 32],
    verified_generations: u64,
    node_certificate: RecoveryNodeCertificate,
    replacement_node: crate::RecoveryReplacementNode,
}

impl RecoveryKeyBundleVerification {
    /// Checks that this verified recipient bundle belongs to the signed state delivery.
    /// The caller also verifies the bundle length and the independently signed metadata image.
    #[must_use]
    pub fn matches_state_transfer(
        &self,
        transfer: &meshspan_recovery_bundle::RecoveryStateTransfer,
    ) -> bool {
        let delivery = transfer.claims();
        let recovery = delivery.authorization.claims();
        self.mesh_id == recovery.mesh_id
            && self.partition_id == recovery.partition_id
            && self.recovery_id == recovery.recovery_id
            && self.recovery_epoch == recovery.recovery_epoch
            && self.node_id == delivery.node_id
            && self.incarnation == delivery.incarnation
            && self.manifest_digest == recovery.replacement_manifest_digest
            && self.bundle_digest == delivery.key_bundle_digest
    }

    // Shared transcript construction for recipient verification and coordinator expectations.
    // This does not create installation evidence: the coordinator still needs a node signature.
    pub(crate) fn from_plan(
        plan: &RecoveryReplacementPlan,
        node_id: NodeId,
        bundle_digest: [u8; 32],
        node_certificate: RecoveryNodeCertificate,
    ) -> Result<Self, RecoveryKeyBundleError> {
        let node = plan
            .nodes
            .iter()
            .find(|node| node.node_id == node_id)
            .ok_or(RecoveryKeyBundleError::Authority)?;
        Ok(Self {
            mesh_id: plan.mesh_id,
            partition_id: plan.partition_id,
            recovery_id: plan.recovery_id,
            recovery_epoch: plan.recovery_epoch,
            node_id,
            incarnation: node.incarnation,
            manifest_digest: plan.digest().map_err(|_| RecoveryKeyBundleError::Invalid)?,
            bundle_digest,
            verified_generations: if node.roles.bits() & JoinRoles::GATEWAY != 0 {
                plan.secrets
                    .generation_count
                    .checked_add(2)
                    .ok_or(RecoveryKeyBundleError::Invalid)?
            } else {
                u64::from(node.roles.bits() & JoinRoles::STORAGE != 0)
            },
            node_certificate,
            replacement_node: node.clone(),
        })
    }

    /// Exact SHA-256 of the validated transfer, including all encrypted frames.
    #[must_use]
    pub const fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_digest
    }

    /// Exact selected public node/role description validated against the signed plan.
    #[must_use]
    pub const fn replacement_node(&self) -> &crate::RecoveryReplacementNode {
        &self.replacement_node
    }

    /// Number of generations opened by this recipient, including the fresh control pair.
    /// Storage-only recipients open only the fresh storage-permit key and report one.
    #[must_use]
    pub const fn verified_generations(&self) -> u64 {
        self.verified_generations
    }

    /// Validated replacement certificate installed inside these exact encrypted bundle bytes.
    /// Consumers must separately enforce current validity and recovery service admission.
    #[must_use]
    pub const fn node_certificate(&self) -> &RecoveryNodeCertificate {
        &self.node_certificate
    }

    /// Canonical installation-attestation transcript, bound to exact bytes and node incarnation.
    /// Signing proves node identity and its claim of installation, not physical disk health.
    /// Callers must first durably publish the same validated bytes. This is never service admission.
    #[must_use]
    pub fn installation_message(&self) -> Vec<u8> {
        let mut bytes = b"MeshSpan recovery key installation v3\0".to_vec();
        bytes.extend_from_slice(&self.mesh_id.as_bytes());
        bytes.extend_from_slice(&self.partition_id.as_bytes());
        bytes.extend_from_slice(&self.recovery_id.as_bytes());
        bytes.extend_from_slice(&self.recovery_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.node_id.as_bytes());
        bytes.extend_from_slice(&self.incarnation.to_be_bytes());
        bytes.extend_from_slice(&self.manifest_digest);
        bytes.extend_from_slice(&self.bundle_digest);
        bytes.extend_from_slice(&self.verified_generations.to_be_bytes());
        bytes
    }
}

/// Authenticates a complete bounded-frame stream against an independently trusted public root.
/// Gateway recipients open every exact assigned envelope through their node-local decryptor;
/// storage-only recipients open only the fresh permit key, never gateway or historical keys.
/// Plaintexts are dropped and zeroised after
/// verification. All recipients independently recompute the signed complete-key commitment.
/// The decryptor must open the supplied secret with the supplied envelope using this recipient's
/// private key; returning unrelated plaintext violates its node-local implementation contract.
/// No private offline authority, network call or host clock is needed.
/// # Errors
/// Rejects unsigned/substituted plans, wrong local keys, incomplete/duplicate/reordered material,
/// malformed or excessive frames, failed decryption, changed ciphertext and trailing bytes.
pub fn verify_recovery_key_bundle<E>(
    input: &mut impl Read,
    trusted_root: &[u8],
    recipient: RecoveryKeyRecipient,
    mut decrypt: impl FnMut(&EncryptedSecret, &RecipientKeyEnvelope) -> Result<SecretPlaintext, E>,
) -> Result<RecoveryKeyBundleVerification, RecoveryKeyBundleError> {
    let mut input = DigestReader {
        inner: input,
        digest: Sha256::new(),
    };
    let mut magic = [0; 7];
    input.read_exact(&mut magic)?;
    let mut node_id = [0; 16];
    input.read_exact(&mut node_id)?;
    if magic != BUNDLE_MAGIC || node_id != recipient.node_id.as_bytes() {
        return Err(RecoveryKeyBundleError::Invalid);
    }
    let authorization = RecoveryAuthorization::decode(trusted_root, &read_frame(&mut input, 284)?)
        .map_err(|_| RecoveryKeyBundleError::Authority)?;
    let plan = RecoveryReplacementPlan::decode(&read_frame(&mut input, 2 * 1024 * 1024)?)
        .map_err(|_| RecoveryKeyBundleError::Invalid)?;
    let roles = validate_recipient(&authorization, &plan, recipient)?;
    let gateway = roles.bits() & JoinRoles::GATEWAY != 0;
    let control = recovery_material::decode(&read_frame(&mut input, MAXIMUM_MATERIAL_BYTES)?)
        .map_err(|_| RecoveryKeyBundleError::Invalid)?;
    validate_control_keys(&control, plan.mesh_id, trusted_root)?;
    let certificate = RecoveryNodeCertificate::read(
        &mut input,
        recipient.node_id,
        &recipient.identity_public_key,
        control.online_certificate_der.clone(),
    )?;
    let mut inventory = RecoverySecretInventoryBuilder::new(plan.recovery_id, &control)?;
    open_control_keys(&control, recipient, roles, &mut decrypt)?;
    for _ in 0..plan.secrets.generation_count {
        let material =
            recovery_material::decode_secret(&read_frame(&mut input, MAXIMUM_MATERIAL_BYTES)?)
                .map_err(|_| RecoveryKeyBundleError::Invalid)?;
        inventory.push(&material)?;
        drop(verify_recipient_secret(
            &material,
            recipient,
            gateway,
            &mut decrypt,
        )?);
    }
    let mut excess = [0];
    if inventory.finish()? != plan.secrets || input.read(&mut excess)? != 0 {
        return Err(RecoveryKeyBundleError::Invalid);
    }
    RecoveryKeyBundleVerification::from_plan(
        &plan,
        recipient.node_id,
        input.digest.finalize().into(),
        certificate,
    )
}

fn validate_recipient(
    authorization: &RecoveryAuthorization,
    plan: &RecoveryReplacementPlan,
    recipient: RecoveryKeyRecipient,
) -> Result<JoinRoles, RecoveryKeyBundleError> {
    let claims = authorization.claims();
    if claims.mesh_id != plan.mesh_id
        || claims.partition_id != plan.partition_id
        || claims.recovery_id != plan.recovery_id
        || claims.recovery_epoch != plan.recovery_epoch
        || plan.digest().map_err(|_| RecoveryKeyBundleError::Invalid)?
            != claims.replacement_manifest_digest
    {
        return Err(RecoveryKeyBundleError::Authority);
    }
    let node = plan
        .nodes
        .iter()
        .find(|node| node.node_id == recipient.node_id)
        .ok_or(RecoveryKeyBundleError::Authority)?;
    if node.identity_public_key != recipient.identity_public_key
        || node.wrapping_public_key != recipient.wrapping_public_key
    {
        return Err(RecoveryKeyBundleError::Authority);
    }
    Ok(node.roles)
}

fn validate_control_keys(
    control: &RecoveryControlKeys,
    mesh: MeshId,
    root: &[u8],
) -> Result<(), RecoveryKeyBundleError> {
    for (material, kind) in [
        (
            &control.online_authority_key,
            ONLINE_AUTHORITY_KEY_SECRET_KIND,
        ),
        (&control.storage_permit_key, STORAGE_PERMIT_KEY_SECRET_KIND),
    ] {
        let context = material.secret.context;
        if context.kind() != kind || context.id() != mesh.as_bytes() || context.generation() < 2 {
            return Err(RecoveryKeyBundleError::Authority);
        }
    }
    validate_online_authority_certificate(&control.online_certificate_der, root)
        .map_err(|_| RecoveryKeyBundleError::Authority)
}

fn open_control_keys<E>(
    control: &RecoveryControlKeys,
    recipient: RecoveryKeyRecipient,
    roles: JoinRoles,
    decrypt: &mut impl FnMut(&EncryptedSecret, &RecipientKeyEnvelope) -> Result<SecretPlaintext, E>,
) -> Result<(), RecoveryKeyBundleError> {
    let gateway = roles.bits() & JoinRoles::GATEWAY != 0;
    if let Some(online) =
        verify_recipient_secret(&control.online_authority_key, recipient, gateway, decrypt)?
    {
        drop(
            OnlineCertificateAuthority::from_pkcs8_and_certificate(
                online.expose(),
                &control.online_certificate_der,
            )
            .map_err(|_| RecoveryKeyBundleError::Decryption)?,
        );
    }
    if let Some(permit) = verify_recipient_secret(
        &control.storage_permit_key,
        recipient,
        roles.bits() & (JoinRoles::GATEWAY | JoinRoles::STORAGE) != 0,
        decrypt,
    )? && (permit.expose().len() != 32 || permit.expose().iter().all(|byte| *byte == 0))
    {
        return Err(RecoveryKeyBundleError::Decryption);
    }
    Ok(())
}

fn verify_recipient_secret<E>(
    material: &CommitSecretGeneration,
    recipient: RecoveryKeyRecipient,
    required: bool,
    decrypt: &mut impl FnMut(&EncryptedSecret, &RecipientKeyEnvelope) -> Result<SecretPlaintext, E>,
) -> Result<Option<SecretPlaintext>, RecoveryKeyBundleError> {
    let secret = EncryptedSecret::from_parts(material.secret.clone())
        .map_err(|_| RecoveryKeyBundleError::Invalid)?;
    let assigned = material
        .recipients
        .iter()
        .filter(|envelope| {
            envelope.recipient_public_key == recipient.wrapping_public_key.as_bytes()
        })
        .collect::<Vec<_>>();
    match (required, assigned.as_slice()) {
        (true, [envelope]) => {
            let envelope = RecipientKeyEnvelope::from_parts((*envelope).clone())
                .map_err(|_| RecoveryKeyBundleError::Invalid)?;
            if envelope.context() != secret.context() {
                return Err(RecoveryKeyBundleError::Invalid);
            }
            decrypt(&secret, &envelope)
                .map(Some)
                .map_err(|_| RecoveryKeyBundleError::Decryption)
        }
        (false, []) => Ok(None),
        _ => Err(RecoveryKeyBundleError::Authority),
    }
}

pub(crate) fn write_frame(
    output: &mut impl Write,
    bytes: &[u8],
) -> Result<(), RecoveryKeyBundleError> {
    let size = u32::try_from(bytes.len()).map_err(|_| RecoveryKeyBundleError::Invalid)?;
    output.write_all(&size.to_be_bytes())?;
    output.write_all(bytes)?;
    Ok(())
}

pub(crate) fn read_frame(
    input: &mut impl Read,
    maximum: usize,
) -> Result<Vec<u8>, RecoveryKeyBundleError> {
    let mut size = [0; 4];
    input.read_exact(&mut size)?;
    let size =
        usize::try_from(u32::from_be_bytes(size)).map_err(|_| RecoveryKeyBundleError::Invalid)?;
    if size == 0 || size > maximum {
        return Err(RecoveryKeyBundleError::Invalid);
    }
    let mut bytes = vec![0; size];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

struct DigestReader<R> {
    inner: R,
    digest: Sha256,
}
impl<R: Read> Read for DigestReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(bytes)?;
        self.digest.update(&bytes[..read]);
        Ok(read)
    }
}

/// Redacted recovery-key transfer failure; never includes key, code or path contents.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryKeyBundleError {
    /// Malformed, incomplete or noncanonical stream.
    #[error("recovery key bundle is invalid")]
    Invalid,
    /// Root, plan, recipient or preparation state was not authorised.
    #[error("recovery key bundle authority does not match")]
    Authority,
    /// Assigned material could not be opened by the local node.
    #[error("recovery key bundle cannot be decrypted by this recipient")]
    Decryption,
    /// A local stream failed; callers must discard partial output.
    #[error("recovery key bundle IO failed")]
    Io(#[from] std::io::Error),
    /// Prepared metadata failed validation or persistence reads.
    #[error("recovery key bundle metadata failed")]
    Metadata(#[from] RepositoryError),
}
