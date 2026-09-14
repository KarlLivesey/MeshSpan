// SPDX-License-Identifier: GPL-2.0-only

//! Bounded encrypted-material export for independently selected replacement recipients.

use std::io::Write;

use meshspan_domain::NodeId;
use meshspan_recovery_bundle::RecoveredAuthority;

use super::credential_fence::read_fence;
use crate::command_codec::recovery_material;
use crate::recovery_key_bundle::{BUNDLE_MAGIC, write_frame};
use crate::{
    AuthoritativeRepository, PageLimit, RecoveryKeyBundleError, RecoveryNodeCertificate,
    RepositoryError,
};

impl AuthoritativeRepository {
    /// Streams a deterministic, encrypted key bundle for a selected replacement node.
    /// The caller must use an isolated local output, discard partial failures and publish it
    /// durably only after success; this read transaction must never span network IO.
    /// The bundle contains public recovery intent and encrypted keys, never root/node private
    /// identities or plaintext user credentials. It is not a metadata backup or admission token.
    /// # Errors
    /// Rejects missing/changed selection, unfenced credentials, incomplete/corrupt keys, another
    /// root, an unselected node, encoding failures or output IO. Source state is unchanged.
    pub fn export_recovery_key_bundle(
        &self,
        recovery: &RecoveredAuthority,
        node_id: NodeId,
        output: &mut impl Write,
    ) -> Result<(), RecoveryKeyBundleError> {
        let transaction = self
            .database
            .connection()
            .unchecked_transaction()
            .map_err(RepositoryError::from)?;
        self.write_recovery_key_bundle(recovery, node_id, output)?;
        transaction.commit().map_err(RepositoryError::from)?;
        Ok(())
    }

    // The caller owns a transaction so export and acknowledgement validation see one snapshot.
    pub(super) fn write_recovery_key_bundle(
        &self,
        recovery: &RecoveredAuthority,
        node_id: NodeId,
        output: &mut impl Write,
    ) -> Result<RecoveryNodeCertificate, RecoveryKeyBundleError> {
        let plan = self
            .load_recovery_replacement_plan(recovery)?
            .ok_or(RecoveryKeyBundleError::Authority)?;
        let authorization = self.prepared_recovery_authorization(recovery)?;
        let fence =
            read_fence(self.database.connection())?.ok_or(RecoveryKeyBundleError::Authority)?;
        let node = plan
            .nodes
            .iter()
            .find(|node| node.node_id == node_id)
            .ok_or(RecoveryKeyBundleError::Authority)?;
        if fence.recovery_id != plan.recovery_id
            || fence.manifest_digest != authorization.claims().replacement_manifest_digest
            || fence.source_revision != authorization.claims().source_revision
        {
            return Err(RecoveryKeyBundleError::Authority);
        }
        let control = self
            .load_recovery_control_keys(recovery, plan.recovery_id)?
            .ok_or(RecoveryKeyBundleError::Authority)?;
        if fence.online_generation != control.online_authority_key.secret.context.generation()
            || fence.permit_generation != control.storage_permit_key.secret.context.generation()
        {
            return Err(RecoveryKeyBundleError::Authority);
        }
        let certificate =
            self.issue_recovery_node_certificate(recovery, &control, node, fence.fenced_at)?;
        output.write_all(&BUNDLE_MAGIC)?;
        output.write_all(&node_id.as_bytes())?;
        write_frame(
            output,
            &authorization
                .encode()
                .map_err(|_| RecoveryKeyBundleError::Invalid)?,
        )?;
        write_frame(
            output,
            &plan.encode().map_err(|_| RecoveryKeyBundleError::Invalid)?,
        )?;
        write_frame(
            output,
            &recovery_material::encode(&control).map_err(|_| RecoveryKeyBundleError::Invalid)?,
        )?;
        certificate.write(output)?;
        let mut after = None;
        loop {
            let page = self.secret_generation_contexts(
                after,
                PageLimit::new(128).map_err(|_| RecoveryKeyBundleError::Invalid)?,
            )?;
            for context in page.items {
                let material = self
                    .load_retained_recovery_secret(recovery, context, &control, plan.recovery_id)?
                    .ok_or(RecoveryKeyBundleError::Authority)?;
                write_frame(
                    output,
                    &recovery_material::encode_secret(&material)
                        .map_err(|_| RecoveryKeyBundleError::Invalid)?,
                )?;
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Ok(certificate)
    }
}
