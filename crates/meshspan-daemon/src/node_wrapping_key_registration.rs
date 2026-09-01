// SPDX-License-Identifier: GPL-2.0-only

//! Idempotent consensus registration of one node-local public wrapping key.

use meshspan_domain::{
    AuditEventId, EntropyError, NodeId, OperationId, RandomSource, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind, NodeWrappingKeyRecord,
    RegisterNodeWrappingKey, RepositoryError, StorageTargetRegistrationContext,
};
use meshspan_secret_envelope::WrappingPublicKey;
use thiserror::Error;

const INITIAL_GENERATION: u64 = 1;

/// Authoritative reads and mutation required to register one public wrapping key.
pub trait NodeWrappingKeyRegistrationAuthority {
    /// Resolves the active node and one current system manager.
    ///
    /// # Errors
    ///
    /// Fails closed when current topology or authority cannot be trusted.
    fn registration_context(
        &self,
        node_id: NodeId,
        now: UnixMicros,
    ) -> Result<Option<StorageTargetRegistrationContext>, NodeWrappingKeyRegistrationAuthorityError>;

    /// Returns the node's current authoritative public wrapping-key generation.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed persisted public material or unavailable metadata.
    fn current_key(
        &self,
        node_id: NodeId,
    ) -> Result<Option<NodeWrappingKeyRecord>, NodeWrappingKeyRegistrationAuthorityError>;

    /// Commits or exactly resolves one public key registration through consensus.
    ///
    /// # Errors
    ///
    /// Never reports success without a committed receipt.
    fn commit_or_resolve_registration(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, NodeWrappingKeyRegistrationAuthorityError>;
}

/// Reconciles one protected local private key with its authoritative public generation.
pub struct NodeWrappingKeyRegistrationService<A, R> {
    node_id: NodeId,
    public_key: WrappingPublicKey,
    authority: A,
    random: R,
}

impl<A, R> NodeWrappingKeyRegistrationService<A, R> {
    /// Binds one exact node/public key, consensus authority and cryptographic entropy source.
    #[must_use]
    pub const fn new(
        node_id: NodeId,
        public_key: WrappingPublicKey,
        authority: A,
        random: R,
    ) -> Self {
        Self {
            node_id,
            public_key,
            authority,
            random,
        }
    }

    #[cfg(test)]
    pub(crate) const fn authority(&self) -> &A {
        &self.authority
    }
}

impl<A, R> NodeWrappingKeyRegistrationService<A, R>
where
    A: NodeWrappingKeyRegistrationAuthority,
    R: RandomSource,
{
    /// Ensures consensus contains this exact node's initial public wrapping key.
    ///
    /// A lost response needs no local journal: the authoritative unique current key is queried
    /// before and after every attempt. An exact committed generation is success; any different
    /// generation or key is a conflict requiring explicit rotation rather than silent replacement.
    ///
    /// # Errors
    ///
    /// Rejects incomplete setup, changed authoritative keys, entropy failure and unverifiable
    /// receipts. An ambiguous commit is accepted only when a following authoritative read proves
    /// the exact desired key.
    pub fn ensure(&mut self, now: UnixMicros) -> Result<(), NodeWrappingKeyRegistrationError> {
        if let Some(current) = self.authority.current_key(self.node_id)? {
            return validate_current(self.node_id, self.public_key, current);
        }
        let registration = self
            .authority
            .registration_context(self.node_id, now)?
            .ok_or(NodeWrappingKeyRegistrationError::NotConfigured)?;
        let context = CommandContext {
            operation_id: OperationId::from_bytes(random_identifier(&mut self.random)?)?,
            actor_principal_id: registration.actor_principal_id,
            audit_event_id: AuditEventId::from_bytes(random_identifier(&mut self.random)?)?,
            occurred_at: now,
            expected_revision: None,
        };
        let command = AuthoritativeCommand::RegisterNodeWrappingKey(RegisterNodeWrappingKey {
            node_id: self.node_id,
            generation: INITIAL_GENERATION,
            public_key: self.public_key.as_bytes(),
            key_fingerprint: self.public_key.fingerprint(),
        });
        let expected_digest = command.request_digest(context);
        match self
            .authority
            .commit_or_resolve_registration(context, &command)
        {
            Ok(receipt) => validate_receipt(self.node_id, expected_digest, receipt)?,
            Err(commit_error) => {
                if let Some(current) = self.authority.current_key(self.node_id)? {
                    validate_current(self.node_id, self.public_key, current)?;
                } else {
                    return Err(commit_error.into());
                }
            }
        }
        let current = self
            .authority
            .current_key(self.node_id)?
            .ok_or(NodeWrappingKeyRegistrationError::Conflict)?;
        validate_current(self.node_id, self.public_key, current)
    }
}

fn validate_current(
    node_id: NodeId,
    public_key: WrappingPublicKey,
    current: NodeWrappingKeyRecord,
) -> Result<(), NodeWrappingKeyRegistrationError> {
    if current.node_id == node_id
        && current.generation == INITIAL_GENERATION
        && current.public_key == public_key
    {
        Ok(())
    } else {
        Err(NodeWrappingKeyRegistrationError::Conflict)
    }
}

fn validate_receipt(
    node_id: NodeId,
    expected_digest: [u8; 32],
    receipt: CommandReceipt,
) -> Result<(), NodeWrappingKeyRegistrationError> {
    if receipt.request_digest == expected_digest
        && receipt.result_digest != [0; 32]
        && receipt.entity.kind == EntityKind::NodeWrappingKey
        && receipt.entity.id == node_id.as_bytes()
    {
        Ok(())
    } else {
        Err(NodeWrappingKeyRegistrationError::Conflict)
    }
}

fn random_identifier(random: &mut impl RandomSource) -> Result<[u8; 16], EntropyError> {
    let mut bytes = [0_u8; 16];
    random.fill_bytes(&mut bytes)?;
    Ok(uuid_v8(bytes))
}

/// Closed authoritative failure for public wrapping-key registration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NodeWrappingKeyRegistrationAuthorityError {
    /// Current consensus projection or leader is unavailable.
    #[error("node wrapping key authority is unavailable")]
    Unavailable,
    /// Operation identity or authoritative state conflicts with the request.
    #[error("node wrapping key authority conflicts with the request")]
    Conflict,
    /// Persisted evidence or an invariant failed closed.
    #[error("node wrapping key authority failed closed")]
    Failed,
}

impl From<RepositoryError> for NodeWrappingKeyRegistrationAuthorityError {
    fn from(error: RepositoryError) -> Self {
        if error.is_command_rejection() || matches!(error, RepositoryError::OperationConflict) {
            return Self::Conflict;
        }
        match error {
            RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
                Self::Unavailable
            }
            _ => Self::Failed,
        }
    }
}

/// Public wrapping-key reconciliation failure without private material.
#[derive(Debug, Error)]
pub enum NodeWrappingKeyRegistrationError {
    /// Mesh setup or an active local topology is not yet available.
    #[error("node wrapping key registration requires completed mesh setup")]
    NotConfigured,
    /// Durable local and authoritative public identities disagree.
    #[error("node wrapping key registration conflicts with authoritative state")]
    Conflict,
    /// Cryptographic operation identity entropy was unavailable.
    #[error("node wrapping key registration entropy is unavailable")]
    Entropy(#[from] EntropyError),
    /// Generated operation or audit identity was invalid.
    #[error("node wrapping key registration identity generation failed")]
    Identifier(#[from] meshspan_domain::IdentifierError),
    /// Consensus or authoritative reads failed closed.
    #[error("node wrapping key registration authority failed")]
    Authority(#[from] NodeWrappingKeyRegistrationAuthorityError),
}
