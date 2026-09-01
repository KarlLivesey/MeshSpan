// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_domain::{
    EntropyError, HostId, MeshId, NodeId, PrincipalId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind,
    EntityReference, LogPosition, NodeWrappingKeyRecord, StorageTargetRegistrationContext,
};
use meshspan_secret_envelope::{WrappingPrivateKey, WrappingPublicKey};

use crate::{
    NodeWrappingKeyRegistrationAuthority, NodeWrappingKeyRegistrationAuthorityError,
    NodeWrappingKeyRegistrationError, NodeWrappingKeyRegistrationService,
};

#[test]
fn exact_key_commits_once_and_restart_only_reads() -> Result<(), Box<dyn std::error::Error>> {
    let node_id = NodeId::from_bytes([4; 16])?;
    let public_key = WrappingPrivateKey::from_bytes([7; 32])?.public_key();
    let authority = FakeAuthority::new(node_id, false)?;
    let mut service = NodeWrappingKeyRegistrationService::new(
        node_id,
        public_key,
        authority,
        SequentialRandom(20),
    );
    service.ensure(UnixMicros::new(30))?;
    service.ensure(UnixMicros::new(31))?;
    assert_eq!(service.authority().commits(), 1);
    assert_eq!(
        service
            .authority()
            .current_key(node_id)?
            .map(|key| key.public_key),
        Some(public_key)
    );
    Ok(())
}

#[test]
fn ambiguous_commit_succeeds_only_after_exact_authoritative_read()
-> Result<(), Box<dyn std::error::Error>> {
    let node_id = NodeId::from_bytes([4; 16])?;
    let public_key = WrappingPrivateKey::from_bytes([9; 32])?.public_key();
    let authority = FakeAuthority::new(node_id, true)?;
    let mut service = NodeWrappingKeyRegistrationService::new(
        node_id,
        public_key,
        authority,
        SequentialRandom(40),
    );
    service.ensure(UnixMicros::new(50))?;
    assert_eq!(service.authority().commits(), 1);
    Ok(())
}

#[test]
fn a_different_authoritative_key_never_rotates_silently() -> Result<(), Box<dyn std::error::Error>>
{
    let node_id = NodeId::from_bytes([4; 16])?;
    let local_key = WrappingPrivateKey::from_bytes([11; 32])?.public_key();
    let authority = FakeAuthority::new(node_id, false)?;
    authority.set_current(WrappingPrivateKey::from_bytes([12; 32])?.public_key());
    let mut service = NodeWrappingKeyRegistrationService::new(
        node_id,
        local_key,
        authority,
        SequentialRandom(60),
    );
    assert!(matches!(
        service.ensure(UnixMicros::new(70)),
        Err(NodeWrappingKeyRegistrationError::Conflict)
    ));
    assert_eq!(service.authority().commits(), 0);
    Ok(())
}

struct FakeState {
    current: Option<NodeWrappingKeyRecord>,
    commits: usize,
}

struct FakeAuthority {
    registration: StorageTargetRegistrationContext,
    ambiguous: bool,
    state: Mutex<FakeState>,
}

impl FakeAuthority {
    fn new(node_id: NodeId, ambiguous: bool) -> Result<Self, meshspan_domain::IdentifierError> {
        Ok(Self {
            registration: StorageTargetRegistrationContext {
                mesh_id: MeshId::from_bytes([1; 16])?,
                node_id,
                host_id: HostId::from_bytes([2; 16])?,
                actor_principal_id: PrincipalId::from_bytes([3; 16])?,
            },
            ambiguous,
            state: Mutex::new(FakeState {
                current: None,
                commits: 0,
            }),
        })
    }

    fn set_current(&self, public_key: WrappingPublicKey) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .current = Some(NodeWrappingKeyRecord {
            node_id: self.registration.node_id,
            generation: 1,
            public_key,
            registered_at: UnixMicros::new(1),
            revision: Revision::new(1),
        });
    }

    fn commits(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .commits
    }
}

impl NodeWrappingKeyRegistrationAuthority for FakeAuthority {
    fn registration_context(
        &self,
        node_id: NodeId,
        _now: UnixMicros,
    ) -> Result<Option<StorageTargetRegistrationContext>, NodeWrappingKeyRegistrationAuthorityError>
    {
        Ok((node_id == self.registration.node_id).then_some(self.registration))
    }

    fn current_key(
        &self,
        node_id: NodeId,
    ) -> Result<Option<NodeWrappingKeyRecord>, NodeWrappingKeyRegistrationAuthorityError> {
        if node_id != self.registration.node_id {
            return Ok(None);
        }
        Ok(self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .current)
    }

    fn commit_or_resolve_registration(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, NodeWrappingKeyRegistrationAuthorityError> {
        let AuthoritativeCommand::RegisterNodeWrappingKey(command) = command else {
            return Err(NodeWrappingKeyRegistrationAuthorityError::Conflict);
        };
        let public_key = WrappingPublicKey::from_bytes(command.public_key)
            .map_err(|_| NodeWrappingKeyRegistrationAuthorityError::Conflict)?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.commits = state.commits.saturating_add(1);
        state.current = Some(NodeWrappingKeyRecord {
            node_id: command.node_id,
            generation: command.generation,
            public_key,
            registered_at: context.occurred_at,
            revision: Revision::new(2),
        });
        if self.ambiguous {
            return Err(NodeWrappingKeyRegistrationAuthorityError::Unavailable);
        }
        Ok(CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: AuthoritativeCommand::RegisterNodeWrappingKey(*command)
                .request_digest(context),
            result_digest: [8; 32],
            committed_revision: Revision::new(2),
            committed_position: LogPosition { index: 2, term: 1 },
            applied_position: LogPosition { index: 2, term: 1 },
            entity: EntityReference {
                kind: EntityKind::NodeWrappingKey,
                id: command.node_id.as_bytes(),
            },
        })
    }
}

struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
