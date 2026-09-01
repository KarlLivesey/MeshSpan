// SPDX-License-Identifier: GPL-2.0-only

//! Adapter from replicated metadata access decisions to the logical filesystem contract.

use meshspan_domain::{Rights, VolumeId};
use meshspan_filesystem::{
    FilesystemAccessAuthority, FilesystemAccessContext, FilesystemAuthorityGrant,
    FilesystemAuthorityRequest,
};
use meshspan_metadata::{
    AccessDecision, AccessDenial, AccessRequest, AuthoritativeRepository, RepositoryError,
};
use thiserror::Error;

/// Borrowed committed metadata authority shared by every connector composition.
pub struct MetadataFilesystemAuthority<'a> {
    repository: &'a AuthoritativeRepository,
}

impl<'a> MetadataFilesystemAuthority<'a> {
    /// Wraps the exact replicated metadata projection used for operation-time decisions.
    #[must_use]
    pub const fn new(repository: &'a AuthoritativeRepository) -> Self {
        Self { repository }
    }
}

impl FilesystemAccessAuthority for MetadataFilesystemAuthority<'_> {
    type Error = MetadataFilesystemAuthorityError;

    fn authorise(
        &self,
        request: FilesystemAuthorityRequest,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        let decision = self.repository.evaluate_access(AccessRequest {
            authentication_service: request.context.authentication_service,
            credential_digest: request.context.credential_digest,
            required_assurance: request.context.required_assurance,
            gateway_node_id: request.context.gateway_node_id,
            gateway_incarnation: request.context.gateway_incarnation,
            volume_id: request.volume_id,
            object_id: request.object_id,
            requested_rights: request.requested_rights,
            now: request.context.now,
        })?;
        match decision {
            AccessDecision::Granted(capability) => Ok(FilesystemAuthorityGrant {
                principal_id: capability.principal_id,
                gateway_node_id: capability.gateway_node_id,
                gateway_incarnation: capability.gateway_incarnation,
                volume_id: capability.volume_id,
                object_id: capability.object_id,
                requested_rights: capability.requested_rights,
                identity_revision: capability.identity_revision,
                namespace_revision: capability.namespace_revision,
                object_revision: capability.object_revision,
                gateway_revision: capability.gateway_revision,
                expires_at: capability.expires_at,
                evidence_digest: capability.capability_digest,
            }),
            AccessDecision::Denied(denial) => Err(MetadataFilesystemAuthorityError::Denied(denial)),
        }
    }

    fn authorise_volume_root(
        &self,
        context: FilesystemAccessContext,
        volume_id: VolumeId,
        requested_rights: Rights,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        let volume = self
            .repository
            .volume_inventory_record(volume_id)?
            .ok_or(MetadataFilesystemAuthorityError::VolumeUnavailable)?;
        self.authorise(FilesystemAuthorityRequest {
            context,
            volume_id,
            object_id: volume.root_object_id,
            requested_rights,
        })
    }
}

/// Stable distinction between an intentional denial and unavailable/corrupt committed authority.
#[derive(Debug, Error)]
pub enum MetadataFilesystemAuthorityError {
    /// The current committed identity, gateway, object or grants deny the operation.
    #[error("committed metadata denied filesystem access: {0:?}")]
    Denied(AccessDenial),
    /// The requested volume has no committed root object.
    #[error("committed metadata volume root is unavailable")]
    VolumeUnavailable,
    /// The committed metadata projection could not be evaluated safely.
    #[error("committed metadata access evaluation failed")]
    Repository(#[from] RepositoryError),
}

#[cfg(test)]
mod tests {
    use meshspan_contracts::BoundedItems;
    use meshspan_domain::{
        ApiKeyId, AssuranceLevel, AuditEventId, AuthenticationMethodId, AuthenticationService,
        HostId, MeshId, NodeId, ObjectId, OperationId, OwnerSetId, PartitionId, PrincipalId,
        Revision, Rights, RoleId, SessionId, UnixMicros, VolumeId,
    };
    use meshspan_filesystem::{FilesystemAccessContext, FilesystemAuthorityRequest};
    use meshspan_metadata::{
        AuthoritativeCommand, BootstrapMesh, CommandContext, CreateAuthenticationMethod,
        CreateUser, CreateVolume, IssueAuthenticationSession, LogPosition,
        NewAuthenticationCredential, PartitionDatabase, RecordName, RevokeAuthenticationMethod,
        RevokeAuthenticationSession, SessionAuthenticationFactor, TotpAlgorithm,
    };

    use super::*;
    use crate::protected_volume_test_support::{
        confirm_recovery, initial_volume_key, protected_bootstrap, register_gateway_key,
    };

    struct AuthorityFixture {
        repository: AuthoritativeRepository,
        user_id: PrincipalId,
        gateway_node_id: NodeId,
        volume_id: VolumeId,
        root_object_id: ObjectId,
        session_id: SessionId,
        token_digest: [u8; 32],
    }

    #[test]
    fn adapter_revalidates_browser_sessions_and_direct_native_api_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let AuthorityFixture {
            mut repository,
            user_id,
            gateway_node_id,
            volume_id,
            root_object_id,
            session_id,
            token_digest,
        } = prepare_authority_fixture()?;
        let request = FilesystemAuthorityRequest {
            context: FilesystemAccessContext {
                authentication_service: AuthenticationService::Https,
                credential_digest: token_digest,
                required_assurance: AssuranceLevel::SingleFactor,
                gateway_node_id,
                gateway_incarnation: 1,
                now: UnixMicros::new(200),
            },
            volume_id,
            object_id: root_object_id,
            requested_rights: Rights::READ_DATA,
        };
        let grant = MetadataFilesystemAuthority::new(&repository).authorise(request)?;
        assert_eq!(grant.principal_id, user_id);
        assert_eq!(grant.object_id, root_object_id);
        assert_eq!(grant.requested_rights, Rights::READ_DATA);
        assert_ne!(grant.evidence_digest, [0; 32]);
        assert_volume_root_authority(&repository, request.context, volume_id, grant)?;

        apply(
            &mut repository,
            9,
            user_id,
            &AuthoritativeCommand::RevokeAuthenticationSession(RevokeAuthenticationSession {
                session_id,
                principal_id: user_id,
            }),
        )?;
        assert!(matches!(
            MetadataFilesystemAuthority::new(&repository).authorise(request),
            Err(MetadataFilesystemAuthorityError::Denied(
                AccessDenial::AuthenticationUnavailable
            ))
        ));

        assert_direct_key_revalidation(
            &mut repository,
            user_id,
            gateway_node_id,
            volume_id,
            root_object_id,
        )?;
        Ok(())
    }

    fn prepare_authority_fixture() -> Result<AuthorityFixture, Box<dyn std::error::Error>> {
        let partition_id = PartitionId::from_bytes([1; 16])?;
        let administrator_id = PrincipalId::from_bytes([2; 16])?;
        let user_id = PrincipalId::from_bytes([3; 16])?;
        let gateway_node_id = NodeId::from_bytes([4; 16])?;
        let volume_id = VolumeId::from_bytes([5; 16])?;
        let root_object_id = ObjectId::from_bytes([6; 16])?;
        let session_id = SessionId::from_bytes([7; 16])?;
        let token_digest = [8; 32];
        let database = PartitionDatabase::open(
            std::path::Path::new(":memory:"),
            partition_id,
            UnixMicros::new(1),
        )?;
        let mut repository = AuthoritativeRepository::new(database);
        apply(
            &mut repository,
            1,
            administrator_id,
            &protected_bootstrap(BootstrapMesh {
                mesh_id: MeshId::from_bytes([9; 16])?,
                mesh_name: RecordName::new("Authority proof")?,
                administrator_id,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([10; 16])?,
                host_id: HostId::from_bytes([11; 16])?,
                host_name: RecordName::new("Host")?,
                node_id: gateway_node_id,
                node_name: RecordName::new("Gateway")?,
                partition_name: RecordName::new(&partition_id.to_string())?,
            })?,
        )?;
        apply(
            &mut repository,
            2,
            administrator_id,
            &confirm_recovery(MeshId::from_bytes([9; 16])?),
        )?;
        apply(
            &mut repository,
            3,
            administrator_id,
            &register_gateway_key(gateway_node_id)?,
        )?;
        apply(
            &mut repository,
            4,
            administrator_id,
            &AuthoritativeCommand::CreateUser(CreateUser {
                principal_id: user_id,
                name: RecordName::new("User")?,
            }),
        )?;
        apply(
            &mut repository,
            5,
            administrator_id,
            &AuthoritativeCommand::CreateVolume(CreateVolume {
                volume_id,
                name: RecordName::new("Volume")?,
                root_object_id,
                owner_set_id: OwnerSetId::from_bytes([12; 16])?,
                owners: BoundedItems::new(vec![user_id], 1_024)?,
                key_generation: initial_volume_key(volume_id)?,
            }),
        )?;
        issue_test_session(&mut repository, user_id, session_id, token_digest)?;
        Ok(AuthorityFixture {
            repository,
            user_id,
            gateway_node_id,
            volume_id,
            root_object_id,
            session_id,
            token_digest,
        })
    }

    fn assert_volume_root_authority(
        repository: &AuthoritativeRepository,
        context: FilesystemAccessContext,
        volume_id: VolumeId,
        expected: FilesystemAuthorityGrant,
    ) -> Result<(), MetadataFilesystemAuthorityError> {
        let observed = MetadataFilesystemAuthority::new(repository).authorise_volume_root(
            context,
            volume_id,
            Rights::READ_DATA,
        )?;
        assert_eq!(observed, expected);
        Ok(())
    }

    fn assert_direct_key_revalidation(
        repository: &mut AuthoritativeRepository,
        user_id: PrincipalId,
        gateway_node_id: NodeId,
        volume_id: VolumeId,
        root_object_id: ObjectId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let direct_method_id = AuthenticationMethodId::from_bytes([18; 16])?;
        let direct_key_id = ApiKeyId::from_bytes([19; 16])?;
        let direct_digest = [20; 32];
        apply(
            repository,
            10,
            user_id,
            &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
                method_id: direct_method_id,
                principal_id: user_id,
                label: "Native API key".to_owned(),
                service_scope: AuthenticationService::HeadlessApi.scope_bit(),
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: direct_key_id,
                    key_digest: direct_digest,
                    scopes: AuthenticationService::HeadlessApi.api_key_login_scope(),
                    valid_from: UnixMicros::new(100),
                },
            }),
        )?;
        let direct_request = FilesystemAuthorityRequest {
            context: FilesystemAccessContext {
                authentication_service: AuthenticationService::HeadlessApi,
                credential_digest: direct_digest,
                required_assurance: AssuranceLevel::SingleFactor,
                gateway_node_id,
                gateway_incarnation: 1,
                now: UnixMicros::new(200),
            },
            volume_id,
            object_id: root_object_id,
            requested_rights: Rights::READ_DATA,
        };
        assert!(
            MetadataFilesystemAuthority::new(repository)
                .authorise(direct_request)
                .is_ok()
        );
        apply(
            repository,
            11,
            user_id,
            &AuthoritativeCommand::RevokeAuthenticationMethod(RevokeAuthenticationMethod {
                method_id: direct_method_id,
                principal_id: user_id,
                reason: "test revocation".to_owned(),
            }),
        )?;
        assert!(matches!(
            MetadataFilesystemAuthority::new(repository).authorise(direct_request),
            Err(MetadataFilesystemAuthorityError::Denied(
                AccessDenial::AuthenticationUnavailable
            ))
        ));
        Ok(())
    }

    fn issue_test_session(
        repository: &mut AuthoritativeRepository,
        user_id: PrincipalId,
        session_id: SessionId,
        token_digest: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        apply(
            repository,
            6,
            user_id,
            &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([13; 16])?,
                principal_id: user_id,
                label: "API key".to_owned(),
                service_scope: AuthenticationService::Https.scope_bit(),
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([14; 16])?,
                    key_digest: [15; 32],
                    scopes: AuthenticationService::Https.api_key_login_scope(),
                    valid_from: UnixMicros::new(100),
                },
            }),
        )?;
        apply(
            repository,
            7,
            user_id,
            &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([16; 16])?,
                principal_id: user_id,
                label: "TOTP".to_owned(),
                service_scope: AuthenticationService::Https.scope_bit(),
                expires_at: None,
                credential: NewAuthenticationCredential::Totp {
                    secret_ciphertext: vec![17; 64],
                    algorithm: TotpAlgorithm::Sha256,
                    digits: 6,
                    period_seconds: 30,
                    accepted_step_window: 1,
                },
            }),
        )?;
        apply(
            repository,
            8,
            user_id,
            &AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
                session_id,
                principal_id: user_id,
                token_digest,
                csrf_digest: [71; 32],
                client_label: meshspan_metadata::SessionClientLabel::Missing,
                persistent_cookie: false,
                service: AuthenticationService::Https,
                factors: BoundedItems::new(
                    vec![
                        SessionAuthenticationFactor::ApiKey {
                            method_id: AuthenticationMethodId::from_bytes([13; 16])?,
                            credential_generation: 1,
                            method_revision: Revision::new(6),
                            key_id: ApiKeyId::from_bytes([14; 16])?,
                        },
                        SessionAuthenticationFactor::Totp {
                            method_id: AuthenticationMethodId::from_bytes([16; 16])?,
                            credential_generation: 1,
                            method_revision: Revision::new(7),
                            accepted_step: 0,
                        },
                    ],
                    8,
                )?,
                expires_at: UnixMicros::new(500),
            }),
        )
    }

    fn apply(
        repository: &mut AuthoritativeRepository,
        revision: u64,
        actor_principal_id: PrincipalId,
        command: &AuthoritativeCommand,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let operation_byte = u8::try_from(revision)?;
        let audit_byte = u8::try_from(revision + 20)?;
        repository.apply_committed(
            LogPosition {
                index: revision,
                term: 1,
            },
            CommandContext {
                operation_id: OperationId::from_bytes([operation_byte; 16])?,
                actor_principal_id,
                audit_event_id: AuditEventId::from_bytes([audit_byte; 16])?,
                occurred_at: UnixMicros::new(i64::try_from(revision + 100)?),
                expected_revision: Some(Revision::new(revision - 1)),
            },
            command,
        )?;
        Ok(())
    }
}
