// SPDX-License-Identifier: GPL-2.0-only

//! Consensus-backed current-user authentication-method lifecycle.

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{AuthenticationMethodKind, OperationId, PrincipalId};
use meshspan_metadata::{
    AuthenticationMethodCreationReplay, AuthenticationMethodCursor, AuthenticationMethodRecord,
    AuthenticationMethodRevocationReplay, AuthenticationRegistrationProfile, AuthoritativeCommand,
    CommandContext, Page, PageLimit, PasskeyRegistrationProfile, RepositoryError,
};

use crate::{
    ApiKeyIssuanceAuthority, ApiKeyIssuanceAuthorityError, ApiKeyIssuanceCommit,
    AuthenticationMethodListingAuthority, AuthenticationMethodListingAuthorityError,
    AuthenticationMethodRevocationAuthority, AuthenticationMethodRevocationAuthorityError,
    AuthenticationMethodRevocationCommit, ConsensusAuthenticationAuthority,
    PasskeyRegistrationAuthority, PasskeyRegistrationAuthorityError, PasskeyRegistrationCommit,
    RecoveryCodeIssuanceAuthority, RecoveryCodeIssuanceAuthorityError, RecoveryCodeIssuanceCommit,
    TotpRegistrationAuthority, TotpRegistrationAuthorityError, TotpRegistrationCommit,
};

impl AuthenticationMethodListingAuthority for ConsensusAuthenticationAuthority {
    fn authentication_methods(
        &self,
        principal_id: PrincipalId,
        after: Option<AuthenticationMethodCursor>,
        limit: PageLimit,
    ) -> Result<
        Page<AuthenticationMethodRecord, AuthenticationMethodCursor>,
        AuthenticationMethodListingAuthorityError,
    > {
        self.reader()
            .authentication_methods(principal_id, after, limit)
            .map_err(|error| match repository_failure(&error) {
                AuthorityFailure::Unavailable => {
                    AuthenticationMethodListingAuthorityError::Unavailable
                }
                AuthorityFailure::Conflict | AuthorityFailure::Failed => {
                    AuthenticationMethodListingAuthorityError::Failed
                }
            })
    }
}

impl ApiKeyIssuanceAuthority for ConsensusAuthenticationAuthority {
    fn resolve_api_key_issuance(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApiKeyIssuanceCommit>, ApiKeyIssuanceAuthorityError> {
        self.reader()
            .resolve_authentication_method_creation(operation_id, AuthenticationMethodKind::ApiKey)
            .map(|replay| replay.map(api_key_commit))
            .map_err(|error| repository_failure(&error).into())
    }

    fn commit_or_resolve_api_key_issuance(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<ApiKeyIssuanceCommit, ApiKeyIssuanceAuthorityError> {
        let expected_digest = command.request_digest(context);
        self.commit_authoritative(context, command)
            .map_err(authority_failure)?;
        let replay = self
            .reader()
            .resolve_authentication_method_creation(
                context.operation_id,
                AuthenticationMethodKind::ApiKey,
            )
            .map_err(|error| repository_failure(&error))?
            .ok_or(AuthorityFailure::Failed)?;
        require_digest(replay.request_digest, expected_digest)?;
        Ok(api_key_commit(replay))
    }
}

impl RecoveryCodeIssuanceAuthority for ConsensusAuthenticationAuthority {
    fn resolve_recovery_code_issuance(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<RecoveryCodeIssuanceCommit>, RecoveryCodeIssuanceAuthorityError> {
        self.reader()
            .resolve_authentication_method_creation(
                operation_id,
                AuthenticationMethodKind::RecoveryCode,
            )
            .map(|replay| replay.map(recovery_code_commit))
            .map_err(|error| repository_failure(&error).into())
    }

    fn commit_or_resolve_recovery_code_issuance(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<RecoveryCodeIssuanceCommit, RecoveryCodeIssuanceAuthorityError> {
        let expected_digest = command.request_digest(context);
        self.commit_authoritative(context, command)
            .map_err(authority_failure)?;
        let replay = self
            .reader()
            .resolve_authentication_method_creation(
                context.operation_id,
                AuthenticationMethodKind::RecoveryCode,
            )
            .map_err(|error| repository_failure(&error))?
            .ok_or(AuthorityFailure::Failed)?;
        require_digest(replay.request_digest, expected_digest)?;
        Ok(recovery_code_commit(replay))
    }
}

impl TotpRegistrationAuthority for ConsensusAuthenticationAuthority {
    fn registration_profile(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Option<AuthenticationRegistrationProfile>, TotpRegistrationAuthorityError> {
        self.reader()
            .authentication_registration_profile(principal_id)
            .map_err(|error| repository_failure(&error).into())
    }

    fn resolve_registration(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<TotpRegistrationCommit>, TotpRegistrationAuthorityError> {
        self.reader()
            .resolve_authentication_method_creation(operation_id, AuthenticationMethodKind::Totp)
            .map(|replay| replay.map(totp_commit))
            .map_err(|error| repository_failure(&error).into())
    }

    fn commit_or_resolve_registration(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<TotpRegistrationCommit, TotpRegistrationAuthorityError> {
        let expected_digest = command.request_digest(context);
        self.commit_authoritative(context, command)
            .map_err(authority_failure)?;
        let replay = self
            .reader()
            .resolve_authentication_method_creation(
                context.operation_id,
                AuthenticationMethodKind::Totp,
            )
            .map_err(|error| repository_failure(&error))?
            .ok_or(AuthorityFailure::Failed)?;
        require_digest(replay.request_digest, expected_digest)?;
        Ok(totp_commit(replay))
    }
}

impl PasskeyRegistrationAuthority for ConsensusAuthenticationAuthority {
    fn registration_profile(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Option<PasskeyRegistrationProfile>, PasskeyRegistrationAuthorityError> {
        self.reader()
            .passkey_registration_profile(principal_id)
            .map_err(|error| repository_failure(&error).into())
    }

    fn resolve_registration(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<PasskeyRegistrationCommit>, PasskeyRegistrationAuthorityError> {
        self.reader()
            .resolve_passkey_registration(operation_id)
            .map(|replay| replay.map(passkey_commit))
            .map_err(|error| repository_failure(&error).into())
    }

    fn commit_or_resolve_registration(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<PasskeyRegistrationCommit, PasskeyRegistrationAuthorityError> {
        let expected_digest = command.request_digest(context);
        self.commit_authoritative(context, command)
            .map_err(authority_failure)?;
        let replay = self
            .reader()
            .resolve_passkey_registration(context.operation_id)
            .map_err(|error| repository_failure(&error))?
            .ok_or(AuthorityFailure::Failed)?;
        require_digest(replay.request_digest, expected_digest)?;
        Ok(passkey_commit(replay))
    }
}

impl AuthenticationMethodRevocationAuthority for ConsensusAuthenticationAuthority {
    fn resolve_authentication_method_revocation(
        &self,
        operation_id: OperationId,
    ) -> Result<
        Option<AuthenticationMethodRevocationCommit>,
        AuthenticationMethodRevocationAuthorityError,
    > {
        self.reader()
            .resolve_authentication_method_revocation(operation_id)
            .map(|replay| replay.map(revocation_commit))
            .map_err(|error| repository_failure(&error).into())
    }

    fn commit_or_resolve_authentication_method_revocation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<AuthenticationMethodRevocationCommit, AuthenticationMethodRevocationAuthorityError>
    {
        let expected_digest = command.request_digest(context);
        self.commit_authoritative(context, command)
            .map_err(authority_failure)?;
        let replay = self
            .reader()
            .resolve_authentication_method_revocation(context.operation_id)
            .map_err(|error| repository_failure(&error))?
            .ok_or(AuthorityFailure::Failed)?;
        require_digest(replay.request_digest, expected_digest)?;
        Ok(revocation_commit(replay))
    }
}

fn api_key_commit(replay: AuthenticationMethodCreationReplay) -> ApiKeyIssuanceCommit {
    ApiKeyIssuanceCommit {
        request_digest: replay.request_digest,
        result_digest: replay.result_digest,
        method_id: replay.method_id,
        principal_id: replay.principal_id,
        created_at: replay.created_at,
    }
}

fn recovery_code_commit(replay: AuthenticationMethodCreationReplay) -> RecoveryCodeIssuanceCommit {
    RecoveryCodeIssuanceCommit {
        request_digest: replay.request_digest,
        result_digest: replay.result_digest,
        method_id: replay.method_id,
        principal_id: replay.principal_id,
        created_at: replay.created_at,
    }
}

fn totp_commit(replay: AuthenticationMethodCreationReplay) -> TotpRegistrationCommit {
    TotpRegistrationCommit {
        request_digest: replay.request_digest,
        result_digest: replay.result_digest,
        method_id: replay.method_id,
        principal_id: replay.principal_id,
        created_at: replay.created_at,
    }
}

fn passkey_commit(
    replay: meshspan_metadata::PasskeyRegistrationReplay,
) -> PasskeyRegistrationCommit {
    PasskeyRegistrationCommit {
        request_digest: replay.request_digest,
        result_digest: replay.result_digest,
        method_id: replay.method_id,
        principal_id: replay.principal_id,
        created_at: replay.created_at,
    }
}

fn revocation_commit(
    replay: AuthenticationMethodRevocationReplay,
) -> AuthenticationMethodRevocationCommit {
    AuthenticationMethodRevocationCommit {
        request_digest: replay.request_digest,
        result_digest: replay.result_digest,
        method_id: replay.method_id,
        principal_id: replay.principal_id,
        actor_principal_id: replay.actor_principal_id,
        revoked_at: replay.revoked_at,
    }
}

fn require_digest(actual: [u8; 32], expected: [u8; 32]) -> Result<(), AuthorityFailure> {
    if actual == expected {
        Ok(())
    } else {
        Err(AuthorityFailure::Conflict)
    }
}

#[derive(Clone, Copy)]
enum AuthorityFailure {
    Unavailable,
    Conflict,
    Failed,
}

fn repository_failure(error: &RepositoryError) -> AuthorityFailure {
    match error {
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            AuthorityFailure::Unavailable
        }
        RepositoryError::OperationConflict => AuthorityFailure::Conflict,
        _ => AuthorityFailure::Failed,
    }
}

fn authority_failure(error: MetadataAuthorityRequestError) -> AuthorityFailure {
    match error {
        MetadataAuthorityRequestError::NotLeader { .. }
        | MetadataAuthorityRequestError::Unavailable => AuthorityFailure::Unavailable,
        MetadataAuthorityRequestError::Conflict => AuthorityFailure::Conflict,
        MetadataAuthorityRequestError::Unsupported | MetadataAuthorityRequestError::Failed => {
            AuthorityFailure::Failed
        }
    }
}

macro_rules! authority_error_conversion {
    ($error:ty) => {
        impl From<AuthorityFailure> for $error {
            fn from(value: AuthorityFailure) -> Self {
                match value {
                    AuthorityFailure::Unavailable => Self::Unavailable,
                    AuthorityFailure::Conflict => Self::Conflict,
                    AuthorityFailure::Failed => Self::Failed,
                }
            }
        }
    };
}

authority_error_conversion!(ApiKeyIssuanceAuthorityError);
authority_error_conversion!(RecoveryCodeIssuanceAuthorityError);
authority_error_conversion!(TotpRegistrationAuthorityError);
authority_error_conversion!(PasskeyRegistrationAuthorityError);
authority_error_conversion!(AuthenticationMethodRevocationAuthorityError);
