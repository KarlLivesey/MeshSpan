// SPDX-License-Identifier: GPL-2.0-only

//! Atomic invitation redemption using ordinary API-key construction and receipts.

use super::service::require_receipt;
use super::{UserEnrollmentAuthority, UserEnrollmentError, UserEnrollmentService};
use crate::ApiKeyIssuanceCommit;
use crate::api_key_issuance_model::{self as key_model, ApiKeyCommandMaterial};
use meshspan_api_contract::{
    ApiKeyScope, CreateApiKeyRequest, CreateApiKeyResponse, EnrollmentApiKeyScope,
    RedeemUserEnrollmentApiKeyRequest,
};
use meshspan_domain::{
    ApiKeyBundle, ApiKeyIssuanceKey, AuthenticationMethodId, UnixMicros, UserEnrollmentBundle,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind, RedeemUserEnrollment,
    UserEnrollmentRecord, UserEnrollmentState,
};

impl<A: UserEnrollmentAuthority> UserEnrollmentService<A> {
    /// Redeems a live capability into one ordinary primary key, with exact bounded recovery.
    /// # Errors
    /// Rejects invalid, expired, revoked, reused or stale consent and unverifiable outcomes.
    pub fn redeem_api_key(
        &mut self,
        request: &RedeemUserEnrollmentApiKeyRequest,
        key: &ApiKeyIssuanceKey,
        now: UnixMicros,
    ) -> Result<CreateApiKeyResponse, UserEnrollmentError> {
        let bundle = UserEnrollmentBundle::parse(&request.token)
            .map_err(|_| UserEnrollmentError::Rejected)?;
        let now = self.authority.refresh_enrollment_authority(now)?;
        let invitation = self
            .authority
            .enrollment(bundle.issuance_operation_id())?
            .ok_or(UserEnrollmentError::Rejected)?;
        self.require_live(invitation, now)?;
        if invitation.token_digest != bundle.secret_digest() {
            return Err(UserEnrollmentError::Rejected);
        }
        let prepared = PreparedRedemption::new(request, key, invitation, now)?;
        let receipt = self
            .authority
            .commit_enrollment(prepared.context, &prepared.command)?;
        let now = self.authority.refresh_enrollment_authority(now)?;
        let current = self
            .authority
            .enrollment(invitation.issuance_operation_id)?
            .ok_or(UserEnrollmentError::Failed)?;
        self.require_live(current, now)?;
        if current.principal_id != invitation.principal_id
            || current.token_digest != invitation.token_digest
            || current.issuance_request_digest != invitation.issuance_request_digest
        {
            return Err(UserEnrollmentError::Failed);
        }
        prepared.response(receipt, current)
    }
}

struct PreparedRedemption {
    request: CreateApiKeyRequest,
    normalized: key_model::NormalizedIssuance,
    api_key: ApiKeyBundle,
    method_id: AuthenticationMethodId,
    context: CommandContext,
    command: AuthoritativeCommand,
    expires_at: Option<UnixMicros>,
}
impl PreparedRedemption {
    fn new(
        request: &RedeemUserEnrollmentApiKeyRequest,
        key: &ApiKeyIssuanceKey,
        invitation: UserEnrollmentRecord,
        now: UnixMicros,
    ) -> Result<Self, UserEnrollmentError> {
        if request.expires_at_epoch_micros.is_missing() {
            return Err(UserEnrollmentError::InvalidRequest);
        }
        let request = ordinary_request(request);
        let normalized = key_model::normalize_request(&request)
            .map_err(|_| UserEnrollmentError::InvalidRequest)?;
        let created_at = match invitation.state {
            UserEnrollmentState::Issued => now,
            UserEnrollmentState::Redeemed(redemption)
                if redemption.operation_id == normalized.operation_id =>
            {
                redemption.redeemed_at
            }
            UserEnrollmentState::Redeemed(_) | UserEnrollmentState::Revoked => {
                return Err(UserEnrollmentError::Rejected);
            }
        };
        let api_key =
            ApiKeyBundle::derive_issued(key, invitation.principal_id, normalized.operation_id)
                .map_err(|_| UserEnrollmentError::Failed)?;
        let method_id = key_model::method_id(invitation.principal_id, normalized.operation_id)
            .map_err(|_| UserEnrollmentError::Failed)?;
        let expires_at = key_model::expiry(&request, created_at)
            .map_err(|_| UserEnrollmentError::InvalidRequest)?;
        if expires_at.is_some_and(|expiry| now >= expiry) {
            return Err(UserEnrollmentError::Rejected);
        }
        let method = key_model::command(
            &request,
            &normalized,
            ApiKeyCommandMaterial {
                key: &api_key,
                method_id,
                principal_id: invitation.principal_id,
                created_at,
                expires_at,
                smb_verifier_ciphertext: None,
            },
        );
        let AuthoritativeCommand::CreateAuthenticationMethod(method) = method else {
            return Err(UserEnrollmentError::Failed);
        };
        let command = AuthoritativeCommand::RedeemUserEnrollment(RedeemUserEnrollment {
            enrollment_operation_id: invitation.issuance_operation_id,
            token_digest: invitation.token_digest,
            method,
        });
        let context = key_model::context(
            normalized.operation_id,
            invitation.principal_id,
            &api_key,
            created_at,
        )
        .map_err(|_| UserEnrollmentError::Failed)?;
        Ok(Self {
            request,
            normalized,
            api_key,
            method_id,
            context,
            command,
            expires_at,
        })
    }
    fn response(
        self,
        receipt: CommandReceipt,
        current: UserEnrollmentRecord,
    ) -> Result<CreateApiKeyResponse, UserEnrollmentError> {
        require_receipt(
            receipt,
            self.context,
            &self.command,
            EntityKind::AuthenticationMethod,
            self.method_id.as_bytes(),
        )?;
        let UserEnrollmentState::Redeemed(redemption) = current.state else {
            return Err(UserEnrollmentError::Failed);
        };
        if redemption.operation_id != self.normalized.operation_id
            || redemption.method_id != self.method_id
            || redemption.request_digest != receipt.request_digest
            || redemption.redeemed_at != self.context.occurred_at
        {
            return Err(UserEnrollmentError::Failed);
        }
        key_model::response(
            &self.request,
            self.normalized,
            &self.api_key,
            ApiKeyIssuanceCommit {
                request_digest: receipt.request_digest,
                result_digest: receipt.result_digest,
                method_id: self.method_id,
                principal_id: current.principal_id,
                created_at: self.context.occurred_at,
            },
            self.expires_at,
        )
        .map_err(|_| UserEnrollmentError::Failed)
    }
}

fn ordinary_request(request: &RedeemUserEnrollmentApiKeyRequest) -> CreateApiKeyRequest {
    CreateApiKeyRequest {
        operation_id: request.operation_id.clone(),
        label: request.label.clone(),
        scopes: request
            .scopes
            .iter()
            .map(|scope| match scope {
                EnrollmentApiKeyScope::HttpsSession => ApiKeyScope::HttpsSession,
                EnrollmentApiKeyScope::HeadlessApi => ApiKeyScope::HeadlessApi,
            })
            .collect(),
        expires_at_epoch_micros: request.expires_at_epoch_micros.clone(),
    }
}
