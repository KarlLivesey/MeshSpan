// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated administration of exact manual DNS challenge work.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{
    ListManualDnsTasksQuery, ListManualDnsTasksResponse, ManualDnsTaskAction,
    ManualDnsTaskCursor as ApiCursor, ManualDnsTaskSummary, validate_list_manual_dns_tasks_query,
};
use meshspan_domain::{AssuranceLevel, UnixMicros};
use meshspan_metadata::{
    ManualDnsTaskCursor, ManualDnsTaskRecord, ManualDnsTaskState, Page, PageLimit, RepositoryError,
};
use thiserror::Error;

use crate::create_mesh_setup::format_uuid;
use crate::{
    BrowserAuthenticationError, BrowserRequestProtection, BrowserSessionAuthenticator,
    ConsensusAuthenticationAuthority, FileApiAuthenticationError, GatewaySessionIdentity,
    IdentityAdministrationAuthority, IdentityAdministrationAuthorityError, IdentityAdministrator,
    NativeApiKeyAuthenticator,
};

const DEFAULT_PAGE_LIMIT: u16 = 50;
const MAXIMUM_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAXIMUM_SAFE_TIME: i64 = 9_007_199_254_740_991;
const CURSOR_PREFIX: &str = "v1";
const LIST_ROUTE: &str = "/api/latest/admin/certificate-tasks/manual-dns";

/// Authoritative reads required by the administrator task inventory.
pub trait ManualDnsTaskAdministrationAuthority: IdentityAdministrationAuthority {
    /// Returns one stable deadline-ordered page of currently actionable tasks.
    ///
    /// # Errors
    ///
    /// Fails closed when metadata is unavailable or malformed.
    fn manual_dns_tasks(
        &self,
        after: Option<ManualDnsTaskCursor>,
        limit: PageLimit,
    ) -> Result<Page<ManualDnsTaskRecord, ManualDnsTaskCursor>, RepositoryError>;
}

impl ManualDnsTaskAdministrationAuthority for ConsensusAuthenticationAuthority {
    fn manual_dns_tasks(
        &self,
        after: Option<ManualDnsTaskCursor>,
        limit: PageLimit,
    ) -> Result<Page<ManualDnsTaskRecord, ManualDnsTaskCursor>, RepositoryError> {
        self.reader().actionable_manual_dns_tasks(after, limit)
    }
}

/// Synchronous controller kept behind the bounded HTTP blocking pool.
pub trait ManualDnsTaskAdministrationController: Send + 'static {
    /// Authenticates current system-manager authority before any task read.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous, stale or insufficient credentials.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, ManualDnsTaskAdministrationError>;

    /// Lists one validated task page under already-proven administrator authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed continuations and untrustworthy authoritative output.
    fn list_manual_dns_tasks(
        &self,
        administrator: IdentityAdministrator,
        query: ListManualDnsTasksQuery,
    ) -> Result<ListManualDnsTasksResponse, ManualDnsTaskAdministrationError>;
}

/// Manager-only manual DNS task service over the replicated authority boundary.
pub struct ManualDnsTaskAdministrationService<A> {
    authority: A,
    gateway: GatewaySessionIdentity,
}

impl<A> ManualDnsTaskAdministrationService<A> {
    /// Binds task visibility to one gateway's browser and API-key authentication context.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity) -> Self {
        Self { authority, gateway }
    }
}

impl<A> ManualDnsTaskAdministrationController for ManualDnsTaskAdministrationService<A>
where
    A: ManualDnsTaskAdministrationAuthority + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, ManualDnsTaskAdministrationError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(ManualDnsTaskAdministrationError::Unauthenticated);
        }
        if has_authorization {
            let principal_id = NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error)?;
            return self
                .authority
                .is_system_manager(principal_id, now)
                .map_err(map_authority_error)?
                .then_some(IdentityAdministrator { principal_id, now })
                .ok_or(ManualDnsTaskAdministrationError::Forbidden);
        }
        let capability = BrowserSessionAuthenticator::new(&self.authority, self.gateway)
            .authenticate(headers, protection, AssuranceLevel::SingleFactor, now)
            .map_err(map_browser_authentication_error)?;
        if !capability.is_system_manager() {
            return Err(ManualDnsTaskAdministrationError::Forbidden);
        }
        Ok(IdentityAdministrator {
            principal_id: capability.principal_id,
            now,
        })
    }

    fn list_manual_dns_tasks(
        &self,
        _administrator: IdentityAdministrator,
        query: ListManualDnsTasksQuery,
    ) -> Result<ListManualDnsTasksResponse, ManualDnsTaskAdministrationError> {
        validate_list_manual_dns_tasks_query(&query)
            .map_err(|_| ManualDnsTaskAdministrationError::InvalidInput)?;
        let after = query.cursor.as_ref().map(decode_cursor).transpose()?;
        let limit = PageLimit::new(usize::from(query.limit.unwrap_or(DEFAULT_PAGE_LIMIT)))
            .map_err(|error| map_repository_error(&error))?;
        let page = self
            .authority
            .manual_dns_tasks(after, limit)
            .map_err(|error| map_repository_error(&error))?;
        let tasks = page
            .items
            .into_iter()
            .map(public_task)
            .collect::<Result<Vec<_>, _>>()?;
        let next_page_url = page
            .next
            .map(|cursor| next_page_url(cursor, query.limit))
            .transpose()?;
        Ok(ListManualDnsTasksResponse {
            tasks,
            next_page_url,
        })
    }
}

fn public_task(
    task: ManualDnsTaskRecord,
) -> Result<ManualDnsTaskSummary, ManualDnsTaskAdministrationError> {
    let action = match task.state {
        ManualDnsTaskState::AwaitingPublication => ManualDnsTaskAction::Publish,
        ManualDnsTaskState::AwaitingRemoval => ManualDnsTaskAction::Remove,
        ManualDnsTaskState::PublicationObserved
        | ManualDnsTaskState::Complete
        | ManualDnsTaskState::Superseded => return Err(ManualDnsTaskAdministrationError::Failed),
    };
    let record_value = String::from_utf8(task.record_value)
        .ok()
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 512
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        .ok_or(ManualDnsTaskAdministrationError::Failed)?;
    if task.revision.get() > MAXIMUM_SAFE_INTEGER {
        return Err(ManualDnsTaskAdministrationError::Failed);
    }
    Ok(ManualDnsTaskSummary {
        task_digest: encode_hex(task.task_digest),
        order_id: format_uuid(task.order_id.as_bytes()),
        order_fence: task.fence.to_string(),
        record_name: task.record_name,
        record_value,
        action,
        expires_at_epoch_micros: task.expires_at.get(),
        created_at_epoch_micros: task.created_at.get(),
        transitioned_at_epoch_micros: task.transitioned_at.get(),
        revision: task.revision.get(),
    })
}

fn encode_cursor(cursor: ManualDnsTaskCursor) -> String {
    format!(
        "{CURSOR_PREFIX}.{}.{}.{}",
        cursor.expires_at().get(),
        cursor.created_at().get(),
        encode_hex(cursor.task_digest())
    )
}

fn decode_cursor(
    cursor: &ApiCursor,
) -> Result<ManualDnsTaskCursor, ManualDnsTaskAdministrationError> {
    let mut fields = cursor.as_str().split('.');
    if fields.next() != Some(CURSOR_PREFIX) {
        return Err(ManualDnsTaskAdministrationError::InvalidInput);
    }
    let expires_at = positive_time(fields.next())?;
    let created_at = positive_time(fields.next())?;
    let digest = decode_hex(fields.next().unwrap_or_default())?;
    if fields.next().is_some() {
        return Err(ManualDnsTaskAdministrationError::InvalidInput);
    }
    Ok(ManualDnsTaskCursor::new(expires_at, created_at, digest))
}

fn positive_time(value: Option<&str>) -> Result<UnixMicros, ManualDnsTaskAdministrationError> {
    value
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0 && *value <= MAXIMUM_SAFE_TIME)
        .map(UnixMicros::new)
        .ok_or(ManualDnsTaskAdministrationError::InvalidInput)
}

fn next_page_url(
    cursor: ManualDnsTaskCursor,
    requested_limit: Option<u16>,
) -> Result<String, ManualDnsTaskAdministrationError> {
    use std::fmt::Write;

    let encoded = encode_cursor(cursor);
    let mut url = format!("{LIST_ROUTE}?cursor={encoded}");
    if let Some(limit) = requested_limit {
        write!(url, "&limit={limit}").map_err(|_| ManualDnsTaskAdministrationError::Failed)?;
    }
    Ok(url)
}

fn encode_hex<const LENGTH: usize>(bytes: [u8; LENGTH]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(LENGTH.saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Result<[u8; 32], ManualDnsTaskAdministrationError> {
    if value.len() != 64 {
        return Err(ManualDnsTaskAdministrationError::InvalidInput);
    }
    let mut output = [0_u8; 32];
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ManualDnsTaskAdministrationError::InvalidInput);
    }
    for (target, pair) in output.iter_mut().zip(pairs) {
        let high = decode_nibble(pair[0])?;
        let low = decode_nibble(pair[1])?;
        *target = (high << 4) | low;
    }
    Ok(output)
}

const fn decode_nibble(value: u8) -> Result<u8, ManualDnsTaskAdministrationError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ManualDnsTaskAdministrationError::InvalidInput),
    }
}

const fn map_authority_error(
    error: IdentityAdministrationAuthorityError,
) -> ManualDnsTaskAdministrationError {
    match error {
        IdentityAdministrationAuthorityError::Unavailable => {
            ManualDnsTaskAdministrationError::Unavailable
        }
        IdentityAdministrationAuthorityError::Conflict
        | IdentityAdministrationAuthorityError::Failed => ManualDnsTaskAdministrationError::Failed,
    }
}

const fn map_file_authentication_error(
    error: FileApiAuthenticationError,
) -> ManualDnsTaskAdministrationError {
    match error {
        FileApiAuthenticationError::Rejected => ManualDnsTaskAdministrationError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => {
            ManualDnsTaskAdministrationError::Unavailable
        }
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => ManualDnsTaskAdministrationError::Failed,
    }
}

const fn map_browser_authentication_error(
    error: BrowserAuthenticationError,
) -> ManualDnsTaskAdministrationError {
    match error {
        BrowserAuthenticationError::Rejected => ManualDnsTaskAdministrationError::Unauthenticated,
        BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Unavailable) => {
            ManualDnsTaskAdministrationError::Unavailable
        }
        BrowserAuthenticationError::InvalidGateway
        | BrowserAuthenticationError::Authority(crate::BrowserSessionAuthorityError::Failed) => {
            ManualDnsTaskAdministrationError::Failed
        }
    }
}

fn map_repository_error(error: &RepositoryError) -> ManualDnsTaskAdministrationError {
    match error {
        RepositoryError::InvalidPageLimit => ManualDnsTaskAdministrationError::InvalidInput,
        RepositoryError::Sqlite(_) | RepositoryError::Store(_) | RepositoryError::Io(_) => {
            ManualDnsTaskAdministrationError::Unavailable
        }
        _ => ManualDnsTaskAdministrationError::Failed,
    }
}

/// Closed public-safe task administration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManualDnsTaskAdministrationError {
    /// Query or cursor input is invalid.
    #[error("manual DNS task input is invalid")]
    InvalidInput,
    /// Authentication was absent, malformed or stale.
    #[error("manual DNS task authentication was rejected")]
    Unauthenticated,
    /// The current principal lacks system-manager authority.
    #[error("manual DNS task administration is forbidden")]
    Forbidden,
    /// Current metadata authority cannot safely serve the inventory.
    #[error("manual DNS task authority is unavailable")]
    Unavailable,
    /// An internal invariant or outgoing contract failed closed.
    #[error("manual DNS task administration failed closed")]
    Failed,
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{CertificateOrderId, Revision};

    use super::*;

    #[test]
    fn cursor_round_trips_every_seek_field_and_rejects_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected =
            ManualDnsTaskCursor::new(UnixMicros::new(30), UnixMicros::new(20), [0xab; 32]);
        let encoded = encode_cursor(expected);
        let public = ApiCursor::from_encoded(encoded).ok_or("cursor")?;
        assert_eq!(decode_cursor(&public)?, expected);
        let upper = ApiCursor::from_encoded(format!("v1.30.20.{}", "AB".repeat(32)))
            .ok_or("upper cursor")?;
        assert_eq!(
            decode_cursor(&upper),
            Err(ManualDnsTaskAdministrationError::InvalidInput)
        );
        Ok(())
    }

    #[test]
    fn record_projection_preserves_exact_operator_action() -> Result<(), Box<dyn std::error::Error>>
    {
        let task = ManualDnsTaskRecord {
            task_digest: [1; 32],
            order_id: CertificateOrderId::from_bytes([2; 16])?,
            fence: 3,
            record_name: "_acme-challenge.files.example.test".to_owned(),
            record_value: b"exact_value-1".to_vec(),
            expires_at: UnixMicros::new(40),
            state: ManualDnsTaskState::AwaitingRemoval,
            created_at: UnixMicros::new(10),
            transitioned_at: UnixMicros::new(20),
            revision: Revision::new(5),
        };
        let projected = public_task(task)?;
        assert_eq!(projected.action, ManualDnsTaskAction::Remove);
        assert_eq!(projected.record_value, "exact_value-1");
        assert_eq!(projected.order_fence, "3");
        Ok(())
    }
}
