// SPDX-License-Identifier: GPL-2.0-only

//! Authorised backup history over the common partition authority.

use axum::http::HeaderMap;
use meshspan_api_contract::{ListBackupRunsQuery, ListBackupRunsResponse};
use meshspan_domain::{PrincipalId, UnixMicros};

use crate::backup_schedule_administration::BackupScheduleError;
use crate::{
    ConsensusAuthenticationAuthority, GatewaySessionIdentity, SystemManagerAuthenticationError,
    authenticate_system_manager_read,
};

#[path = "backup_history_inventory.rs"]
pub(crate) mod inventory;

/// Replaceable synchronous history controller; HTTP invokes it on the blocking pool.
pub trait BackupHistoryController: Send + 'static {
    /// Checks current credentials and system-manager authority before parsing or reading.
    ///
    /// # Errors
    /// Rejects missing, revoked or insufficient authority.
    fn authenticate(&self, headers: &HeaderMap, now: UnixMicros)
    -> Result<(), BackupScheduleError>;
    /// Reauthorises and reads a bounded newest-first page.
    ///
    /// # Errors
    /// Rejects substituted continuations and untrustworthy metadata.
    fn list(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        query: &ListBackupRunsQuery,
    ) -> Result<ListBackupRunsResponse, BackupScheduleError>;
}

/// Composes history with existing swarm identity and consensus-backed metadata.
pub struct BackupHistoryService {
    authority: ConsensusAuthenticationAuthority,
    gateway: GatewaySessionIdentity,
}

impl BackupHistoryService {
    /// Binds a gateway to its authoritative backup partition.
    #[must_use]
    pub const fn new(
        authority: ConsensusAuthenticationAuthority,
        gateway: GatewaySessionIdentity,
    ) -> Self {
        Self { authority, gateway }
    }

    fn principal(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<PrincipalId, BackupScheduleError> {
        authenticate_system_manager_read(&self.authority, self.gateway, headers, now)
            .map(|administrator| administrator.principal_id)
            .map_err(|error| match error {
                SystemManagerAuthenticationError::Rejected => BackupScheduleError::Unauthenticated,
                SystemManagerAuthenticationError::Forbidden => BackupScheduleError::Forbidden,
                SystemManagerAuthenticationError::Unavailable => BackupScheduleError::Unavailable,
                SystemManagerAuthenticationError::Failed => BackupScheduleError::Failed,
            })
    }
}

impl BackupHistoryController for BackupHistoryService {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<(), BackupScheduleError> {
        self.principal(headers, now).map(|_| ())
    }

    fn list(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
        query: &ListBackupRunsQuery,
    ) -> Result<ListBackupRunsResponse, BackupScheduleError> {
        let principal = self.principal(headers, now)?;
        inventory::list(self.authority.reader(), principal, query)
    }
}
