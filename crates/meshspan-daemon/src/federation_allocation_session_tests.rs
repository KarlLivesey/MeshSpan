// SPDX-License-Identifier: GPL-2.0-only

//! Allocation discovery over the native session, before requesting an exact backup capability.

use super::{TestResult, exchange};
use crate::federation_sessions::NativeFederationSession;
use meshspan_domain::{DurationMicros, FederationGrantId};
use meshspan_protocol::v1::{
    FederatedBackupScope, FetchFederatedBackupAllocations, ProtocolVersion,
    federation_envelope::Message,
};
use meshspan_transport::{
    FederationExchangeContext, FederationLocalIdentity, FederationPeerRegistry,
    FederationReplayGuard, signed_federation_backup_message,
};

pub(super) async fn discover(
    session: &NativeFederationSession,
    identity: &FederationLocalIdentity<'_>,
    peers: &FederationPeerRegistry,
    grant: FederationGrantId,
) -> TestResult<FederatedBackupScope> {
    let now = crate::api_http::current_time().ok_or("clock")?;
    let mut replay = FederationReplayGuard::new(32, DurationMicros::new(30_000_000))?;
    let mut cursor = Vec::new();
    let mut scopes = Vec::new();
    let mut revision = None;
    for marker in [221, 222] {
        let context = FederationExchangeContext::new(
            ProtocolVersion { major: 1, minor: 0 },
            [marker; 16],
            [marker; 16],
            [223; 16],
            now.checked_add(DurationMicros::new(5_000_000))
                .ok_or("deadline")?,
            [marker; 32],
        )?;
        let request = signed_federation_backup_message(
            identity,
            context,
            Message::FetchBackupAllocations(FetchFederatedBackupAllocations {
                grant_id: grant.as_bytes().to_vec(),
                required_bytes: 1024,
                cursor,
                limit: 1,
                signature: Vec::new(),
            }),
            session.limits.wire,
            now,
        )?;
        let response = exchange(session, request.envelope()).await??;
        let response = peers.authenticate_backup_response(
            &session.connection,
            &response,
            &request.expectation()?,
            crate::api_http::current_time().ok_or("clock")?,
            &mut replay,
        )?;
        let Message::BackupAllocationPage(page) = response.message() else {
            return Err("allocation page".into());
        };
        assert_eq!(page.allocations.len(), 1);
        if let Some(revision) = revision {
            assert_eq!(page.authority_revision, revision);
        }
        revision = Some(page.authority_revision);
        let allocation = page.allocations.first().ok_or("allocation")?;
        assert_eq!(allocation.maximum_bytes, 2048);
        let scope = allocation.scope.clone().ok_or("scope")?;
        assert_eq!(
            scope.allocation_id,
            vec![if marker == 221 { 211 } else { 218 }; 16]
        );
        assert_eq!(scope.grant_id, grant.as_bytes());
        scopes.push(scope);
        cursor = page.next_cursor.clone();
        assert_eq!(cursor.is_empty(), marker == 222);
        assert!(
            exchange(session, request.envelope()).await?.is_err(),
            "discovery replay was accepted"
        );
    }
    scopes
        .into_iter()
        .next()
        .ok_or_else(|| "first allocation".into())
}
