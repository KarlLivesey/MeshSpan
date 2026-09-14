// SPDX-License-Identifier: GPL-2.0-only

//! Initial allocation selection from complete signed grant authority and bounded route pages.

use super::{FederationSessions, NativeFederationSession, PairedRoute};
use meshspan_cluster::{
    FederationAuthorityFetchRequest, FederationAuthorityImportLimits, FederationAuthorityUpdate,
    FederationRemoteAuthoritySnapshotReceiver,
};
use meshspan_contracts::{
    BackupObjectIdentity, BackupStoreRequest, ContractError as Error, FederatedBackupRequest,
    FederatedBackupScope, federated_provider_backup_identity,
};
use meshspan_data_plane::{FederatedBackupClient, PreparedFederatedBackupUpload};
use meshspan_domain::{Clock, DurationMicros, FederationPolicy, MeshId, Revision, UnixMicros};
use meshspan_metadata::{
    FederationGrantRecord, FederationGrantState, FederationRemoteAuthoritySnapshot,
};
use meshspan_protocol::v1::{
    FederatedBackupAllocationPage, FetchFederatedBackupAllocations, ProtocolVersion,
    federation_envelope::Message,
};
use meshspan_transport::{
    FederationExchangeContext, FederationPeerRegistry, FederationReplayGuard, StreamKind,
    open_stream, receive_federation, send_federation, signed_federation_backup_message,
};

const MAXIMUM_PAGES: usize = 64;
const PAGE_ITEMS: u32 = 32;

impl FederationSessions {
    pub(super) async fn select_backup_allocation(
        &self,
        remote: MeshId,
        request: BackupStoreRequest,
    ) -> Result<PreparedFederatedBackupUpload, Error> {
        let object = request.object;
        let deadline = request.context.deadline;
        let now = crate::OperatingSystemClock.now();
        let remaining = deadline
            .get()
            .checked_sub(now.get())
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(Error::DeadlineExceeded)?;
        tokio::time::timeout(std::time::Duration::from_micros(remaining), async {
            let routes = tokio::task::block_in_place(|| {
                self.authority.routes(crate::OperatingSystemClock.now())
            })
            .map_err(|_| Error::Unavailable)?;
            let mut reached_provider = false;
            for route in routes
                .values()
                .filter(|route| route.authority.local_identity.remote_mesh_id == remote)
            {
                let session = match self.live_session(route) {
                    Ok(session) => session,
                    Err(Error::Unavailable | Error::Stale) => continue,
                    Err(error) => return Err(error),
                };
                reached_provider = true;
                let snapshot = self
                    .backup_grants(&session, route, object, deadline)
                    .await?;
                for grant in snapshot
                    .grants
                    .iter()
                    .filter(|grant| eligible(grant, route))
                {
                    if let Some(scope) = self
                        .backup_allocation(&session, route, grant, request)
                        .await?
                    {
                        return Ok(scope);
                    }
                }
            }
            Err(if reached_provider {
                Error::ResourceExhausted
            } else {
                Error::Unavailable
            })
        })
        .await
        .map_err(|_| Error::DeadlineExceeded)?
    }

    /// Refreshes only permission for an already bound allocation. It never selects replacement
    /// storage or mutates the consumer's immutable physical routing intent.
    pub(super) async fn refresh_backup_scope(
        &self,
        session: &NativeFederationSession,
        route: &PairedRoute,
        retained: FederatedBackupScope,
        request: &FederatedBackupRequest,
    ) -> Result<FederatedBackupScope, Error> {
        let object = request.object();
        let deadline = request.context().deadline;
        let remaining = deadline
            .get()
            .checked_sub(crate::OperatingSystemClock.now().get())
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(Error::DeadlineExceeded)?;
        tokio::time::timeout(std::time::Duration::from_micros(remaining), async {
            let snapshot = self.backup_grants(session, route, object, deadline).await?;
            for grant in snapshot
                .grants
                .iter()
                .filter(|grant| eligible(grant, route))
            {
                let mut cursor = Vec::new();
                for page_index in 0..MAXIMUM_PAGES {
                    let page = self
                        .backup_allocation_page(
                            session,
                            route,
                            FetchFederatedBackupAllocations {
                                grant_id: grant.grant.grant_id().as_bytes().to_vec(),
                                required_bytes: object.byte_length,
                                cursor: cursor.clone(),
                                limit: PAGE_ITEMS,
                                signature: Vec::new(),
                            },
                            context(object, deadline)?,
                        )
                        .await?;
                    for allocation in &page.allocations {
                        let scope = meshspan_data_plane::decode_federated_backup_scope(
                            allocation.scope.as_ref().ok_or(Error::Corrupt)?,
                        )?;
                        let stable = FederatedBackupScope {
                            grant_id: retained.grant_id,
                            grant_revision: retained.grant_revision,
                            relationship_authority_epoch: retained.relationship_authority_epoch,
                            ..scope
                        };
                        if stable != retained {
                            continue;
                        }
                        if scope.grant_revision != grant.revision {
                            return Err(Error::Stale);
                        }
                        let now = crate::OperatingSystemClock.now().get();
                        if allocation.valid_from_unix_micros <= now
                            && allocation.valid_until_unix_micros > now
                        {
                            return Ok(scope);
                        }
                    }
                    if page.next_cursor.is_empty() {
                        break;
                    }
                    if page.next_cursor == cursor {
                        return Err(Error::Corrupt);
                    }
                    if page_index + 1 == MAXIMUM_PAGES {
                        return Err(Error::ResourceExhausted);
                    }
                    cursor = page.next_cursor;
                }
            }
            Err(Error::Unauthorized)
        })
        .await
        .map_err(|_| Error::DeadlineExceeded)?
    }

    async fn backup_grants(
        &self,
        session: &NativeFederationSession,
        route: &PairedRoute,
        object: BackupObjectIdentity,
        deadline: UnixMicros,
    ) -> Result<Box<FederationRemoteAuthoritySnapshot>, Error> {
        let runtime = self
            .session_runtime_with_limits(session.limits)
            .map_err(|_| Error::Unavailable)?;
        let limits = FederationAuthorityImportLimits::new(MAXIMUM_PAGES, 4096, 4 * 1024 * 1024)
            .map_err(|_| Error::InternalContract)?;
        let mut receiver = FederationRemoteAuthoritySnapshotReceiver::new(
            route.authority,
            Revision::new(0),
            limits,
        );
        let mut replay = replay()?;
        for _ in 0..MAXIMUM_PAGES {
            let cursor = receiver
                .next_cursor()
                .ok_or(Error::InternalContract)?
                .to_vec();
            let page = runtime
                .fetch_authority_page(
                    &session.connection,
                    self.authority.as_ref(),
                    FederationAuthorityFetchRequest {
                        relationship_id: session.relationship,
                        context: context(object, deadline)?,
                        after_revision: 0,
                        cursor: cursor.clone(),
                        limit: PAGE_ITEMS,
                        now: crate::OperatingSystemClock.now(),
                    },
                    &mut replay,
                )
                .await
                .map_err(|_| Error::Unavailable)?;
            receiver
                .accept_page(&cursor, &page)
                .map_err(|_| Error::Corrupt)?;
            if receiver.next_cursor().is_none() {
                return match receiver.finish().map_err(|_| Error::Corrupt)? {
                    FederationAuthorityUpdate::Snapshot(snapshot) => Ok(snapshot),
                    FederationAuthorityUpdate::Unchanged { .. } => Err(Error::Corrupt),
                };
            }
        }
        Err(Error::ResourceExhausted)
    }

    async fn backup_allocation(
        &self,
        session: &NativeFederationSession,
        route: &PairedRoute,
        grant: &FederationGrantRecord,
        request: BackupStoreRequest,
    ) -> Result<Option<PreparedFederatedBackupUpload>, Error> {
        let object = request.object;
        let deadline = request.context.deadline;
        let mut cursor = Vec::new();
        for _ in 0..MAXIMUM_PAGES {
            let page = self
                .backup_allocation_page(
                    session,
                    route,
                    FetchFederatedBackupAllocations {
                        grant_id: grant.grant.grant_id().as_bytes().to_vec(),
                        required_bytes: object.byte_length,
                        cursor: cursor.clone(),
                        limit: PAGE_ITEMS,
                        signature: Vec::new(),
                    },
                    context(object, deadline)?,
                )
                .await?;
            for allocation in &page.allocations {
                let scope = meshspan_data_plane::decode_federated_backup_scope(
                    allocation.scope.as_ref().ok_or(Error::Corrupt)?,
                )?;
                federated_provider_backup_identity(scope, object)?;
                if scope.relationship_id != session.relationship
                    || scope.remote_mesh_id != route.authority.local_identity.local_mesh_id
                    || scope.provider_mesh_id != route.authority.local_identity.remote_mesh_id
                    || scope.grant_revision != grant.revision
                {
                    return Err(Error::Stale);
                }
                let now = crate::OperatingSystemClock.now().get();
                if allocation.valid_from_unix_micros <= now
                    && allocation.valid_until_unix_micros > now
                {
                    match self
                        .admit_backup_allocation(session, route, scope, request)
                        .await
                    {
                        Ok(prepared) => return Ok(Some(prepared)),
                        // No source was provided. A confirmed full allocation can be skipped
                        // without abandoning bytes; transport failures remain unavailable.
                        Err(Error::ResourceExhausted) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            if page.next_cursor.is_empty() {
                return Ok(None);
            }
            if page.next_cursor == cursor {
                return Err(Error::Corrupt);
            }
            cursor.clone_from(&page.next_cursor);
        }
        Err(Error::ResourceExhausted)
    }

    async fn backup_allocation_page(
        &self,
        session: &NativeFederationSession,
        route: &PairedRoute,
        query: FetchFederatedBackupAllocations,
        context: FederationExchangeContext,
    ) -> Result<FederatedBackupAllocationPage, Error> {
        let runtime = self
            .session_runtime_with_limits(session.limits)
            .map_err(|_| Error::Unavailable)?;
        let identity = runtime
            .local_identity(&route.authority, crate::OperatingSystemClock.now())
            .map_err(|_| Error::Unauthorized)?;
        let peers =
            FederationPeerRegistry::new([route.authority.peer]).map_err(|_| Error::Unauthorized)?;
        let outbound = signed_federation_backup_message(
            &identity,
            context,
            Message::FetchBackupAllocations(query),
            session.limits.wire,
            crate::OperatingSystemClock.now(),
        )
        .map_err(|_| Error::Unauthorized)?;
        let (mut send, mut receive) = open_stream(&session.connection, StreamKind::Federation)
            .await
            .map_err(|_| Error::Unavailable)?;
        send_federation(&mut send, outbound.envelope(), session.limits.wire)
            .await
            .map_err(|_| Error::Unavailable)?;
        send.finish().map_err(|_| Error::Unavailable)?;
        let response = receive_federation(&mut receive, session.limits.wire)
            .await
            .map_err(|_| Error::Unavailable)?;
        let authenticated = peers
            .authenticate_backup_response(
                &session.connection,
                &response,
                &outbound
                    .expectation()
                    .map_err(|_| Error::InternalContract)?,
                crate::OperatingSystemClock.now(),
                &mut replay()?,
            )
            .map_err(|_| Error::Unauthorized)?;
        if receive
            .read(&mut [0_u8; 1])
            .await
            .map_err(|_| Error::Unavailable)?
            .is_some()
        {
            return Err(Error::Corrupt);
        }
        match authenticated.message() {
            Message::BackupAllocationPage(page) => Ok(page.clone()),
            _ => Err(Error::Corrupt),
        }
    }

    async fn admit_backup_allocation(
        &self,
        session: &NativeFederationSession,
        route: &PairedRoute,
        scope: FederatedBackupScope,
        request: BackupStoreRequest,
    ) -> Result<PreparedFederatedBackupUpload, Error> {
        let runtime = self
            .session_runtime_with_limits(session.limits)
            .map_err(|_| Error::Unavailable)?;
        let identity = runtime
            .local_identity(&route.authority, crate::OperatingSystemClock.now())
            .map_err(|_| Error::Unauthorized)?;
        let peers =
            FederationPeerRegistry::new([route.authority.peer]).map_err(|_| Error::Unauthorized)?;
        let mut client = FederatedBackupClient::new(
            &session.connection,
            &identity,
            &peers,
            session.limits.wire,
            &crate::OperatingSystemClock,
        )
        .map_err(|error| crate::cluster_backup_provider::map_backup_plane_error(&error))?;
        client
            .prepare_upload(scope, request, &mut crate::OperatingSystemRandom)
            .await
            .map_err(|error| crate::cluster_backup_provider::map_backup_plane_error(&error))
    }
}

fn eligible(record: &FederationGrantRecord, route: &PairedRoute) -> bool {
    let grant = &record.grant;
    let now = crate::OperatingSystemClock.now();
    record.state == FederationGrantState::Active
        && grant.recipient_mesh_id() == route.authority.local_identity.local_mesh_id
        && grant.issuer_mesh_id() == route.authority.local_identity.remote_mesh_id
        && grant.valid_from() <= now
        && grant.valid_until().is_none_or(|until| until > now)
        && matches!(grant.policy(), FederationPolicy::Storage(_))
}

fn context(
    object: BackupObjectIdentity,
    deadline: UnixMicros,
) -> Result<FederationExchangeContext, Error> {
    // A long-lived export may perform several bounded exchanges. Do not put the
    // export's whole lifetime into a single replay-protected discovery message.
    let deadline = deadline.min(
        crate::OperatingSystemClock
            .now()
            .checked_add(DurationMicros::new(
                meshspan_contracts::MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS.unsigned_abs(),
            ))
            .ok_or(Error::InvalidInput)?,
    );
    FederationExchangeContext::new(
        ProtocolVersion { major: 1, minor: 0 },
        super::random().map_err(|_| Error::Unavailable)?,
        object.backup_id.as_bytes(),
        object.backup_id.as_bytes(),
        deadline,
        super::random().map_err(|_| Error::Unavailable)?,
    )
    .map_err(|_| Error::InvalidInput)
}

fn replay() -> Result<FederationReplayGuard, Error> {
    FederationReplayGuard::new(
        MAXIMUM_PAGES * 2,
        DurationMicros::new(
            meshspan_contracts::MAXIMUM_FEDERATED_BACKUP_PERMIT_LIFETIME_MICROS.unsigned_abs(),
        ),
    )
    .map_err(|_| Error::InternalContract)
}
