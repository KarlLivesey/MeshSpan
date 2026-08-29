// SPDX-License-Identifier: GPL-2.0-only

//! Restart-resumable authenticated history convergence between autonomous swarms.

use std::collections::BTreeSet;

use meshspan_domain::{
    FederationGrantId, FederationRelationshipId, FederationResourceScope, NamespaceCommitId,
    UnixMicros,
};
use meshspan_filesystem::{
    NamespaceHistoryCommitRecord, NamespaceHistoryLimits, NamespaceHistoryPage,
    NamespaceHistoryReceiveCompletion, NamespaceHistoryReceiveRequest,
    NamespaceHistoryReceiveStatus,
};
use meshspan_transport::{
    AuthenticatedFederationBranchPage, FederationExchangeContext, FederationReplayGuard,
};
use thiserror::Error;

use crate::federation_branch_exchange::admitted_history_grant;
use crate::federation_filesystem_history::{authority_binding, volume_scope};
use crate::{
    FederationAuthoritySource, FederationBranchAuthoritySource, FederationBranchFetchRequest,
    FederationHistoryObjectFetchRequest, FederationHistoryReceiveError, FederationHistoryReceiver,
    FederationSessionError, FederationSessionRuntime,
};

const HISTORY_RECORD_FORMAT_VERSION: u32 = 1;
const MAXIMUM_EXCHANGES_PER_RUN: usize = 4_096;
const MAXIMUM_HEADS: usize = 64;
const MAXIMUM_KNOWN_COMMITS: usize = 4_096;
const MAXIMUM_PAGE_RECORDS: u32 = 4_096;

/// One bounded convergence run. Reusing the session with fresh contexts resumes exact progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationHistorySyncRequest {
    /// Receiver-selected durable idempotency identity.
    pub session_id: [u8; 32],
    /// Active autonomous-swarm relationship.
    pub relationship_id: FederationRelationshipId,
    /// Current bilateral namespace grant.
    pub grant_id: FederationGrantId,
    /// Exact shared volume resource.
    pub resource: FederationResourceScope,
    /// Source heads whose causal histories must become available locally.
    pub requested_heads: Vec<NamespaceCommitId>,
    /// Commit identities already known to the receiver before this session started.
    pub known_commits: Vec<NamespaceCommitId>,
    /// Complete receiver-side record bounds.
    pub limits: NamespaceHistoryLimits,
    /// Maximum combined records requested per signed page.
    pub page_limit: u32,
    /// Fresh correlation/deadline/nonce material, one entry per network exchange in this run.
    pub exchange_contexts: Vec<FederationExchangeContext>,
    /// Current authoritative mesh time for this run.
    pub now: UnixMicros,
    /// Stable expiry shared by every resumed run of this receive session.
    pub expires_at: UnixMicros,
}

/// Durable result of one bounded convergence run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FederationHistorySyncOutcome {
    /// Fresh context budget ended; all reported progress is durable and may be resumed.
    Progress {
        /// Signed pages accepted in this run.
        pages: usize,
        /// Independently streamed immutable objects accepted in this run.
        objects: usize,
        /// Exact durable receiver checkpoint.
        receive: NamespaceHistoryReceiveStatus,
    },
    /// The complete authenticated graph was atomically imported.
    Completed {
        /// Signed pages accepted in this run.
        pages: usize,
        /// Independently streamed immutable objects accepted in this run.
        objects: usize,
        /// Applied or replayed durable import receipt.
        completion: NamespaceHistoryReceiveCompletion,
    },
}

impl FederationSessionRuntime<'_> {
    /// Drives signed pages and object streams into one restart-safe atomic filesystem import.
    ///
    /// # Errors
    ///
    /// Rejects invalid run bounds, changed authority, hostile wire records or receiver corruption.
    pub async fn sync_federated_history(
        &self,
        connection: &quinn::Connection,
        authority: &impl FederationAuthoritySource,
        grants: &impl FederationBranchAuthoritySource,
        receiver: &impl FederationHistoryReceiver,
        request: FederationHistorySyncRequest,
        replay: &mut FederationReplayGuard,
    ) -> Result<FederationHistorySyncOutcome, FederationHistorySyncError> {
        validate_request(&request)?;
        let grant = admitted_history_grant(
            grants,
            request.relationship_id,
            request.grant_id,
            request.resource,
            request.now,
        )?;
        let volume_id = volume_scope(request.resource)
            .map_err(|_| FederationHistorySyncError::InvalidRequest)?;
        let mut receive = receiver
            .begin(NamespaceHistoryReceiveRequest {
                session_id: request.session_id,
                scope_binding: authority_binding(grant, request.resource),
                volume_id,
                requested_heads: request.requested_heads.clone(),
                limits: request.limits,
                now: request.now,
                expires_at: request.expires_at,
            })
            .await?;
        let mut contexts = request.exchange_contexts.into_iter();
        let mut pages = 0_usize;
        let mut objects = 0_usize;
        loop {
            if receive.completed || (receive.terminal && receive.missing_immutable_records == 0) {
                let completion = receiver.complete(request.session_id, request.now).await?;
                return Ok(FederationHistorySyncOutcome::Completed {
                    pages,
                    objects,
                    completion,
                });
            }
            let Some(context) = contexts.next() else {
                return Ok(FederationHistorySyncOutcome::Progress {
                    pages,
                    objects,
                    receive,
                });
            };
            if let Some(object_digest) = receive.next_missing_immutable_record {
                let export_token = receive
                    .export_token
                    .ok_or(FederationHistorySyncError::InvalidResponse)?;
                let record = self
                    .fetch_history_object(
                        connection,
                        authority,
                        grants,
                        FederationHistoryObjectFetchRequest {
                            relationship_id: request.relationship_id,
                            grant_id: request.grant_id,
                            resource: request.resource,
                            export_token,
                            object_digest,
                            context,
                            now: request.now,
                        },
                        replay,
                    )
                    .await?;
                receive = receiver
                    .accept_object(request.session_id, record, request.now)
                    .await?;
                objects = checked_increment(objects)?;
                continue;
            }
            let input_cursor = receive.next_cursor.clone();
            let page = self
                .fetch_branch_page(
                    connection,
                    authority,
                    grants,
                    FederationBranchFetchRequest {
                        relationship_id: request.relationship_id,
                        grant_id: request.grant_id,
                        resource: request.resource,
                        requested_heads: request.requested_heads.clone(),
                        known_commits: request.known_commits.clone(),
                        cursor: input_cursor.clone(),
                        limit: request.page_limit,
                        context,
                        now: request.now,
                    },
                    replay,
                )
                .await?;
            receive = receiver
                .accept_page(
                    request.session_id,
                    input_cursor,
                    decode_page(&page)?,
                    request.now,
                )
                .await?;
            pages = checked_increment(pages)?;
        }
    }
}

fn validate_request(
    request: &FederationHistorySyncRequest,
) -> Result<(), FederationHistorySyncError> {
    let heads = request
        .requested_heads
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let known = request
        .known_commits
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let request_ids = request
        .exchange_contexts
        .iter()
        .map(|context| context.request_id)
        .collect::<BTreeSet<_>>();
    let replay_nonces = request
        .exchange_contexts
        .iter()
        .map(|context| context.replay_nonce)
        .collect::<BTreeSet<_>>();
    if request.session_id == [0; 32]
        || request.page_limit == 0
        || request.page_limit > MAXIMUM_PAGE_RECORDS
        || request.exchange_contexts.is_empty()
        || request.exchange_contexts.len() > MAXIMUM_EXCHANGES_PER_RUN
        || request_ids.len() != request.exchange_contexts.len()
        || replay_nonces.len() != request.exchange_contexts.len()
        || request
            .exchange_contexts
            .iter()
            .any(|context| context.deadline <= request.now || context.deadline > request.expires_at)
        || request.requested_heads.is_empty()
        || request.requested_heads.len() > MAXIMUM_HEADS
        || request.known_commits.len() > MAXIMUM_KNOWN_COMMITS
        || heads.len() != request.requested_heads.len()
        || known.len() != request.known_commits.len()
        || request.requested_heads.len() > request.limits.maximum_heads
        || request.now >= request.expires_at
    {
        Err(FederationHistorySyncError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn decode_page(
    page: &AuthenticatedFederationBranchPage,
) -> Result<NamespaceHistoryPage, FederationHistorySyncError> {
    let commits = page
        .branch_commits()
        .iter()
        .map(|record| {
            if record.format_version != HISTORY_RECORD_FORMAT_VERSION {
                return Err(FederationHistorySyncError::InvalidResponse);
            }
            NamespaceHistoryCommitRecord::from_canonical_bytes(record.canonical_bytes.clone())
                .map_err(|_| FederationHistorySyncError::InvalidResponse)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NamespaceHistoryPage {
        export_token: exact_digest(page.export_token())?,
        commits,
        immutable_object_digests: page
            .immutable_object_digests()
            .iter()
            .map(|digest| exact_digest(digest))
            .collect::<Result<Vec<_>, _>>()?,
        next_cursor: page.next_cursor().to_vec(),
    })
}

fn exact_digest(bytes: &[u8]) -> Result<[u8; 32], FederationHistorySyncError> {
    bytes
        .try_into()
        .map_err(|_| FederationHistorySyncError::InvalidResponse)
}

fn checked_increment(value: usize) -> Result<usize, FederationHistorySyncError> {
    value
        .checked_add(1)
        .ok_or(FederationHistorySyncError::InvalidResponse)
}

/// Closed failures for one bounded authenticated history convergence run.
#[derive(Debug, Error)]
pub enum FederationHistorySyncError {
    /// Caller bounds, resource or context budget are unusable.
    #[error("federation history sync request is invalid")]
    InvalidRequest,
    /// An authenticated peer returned structurally or canonically invalid history.
    #[error("federation history sync response is invalid")]
    InvalidResponse,
    /// One signed mTLS Quinn exchange failed.
    #[error("federation history sync transport failed")]
    Session(#[from] FederationSessionError),
    /// The durable receiver rejected or could not persist progress.
    #[error("federation history sync receiver failed")]
    Receive(#[from] FederationHistoryReceiveError),
}
