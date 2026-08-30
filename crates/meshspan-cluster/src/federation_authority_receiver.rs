// SPDX-License-Identifier: GPL-2.0-only

//! Fail-closed assembly of authenticated authority pages into one complete remote snapshot.

use std::collections::BTreeSet;

use meshspan_domain::{FederationGrantId, Revision};
use meshspan_metadata::{
    FederationGovernanceDirection, FederationGrantRecord, FederationRemoteAuthoritySnapshot,
    FederationTransportAuthority,
};
use meshspan_protocol::v1::VersionedPayload;
use meshspan_transport::AuthenticatedFederationAuthorityPage;
use thiserror::Error;

use crate::FederationConnectionAuthority;

/// Explicit whole-import resource ceilings selected by the daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationAuthorityImportLimits {
    pages: usize,
    records: usize,
    canonical_bytes: usize,
}

impl FederationAuthorityImportLimits {
    /// Constructs non-zero whole-import bounds.
    ///
    /// # Errors
    ///
    /// Rejects any zero limit because it could not accept one valid changed snapshot.
    pub const fn new(
        maximum_pages: usize,
        maximum_records: usize,
        maximum_canonical_bytes: usize,
    ) -> Result<Self, FederationAuthorityImportError> {
        if maximum_pages == 0 || maximum_records == 0 || maximum_canonical_bytes == 0 {
            Err(FederationAuthorityImportError::Invalid)
        } else {
            Ok(Self {
                pages: maximum_pages,
                records: maximum_records,
                canonical_bytes: maximum_canonical_bytes,
            })
        }
    }

    /// Returns the maximum complete page count admitted by this import.
    #[must_use]
    pub const fn maximum_pages(self) -> usize {
        self.pages
    }
}

/// Terminal result of one complete remote authority fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FederationAuthorityUpdate {
    /// The peer was already exactly at the requested revision.
    Unchanged {
        /// Confirmed peer authority revision.
        authority_revision: Revision,
    },
    /// One complete changed snapshot ready for a separate authoritative transition.
    Snapshot(Box<FederationRemoteAuthoritySnapshot>),
}

/// Bounded receiver which never exposes records from an incomplete page sequence.
pub struct FederationRemoteAuthoritySnapshotReceiver {
    local_authority: FederationConnectionAuthority,
    after_revision: Revision,
    limits: FederationAuthorityImportLimits,
    authority_revision: Option<Revision>,
    relationship: Option<FederationTransportAuthority>,
    grants: Vec<FederationGrantRecord>,
    last_grant: Option<(Revision, FederationGrantId)>,
    expected_cursor: Vec<u8>,
    seen_cursors: BTreeSet<Vec<u8>>,
    page_count: usize,
    record_count: usize,
    canonical_bytes: usize,
    complete: bool,
    unchanged: bool,
    failed: bool,
}

impl FederationRemoteAuthoritySnapshotReceiver {
    /// Starts one import from the exact current local relationship binding.
    #[must_use]
    pub fn new(
        local_authority: FederationConnectionAuthority,
        after_revision: Revision,
        limits: FederationAuthorityImportLimits,
    ) -> Self {
        Self {
            local_authority,
            after_revision,
            limits,
            authority_revision: None,
            relationship: None,
            grants: Vec::new(),
            last_grant: None,
            expected_cursor: Vec::new(),
            seen_cursors: BTreeSet::new(),
            page_count: 0,
            record_count: 0,
            canonical_bytes: 0,
            complete: false,
            unchanged: false,
            failed: false,
        }
    }

    /// Accepts the next transport-authenticated page for the exact requested continuation.
    ///
    /// # Errors
    ///
    /// Rejects gaps, replayed cursors, mixed revisions, malformed records, identity reflection,
    /// broadened grants, non-canonical ordering or any configured whole-import limit breach.
    pub fn accept_page(
        &mut self,
        requested_cursor: &[u8],
        page: &AuthenticatedFederationAuthorityPage,
    ) -> Result<(), FederationAuthorityImportError> {
        let view = AuthorityPageView {
            authority_revision: page.authority_revision(),
            records: page.records(),
            next_cursor: page.next_cursor(),
        };
        self.accept_page_view(requested_cursor, view)
    }

    fn accept_page_view(
        &mut self,
        requested_cursor: &[u8],
        page: AuthorityPageView<'_>,
    ) -> Result<(), FederationAuthorityImportError> {
        let result = self.try_accept_page_view(requested_cursor, page);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn try_accept_page_view(
        &mut self,
        requested_cursor: &[u8],
        page: AuthorityPageView<'_>,
    ) -> Result<(), FederationAuthorityImportError> {
        if self.complete || self.failed || requested_cursor != self.expected_cursor {
            return Err(FederationAuthorityImportError::Invalid);
        }
        self.reserve_page(page)?;
        let authority_revision = positive_revision(page.authority_revision)?;
        self.bind_revision(authority_revision)?;
        if authority_revision == self.after_revision {
            return self.accept_unchanged_page(page);
        }
        if page.records.is_empty() {
            return Err(FederationAuthorityImportError::Invalid);
        }
        self.accept_records(page)?;
        self.advance_cursor(page.next_cursor)
    }

    /// Returns the exact opaque continuation required for the next fetch.
    #[must_use]
    pub fn next_cursor(&self) -> Option<&[u8]> {
        if self.complete || self.failed {
            None
        } else {
            Some(&self.expected_cursor)
        }
    }

    /// Finishes only after a terminal authenticated page completed the sequence.
    ///
    /// # Errors
    ///
    /// Rejects incomplete or structurally impossible sequences without exposing partial records.
    pub fn finish(self) -> Result<FederationAuthorityUpdate, FederationAuthorityImportError> {
        if self.failed {
            return Err(FederationAuthorityImportError::Invalid);
        }
        if !self.complete {
            return Err(FederationAuthorityImportError::Incomplete);
        }
        let authority_revision = self
            .authority_revision
            .ok_or(FederationAuthorityImportError::Invalid)?;
        if self.unchanged {
            return Ok(FederationAuthorityUpdate::Unchanged { authority_revision });
        }
        let relationship = self
            .relationship
            .ok_or(FederationAuthorityImportError::Invalid)?;
        Ok(FederationAuthorityUpdate::Snapshot(Box::new(
            FederationRemoteAuthoritySnapshot {
                after_revision: self.after_revision,
                authority_revision,
                relationship,
                grants: self.grants,
            },
        )))
    }

    fn reserve_page(
        &mut self,
        page: AuthorityPageView<'_>,
    ) -> Result<(), FederationAuthorityImportError> {
        self.page_count = self
            .page_count
            .checked_add(1)
            .ok_or(FederationAuthorityImportError::CapacityExceeded)?;
        self.record_count = self
            .record_count
            .checked_add(page.records.len())
            .ok_or(FederationAuthorityImportError::CapacityExceeded)?;
        let page_bytes = page.records.iter().try_fold(0_usize, |total, record| {
            total
                .checked_add(record.canonical_bytes.len())
                .ok_or(FederationAuthorityImportError::CapacityExceeded)
        })?;
        self.canonical_bytes = self
            .canonical_bytes
            .checked_add(page_bytes)
            .ok_or(FederationAuthorityImportError::CapacityExceeded)?;
        if self.page_count > self.limits.pages
            || self.record_count > self.limits.records
            || self.canonical_bytes > self.limits.canonical_bytes
        {
            Err(FederationAuthorityImportError::CapacityExceeded)
        } else {
            Ok(())
        }
    }

    fn bind_revision(
        &mut self,
        authority_revision: Revision,
    ) -> Result<(), FederationAuthorityImportError> {
        if authority_revision < self.after_revision
            || self
                .authority_revision
                .is_some_and(|current| current != authority_revision)
        {
            return Err(FederationAuthorityImportError::Invalid);
        }
        self.authority_revision = Some(authority_revision);
        Ok(())
    }

    fn accept_unchanged_page(
        &mut self,
        page: AuthorityPageView<'_>,
    ) -> Result<(), FederationAuthorityImportError> {
        if self.page_count != 1 || !page.records.is_empty() || !page.next_cursor.is_empty() {
            return Err(FederationAuthorityImportError::Invalid);
        }
        self.unchanged = true;
        self.complete = true;
        Ok(())
    }

    fn accept_records(
        &mut self,
        page: AuthorityPageView<'_>,
    ) -> Result<(), FederationAuthorityImportError> {
        let mut records = page.records.iter();
        if self.relationship.is_none() {
            let relationship = records
                .next()
                .ok_or(FederationAuthorityImportError::Invalid)
                .and_then(decode_relationship)?;
            self.validate_relationship(&relationship)?;
            self.relationship = Some(relationship);
        }
        for record in records {
            let grant = decode_grant(record)?;
            self.validate_grant(&grant)?;
            self.last_grant = Some((grant.revision, grant.grant.grant_id()));
            self.grants.push(grant);
        }
        Ok(())
    }

    fn validate_relationship(
        &self,
        authority: &FederationTransportAuthority,
    ) -> Result<(), FederationAuthorityImportError> {
        let local = self.local_authority.local_identity;
        let peer = self.local_authority.peer;
        let relationship = &authority.relationship;
        let valid = authority.authority_revision == self.authority_revision.unwrap_or_default()
            && relationship.relationship_id == peer.relationship_id
            && relationship.local_mesh_id == peer.remote_mesh_id
            && relationship.remote_mesh_id == peer.local_mesh_id
            && relationship.kind == self.local_authority.relationship_kind
            && relationship.governance_direction
                == mirrored_direction(self.local_authority.governance_direction)
            && relationship.authority_epoch == peer.authority_epoch
            && identity_matches(&authority.local_identity.identity, peer)
            && identity_matches_local(&authority.remote_identity.identity, local);
        if valid {
            Ok(())
        } else {
            Err(FederationAuthorityImportError::Invalid)
        }
    }

    fn validate_grant(
        &self,
        record: &FederationGrantRecord,
    ) -> Result<(), FederationAuthorityImportError> {
        let peer = self.local_authority.peer;
        let key = (record.revision, record.grant.grant_id());
        let parties = [peer.local_mesh_id, peer.remote_mesh_id];
        let valid = record.grant.relationship_id() == peer.relationship_id
            && record.grant.authority_epoch() == peer.authority_epoch
            && parties.contains(&record.grant.issuer_mesh_id())
            && parties.contains(&record.grant.recipient_mesh_id())
            && parties.contains(&record.grant.resource().authority_mesh_id())
            && record.revision > self.after_revision
            && self
                .authority_revision
                .is_some_and(|revision| record.revision <= revision)
            && self.last_grant.is_none_or(|last| last < key);
        if valid {
            Ok(())
        } else {
            Err(FederationAuthorityImportError::Invalid)
        }
    }

    fn advance_cursor(&mut self, cursor: &[u8]) -> Result<(), FederationAuthorityImportError> {
        if cursor.is_empty() {
            self.complete = true;
            self.expected_cursor.clear();
            return Ok(());
        }
        if cursor == self.expected_cursor || !self.seen_cursors.insert(cursor.to_vec()) {
            return Err(FederationAuthorityImportError::Invalid);
        }
        self.expected_cursor.clear();
        self.expected_cursor.extend_from_slice(cursor);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct AuthorityPageView<'a> {
    authority_revision: u64,
    records: &'a [VersionedPayload],
    next_cursor: &'a [u8],
}

fn decode_relationship(
    payload: &meshspan_protocol::v1::VersionedPayload,
) -> Result<FederationTransportAuthority, FederationAuthorityImportError> {
    if payload.format_version != 1 {
        return Err(FederationAuthorityImportError::UnsupportedVersion);
    }
    FederationTransportAuthority::from_canonical_bytes(&payload.canonical_bytes)
        .map_err(|_| FederationAuthorityImportError::Invalid)
}

fn decode_grant(
    payload: &meshspan_protocol::v1::VersionedPayload,
) -> Result<FederationGrantRecord, FederationAuthorityImportError> {
    if payload.format_version != 1 {
        return Err(FederationAuthorityImportError::UnsupportedVersion);
    }
    FederationGrantRecord::from_canonical_bytes(&payload.canonical_bytes)
        .map_err(|_| FederationAuthorityImportError::Invalid)
}

fn positive_revision(value: u64) -> Result<Revision, FederationAuthorityImportError> {
    if value == 0 {
        Err(FederationAuthorityImportError::Invalid)
    } else {
        Ok(Revision::new(value))
    }
}

const fn mirrored_direction(
    direction: FederationGovernanceDirection,
) -> FederationGovernanceDirection {
    match direction {
        FederationGovernanceDirection::None => FederationGovernanceDirection::None,
        FederationGovernanceDirection::LocalGovernsRemote => {
            FederationGovernanceDirection::RemoteGovernsLocal
        }
        FederationGovernanceDirection::RemoteGovernsLocal => {
            FederationGovernanceDirection::LocalGovernsRemote
        }
    }
}

fn identity_matches(
    identity: &meshspan_metadata::FederationTrustIdentity,
    binding: meshspan_transport::FederationPeerBinding,
) -> bool {
    identity.generation == binding.identity_generation
        && identity.certificate_fingerprint == binding.certificate_fingerprint
        && identity.verifying_key == binding.verifying_key
        && identity.valid_from == binding.valid_from
        && identity.valid_until == binding.valid_until
}

fn identity_matches_local(
    identity: &meshspan_metadata::FederationTrustIdentity,
    binding: meshspan_transport::FederationLocalIdentityBinding,
) -> bool {
    identity.generation == binding.identity_generation
        && identity.certificate_fingerprint == binding.certificate_fingerprint
        && identity.verifying_key == binding.verifying_key
        && identity.valid_from == binding.valid_from
        && identity.valid_until == binding.valid_until
}

/// Closed receiver failures which never reveal remote-controlled record details.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationAuthorityImportError {
    /// The page sequence or decoded authority contradicts the local trust binding.
    #[error("federation authority import is invalid")]
    Invalid,
    /// A record declared a representation this receiver does not understand.
    #[error("federation authority import version is unsupported")]
    UnsupportedVersion,
    /// The configured whole-import page, record or byte ceiling was exceeded.
    #[error("federation authority import capacity is exceeded")]
    CapacityExceeded,
    /// The caller attempted to expose an import before its terminal page.
    #[error("federation authority import is incomplete")]
    Incomplete,
}

#[cfg(test)]
#[path = "federation_authority_receiver_tests.rs"]
mod tests;
