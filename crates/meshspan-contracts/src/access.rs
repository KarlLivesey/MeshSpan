// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable public access-connector and administration-client contracts.

use meshspan_domain::{AssuranceLevel, ObjectId, PrincipalId, Revision, Rights, VolumeId};

use crate::{BoundedBytes, ComponentLifecycle, ContractError, RequestContext, VersionedPayload};

/// Protocol-neutral filesystem operation emitted by an access connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessOperation {
    /// Resolve attributes without reading file data.
    Inspect,
    /// Enumerate one directory page.
    List,
    /// Read a bounded file range.
    Read,
    /// Create a file or directory.
    Create,
    /// Replace or append file data.
    Write,
    /// Rename or move one namespace object.
    Rename,
    /// Delete one namespace object.
    Delete,
    /// Read or change owners and permission grants.
    ManageAccess,
}

/// Authenticated, session-bound connector context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessSession {
    /// Authenticated user or service principal.
    pub principal_id: PrincipalId,
    /// Assurance proved by the current authentication session.
    pub assurance: AssuranceLevel,
    /// Digest binding transport, authentication and session expiry.
    pub session_binding_digest: [u8; 32],
    /// Authoritative identity revision used to establish the session.
    pub identity_revision: Revision,
}

/// One bounded protocol-neutral filesystem intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessIntent {
    /// Operation identity, deadline and compare-and-swap context.
    pub context: RequestContext,
    /// Authenticated session; connectors cannot invent anonymous authority.
    pub session: AccessSession,
    /// Closed filesystem operation.
    pub operation: AccessOperation,
    /// Volume addressed by the protocol request.
    pub volume_id: VolumeId,
    /// Existing object addressed by the request, when applicable.
    pub object_id: Option<ObjectId>,
    /// Rights required before any expensive data or metadata work begins.
    pub required_rights: Rights,
    /// Independently versioned bounded operation parameters.
    pub parameters: VersionedPayload,
}

/// Authoritative result supplied to a connector for protocol encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessResult {
    /// Operation and deadline context copied from the accepted intent.
    pub context: RequestContext,
    /// Authoritative result revision.
    pub revision: Revision,
    /// Independently versioned bounded result or error detail.
    pub payload: VersionedPayload,
}

/// Public filesystem protocol translation without authentication or data authority.
pub trait AccessConnector: ComponentLifecycle {
    /// Decodes one already size-bounded request into a protocol-neutral intent.
    ///
    /// # Errors
    ///
    /// Rejects malformed, unauthenticated, unsupported or excessive requests before domain work.
    fn decode_request(
        &self,
        session: AccessSession,
        request: &BoundedBytes,
    ) -> Result<AccessIntent, ContractError>;

    /// Encodes one authoritative result into a bounded protocol response.
    ///
    /// # Errors
    ///
    /// Rejects unsupported results or any encoding that exceeds advertised limits.
    fn encode_response(&self, result: &AccessResult) -> Result<BoundedBytes, ContractError>;
}

/// Semantic administrator action prepared by a replaceable client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrationIntent {
    /// Operation identity, deadline and compare-and-swap context.
    pub context: RequestContext,
    /// Rights that the server must authorise before executing the action.
    pub required_rights: Rights,
    /// Stable API operation and bounded canonical request representation.
    pub request: VersionedPayload,
}

/// Server response consumed by a replaceable administration client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrationResult {
    /// Exact originating operation identity and API contract version.
    pub context: RequestContext,
    /// Authority revision observed after the action.
    pub revision: Revision,
    /// Stable bounded public response representation.
    pub response: VersionedPayload,
}

/// Administration-client adapter proven against generated public API fixtures.
pub trait AdministrationClient: ComponentLifecycle {
    /// Produces one bounded public request from a semantic administrator action.
    ///
    /// # Errors
    ///
    /// Rejects unsupported versions, missing authentication context or excessive values.
    fn encode_request(&self, intent: &AdministrationIntent) -> Result<BoundedBytes, ContractError>;

    /// Validates and decodes a bounded public response before client state may use it.
    ///
    /// # Errors
    ///
    /// Rejects malformed, mismatched, unsupported or excessive server responses.
    fn decode_response(
        &self,
        context: RequestContext,
        response: &BoundedBytes,
    ) -> Result<AdministrationResult, ContractError>;
}
