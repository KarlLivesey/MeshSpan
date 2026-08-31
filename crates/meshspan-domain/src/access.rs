// SPDX-License-Identifier: GPL-2.0-only

//! Nested group membership and activation-required access decisions.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::{
    DurationMicros, FederationAssignmentId, GrantId, GroupId, OperationId, PrincipalId, Revision,
    UnixMicros,
};

const MAX_GROUPS: usize = 4_096;
const MAX_MEMBERSHIPS: usize = 65_536;
const MAX_ACTIVATION_REASON_BYTES: usize = 512;
const MAX_OWNERS: usize = 1_024;

/// Protocol-neutral namespace rights stored as a validated bitset.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rights(u32);

impl Rights {
    /// Traverse ancestor directories.
    pub const TRAVERSE: Self = Self(1 << 0);
    /// Enumerate directory entries.
    pub const LIST: Self = Self(1 << 1);
    /// Read file content.
    pub const READ_DATA: Self = Self(1 << 2);
    /// Create a child object.
    pub const CREATE_CHILD: Self = Self(1 << 3);
    /// Replace or modify file content.
    pub const WRITE_DATA: Self = Self(1 << 4);
    /// Append file content.
    pub const APPEND_DATA: Self = Self(1 << 5);
    /// Rename or move an object.
    pub const RENAME: Self = Self(1 << 6);
    /// Delete an object or empty directory.
    pub const DELETE: Self = Self(1 << 7);
    /// Read object attributes.
    pub const READ_ATTRIBUTES: Self = Self(1 << 8);
    /// Change object attributes.
    pub const WRITE_ATTRIBUTES: Self = Self(1 << 9);
    /// Read owners and permission grants.
    pub const READ_PERMISSIONS: Self = Self(1 << 10);
    /// Change permission grants.
    pub const CHANGE_PERMISSIONS: Self = Self(1 << 11);
    /// Change the owner set.
    pub const CHANGE_OWNER: Self = Self(1 << 12);
    /// Every currently defined right.
    pub const ALL: Self = Self((1 << 13) - 1);

    /// Validates a persisted or wire bitset.
    ///
    /// # Errors
    ///
    /// Returns [`RightsError::UnknownBits`] if any unknown bit is set.
    pub const fn from_bits(bits: u32) -> Result<Self, RightsError> {
        if bits & !Self::ALL.0 == 0 {
            Ok(Self(bits))
        } else {
            Err(RightsError::UnknownBits)
        }
    }

    /// Returns the stable wire/storage bitset.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Reports whether this value grants no rights.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns the union of independently applicable allow grants.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the rights permitted by both independently authoritative restrictions.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Reports whether every requested right is present.
    #[must_use]
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }
}

/// Rejection of a persisted or wire rights representation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RightsError {
    /// At least one undefined bit was set.
    #[error("rights bitset contains an unknown right")]
    UnknownBits,
}

/// Non-empty immutable owner set with an authority revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSet {
    owners: BTreeSet<PrincipalId>,
    revision: Revision,
}

impl OwnerSet {
    /// Constructs an owner set after validating its cardinality.
    ///
    /// # Errors
    ///
    /// Rejects an empty or excessively large owner set.
    pub fn new(owners: BTreeSet<PrincipalId>, revision: Revision) -> Result<Self, OwnerSetError> {
        validate_owners(&owners)?;
        Ok(Self { owners, revision })
    }

    /// Returns owners in stable identity order.
    #[must_use]
    pub const fn owners(&self) -> &BTreeSet<PrincipalId> {
        &self.owners
    }

    /// Returns the authoritative owner-set revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Atomically replaces all owners at an expected revision.
    ///
    /// # Errors
    ///
    /// Rejects stale input, an empty result, excessive cardinality or revision exhaustion.
    pub fn replace(
        &self,
        expected_revision: Revision,
        owners: BTreeSet<PrincipalId>,
    ) -> Result<Self, OwnerSetError> {
        if expected_revision != self.revision {
            return Err(OwnerSetError::StaleRevision);
        }
        validate_owners(&owners)?;
        let revision = self
            .revision
            .next()
            .map_err(|_| OwnerSetError::RevisionExhausted)?;
        Ok(Self { owners, revision })
    }
}

fn validate_owners(owners: &BTreeSet<PrincipalId>) -> Result<(), OwnerSetError> {
    if owners.is_empty() {
        Err(OwnerSetError::Ownerless)
    } else if owners.len() > MAX_OWNERS {
        Err(OwnerSetError::CapacityExceeded)
    } else {
        Ok(())
    }
}

/// Rejection of owner-set or rights input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OwnerSetError {
    /// An object cannot have no owner principals.
    #[error("owner set must contain at least one principal")]
    Ownerless,
    /// Owner cardinality exceeds the explicit domain bound.
    #[error("owner set exceeds its bounded capacity")]
    CapacityExceeded,
    /// The caller attempted to replace a newer owner-set revision.
    #[error("owner set revision is stale")]
    StaleRevision,
    /// The monotonic owner-set revision space is exhausted.
    #[error("owner set revision space is exhausted")]
    RevisionExhausted,
}

/// Authentication assurance available to an access decision.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AssuranceLevel {
    /// One accepted authentication factor.
    SingleFactor,
    /// Multiple independent accepted factors.
    MultiFactor,
    /// A recent privileged step-up ceremony.
    RecentStepUp,
}

/// Connector family for which an authentication method or session is valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthenticationService {
    /// Browser HTTPS sessions established through the interactive authentication flow.
    Https = 1,
    /// `MeshSpan`'s native HTTPS administration and data API for arbitrary external clients.
    HeadlessApi = 2,
    /// Embedded SMB 3.1.1 session establishment.
    Smb = 4,
}

impl AuthenticationService {
    /// Returns the service bit used by authentication-method compatibility scopes.
    #[must_use]
    pub const fn scope_bit(self) -> u8 {
        self as u8
    }

    /// Returns the API-key capability bit required to authenticate this service.
    #[must_use]
    pub const fn api_key_login_scope(self) -> u64 {
        self as u64
    }
}

/// Stable operation families governed by authentication policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthenticationOperationClass {
    /// Creation of a new service-bound session.
    SessionEstablishment = 1,
    /// Ordinary authenticated file and account operations.
    Ordinary = 2,
    /// Security-sensitive administration or permission changes.
    Privileged = 3,
    /// Explicit recovery operations with separately audited authority.
    Recovery = 4,
}

impl AuthenticationOperationClass {
    /// Returns the stable storage and wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// Typed authentication-method family retained as session evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthenticationMethodKind {
    /// `WebAuthn` public-key credential and assertion ceremony.
    Passkey = 1,
    /// Time-based one-time password used only as an additional factor.
    Totp = 2,
    /// Single-use recovery code used only for recovery or step-up.
    RecoveryCode = 3,
    /// Scoped high-entropy API key.
    ApiKey = 4,
}

impl AuthenticationMethodKind {
    /// Reports whether this method can establish a primary login by itself.
    #[must_use]
    pub const fn is_primary(self) -> bool {
        matches!(self, Self::Passkey | Self::ApiKey)
    }

    /// Returns this method's bit in an authentication-policy class set.
    #[must_use]
    pub const fn class_bit(self) -> u8 {
        1 << (self as u8 - 1)
    }
}

/// Non-empty, closed set of authentication-method classes allowed by policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticationFactorClasses(u8);

impl AuthenticationFactorClasses {
    /// Every method class implemented by the initial authentication model.
    pub const ALL: Self = Self(0b1111);

    /// Validates a non-empty class bitset with no unknown bits.
    ///
    /// # Errors
    ///
    /// Rejects an empty set or any bit not assigned to a method class.
    pub const fn new(bits: u8) -> Result<Self, AuthenticationFactorClassesError> {
        if bits == 0 || bits & !Self::ALL.0 != 0 {
            Err(AuthenticationFactorClassesError::InvalidBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns the stable storage and wire bitset.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Reports whether this set permits one exact method class.
    #[must_use]
    pub const fn contains(self, kind: AuthenticationMethodKind) -> bool {
        self.0 & kind.class_bit() != 0
    }
}

/// Rejection of an authentication-policy class bitset.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationFactorClassesError {
    /// The bitset is empty or contains an unknown method class.
    #[error("authentication factor classes are empty or contain unknown bits")]
    InvalidBits,
}

/// Exact pre-authorised object whose rights require activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationSubject {
    /// Rights contributed through this structurally containing group.
    Group(GroupId),
    /// Rights contributed by this individual permission grant.
    Grant(GrantId),
    /// Rights contributed by one recipient-local federation grant assignment.
    FederationAssignment(FederationAssignmentId),
}

/// Absolute interval during which a source or policy permits activation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccessWindow {
    /// Inclusive first permitted instant, or no lower bound.
    pub valid_from: Option<UnixMicros>,
    /// Exclusive last permitted instant, or no upper bound.
    pub valid_until: Option<UnixMicros>,
}

impl AccessWindow {
    fn permits(self, now: UnixMicros) -> bool {
        self.valid_from.is_none_or(|start| now >= start)
            && self.valid_until.is_none_or(|end| now < end)
    }
}

/// Pre-authorised limits applied when a user activates access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessActivationPolicy {
    maximum_duration: DurationMicros,
    reason_required: bool,
    minimum_assurance: AssuranceLevel,
    window: AccessWindow,
}

impl AccessActivationPolicy {
    /// Constructs an activation policy.
    ///
    /// # Errors
    ///
    /// Returns [`AccessActivationError::InvalidPolicy`] for a zero or unrepresentable duration or
    /// a reversed absolute window.
    pub fn new(
        maximum_duration: DurationMicros,
        reason_required: bool,
        minimum_assurance: AssuranceLevel,
        window: AccessWindow,
    ) -> Result<Self, AccessActivationError> {
        let duration_is_valid =
            maximum_duration.get() > 0 && i64::try_from(maximum_duration.get()).is_ok();
        let window_is_valid = match (window.valid_from, window.valid_until) {
            (Some(start), Some(end)) => start < end,
            _ => true,
        };
        if !duration_is_valid || !window_is_valid {
            return Err(AccessActivationError::InvalidPolicy);
        }
        Ok(Self {
            maximum_duration,
            reason_required,
            minimum_assurance,
            window,
        })
    }

    /// Evaluates one self-service activation request without consulting ambient time.
    ///
    /// # Errors
    ///
    /// Returns a specific rejection when the request exceeds its pre-authorised bounds.
    pub fn activate(
        self,
        request: AccessActivationRequest<'_>,
    ) -> Result<AccessActivation, AccessActivationError> {
        validate_activation_request(self, &request)?;
        let requested_expiry = request
            .now
            .checked_add(request.duration)
            .ok_or(AccessActivationError::TimeOverflow)?;
        let expires_at = [
            Some(requested_expiry),
            Some(request.session_expires_at),
            request.source_window.valid_until,
            self.window.valid_until,
        ]
        .into_iter()
        .flatten()
        .min()
        .ok_or(AccessActivationError::TimeOverflow)?;
        if expires_at <= request.now {
            return Err(AccessActivationError::NoUsableDuration);
        }
        Ok(AccessActivation {
            operation_id: request.operation_id,
            principal_id: request.principal_id,
            subject: request.subject,
            identity_revision: request.identity_revision,
            source_revision: request.source_revision,
            policy_revision: request.policy_revision,
            reason: request.reason.to_owned(),
            activated_at: request.now,
            expires_at,
        })
    }
}

/// Complete inputs for one deterministic activation decision.
#[derive(Clone, Copy, Debug)]
pub struct AccessActivationRequest<'a> {
    /// Idempotency identity of the activation mutation.
    pub operation_id: OperationId,
    /// User receiving the temporarily active rights.
    pub principal_id: PrincipalId,
    /// Exact group or grant being activated.
    pub subject: ActivationSubject,
    /// Whether current authoritative state assigns the source to this user.
    pub source_is_authorized: bool,
    /// Identity/group revision used to prove structural membership.
    pub identity_revision: Revision,
    /// Revision of the exact source group or grant.
    pub source_revision: Revision,
    /// Revision of the activation policy.
    pub policy_revision: Revision,
    /// User-supplied audit reason.
    pub reason: &'a str,
    /// Requested active duration.
    pub duration: DurationMicros,
    /// Authoritative decision instant.
    pub now: UnixMicros,
    /// Current session expiry.
    pub session_expires_at: UnixMicros,
    /// Assurance proved by the current session.
    pub assurance: AssuranceLevel,
    /// Absolute validity of the source group or grant.
    pub source_window: AccessWindow,
}

/// Durable accepted access activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessActivation {
    operation_id: OperationId,
    principal_id: PrincipalId,
    subject: ActivationSubject,
    identity_revision: Revision,
    source_revision: Revision,
    policy_revision: Revision,
    reason: String,
    activated_at: UnixMicros,
    expires_at: UnixMicros,
}

impl AccessActivation {
    /// Returns the mutation identity for replay and audit correlation.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// Returns the user receiving the active rights.
    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.principal_id
    }

    /// Returns the exact activated group or grant.
    #[must_use]
    pub const fn subject(&self) -> ActivationSubject {
        self.subject
    }

    /// Returns the identity revision used to prove structural membership.
    #[must_use]
    pub const fn identity_revision(&self) -> Revision {
        self.identity_revision
    }

    /// Returns the exact source group or grant revision.
    #[must_use]
    pub const fn source_revision(&self) -> Revision {
        self.source_revision
    }

    /// Returns the activation-policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> Revision {
        self.policy_revision
    }

    /// Returns the bounded audit reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns the authoritative activation instant.
    #[must_use]
    pub const fn activated_at(&self) -> UnixMicros {
        self.activated_at
    }

    /// Returns the exclusive expiry after all source limits are applied.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMicros {
        self.expires_at
    }
}

/// Specific rejection of an activation request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AccessActivationError {
    /// Policy duration or absolute window is invalid.
    #[error("activation policy is invalid")]
    InvalidPolicy,
    /// The requested duration is zero or exceeds the policy maximum.
    #[error("requested activation duration is outside policy bounds")]
    DurationOutsidePolicy,
    /// A required reason is blank, contains control characters or is too large.
    #[error("activation reason is invalid")]
    InvalidReason,
    /// The session has not reached the policy's minimum assurance.
    #[error("activation requires stronger authentication assurance")]
    InsufficientAssurance,
    /// Current authoritative state does not assign the source to this user.
    #[error("activation source is not assigned to this user")]
    SourceUnauthorized,
    /// The policy, source or session is not currently active.
    #[error("activation source is not currently valid")]
    SourceInactive,
    /// Adding the requested duration would exceed the instant representation.
    #[error("activation expiry is outside the supported time range")]
    TimeOverflow,
    /// Intersecting all limits leaves no positive activation interval.
    #[error("activation has no usable duration")]
    NoUsableDuration,
}

fn validate_activation_request(
    policy: AccessActivationPolicy,
    request: &AccessActivationRequest<'_>,
) -> Result<(), AccessActivationError> {
    if request.duration.get() == 0 || request.duration > policy.maximum_duration {
        return Err(AccessActivationError::DurationOutsidePolicy);
    }
    let reason_is_valid = request.reason.len() <= MAX_ACTIVATION_REASON_BYTES
        && !request.reason.chars().any(char::is_control)
        && (!policy.reason_required || !request.reason.trim().is_empty());
    if !reason_is_valid {
        return Err(AccessActivationError::InvalidReason);
    }
    if request.assurance < policy.minimum_assurance {
        return Err(AccessActivationError::InsufficientAssurance);
    }
    if !request.source_is_authorized {
        return Err(AccessActivationError::SourceUnauthorized);
    }
    if !policy.window.permits(request.now)
        || !request.source_window.permits(request.now)
        || request.session_expires_at <= request.now
    {
        return Err(AccessActivationError::SourceInactive);
    }
    Ok(())
}

/// Outcome of applying one structural group-membership command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipChange {
    /// A new edge was added.
    Added,
    /// The requested edge already existed and no state changed.
    AlreadyPresent,
    /// An existing edge was removed.
    Removed,
    /// The requested edge did not exist and no state changed.
    AlreadyAbsent,
}

/// Bounded in-memory oracle for nested group semantics.
#[derive(Clone, Debug, Default)]
pub struct GroupGraph {
    groups: BTreeSet<GroupId>,
    members: BTreeMap<GroupId, BTreeSet<PrincipalId>>,
    membership_count: usize,
}

impl GroupGraph {
    /// Registers a group identity before membership edges reference it.
    ///
    /// # Errors
    ///
    /// Returns [`GroupGraphError::CapacityExceeded`] at the proof-harness bound.
    pub fn register_group(&mut self, group_id: GroupId) -> Result<bool, GroupGraphError> {
        if !self.groups.contains(&group_id) && self.groups.len() == MAX_GROUPS {
            return Err(GroupGraphError::CapacityExceeded);
        }
        Ok(self.groups.insert(group_id))
    }

    /// Adds a direct user or group member while rejecting every cycle.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown containing group, self-membership, a transitive cycle or a
    /// graph beyond the explicit proof bound.
    pub fn add_member(
        &mut self,
        containing_group: GroupId,
        member: PrincipalId,
    ) -> Result<MembershipChange, GroupGraphError> {
        self.require_group(containing_group)?;
        if containing_group.principal_id() == member {
            return Err(GroupGraphError::Cycle);
        }
        if self
            .members
            .get(&containing_group)
            .is_some_and(|members| members.contains(&member))
        {
            return Ok(MembershipChange::AlreadyPresent);
        }
        if self.membership_count == MAX_MEMBERSHIPS {
            return Err(GroupGraphError::CapacityExceeded);
        }
        if let Some(member_group) = self.group_for_principal(member)
            && self.reaches_group(member_group, containing_group)
        {
            return Err(GroupGraphError::Cycle);
        }
        self.members
            .entry(containing_group)
            .or_default()
            .insert(member);
        self.membership_count += 1;
        Ok(MembershipChange::Added)
    }

    /// Removes one direct membership edge without disturbing independent paths.
    ///
    /// # Errors
    ///
    /// Returns [`GroupGraphError::UnknownGroup`] when the containing group is unregistered.
    pub fn remove_member(
        &mut self,
        containing_group: GroupId,
        member: PrincipalId,
    ) -> Result<MembershipChange, GroupGraphError> {
        self.require_group(containing_group)?;
        let removed = self
            .members
            .get_mut(&containing_group)
            .is_some_and(|members| members.remove(&member));
        if removed {
            self.membership_count -= 1;
            Ok(MembershipChange::Removed)
        } else {
            Ok(MembershipChange::AlreadyAbsent)
        }
    }

    /// Returns every direct and transitive containing group in stable order.
    #[must_use]
    pub fn containing_groups(&self, principal: PrincipalId) -> BTreeSet<GroupId> {
        let mut result = BTreeSet::new();
        let mut frontier = vec![principal];
        while let Some(member) = frontier.pop() {
            for group in &self.groups {
                let contains = self
                    .members
                    .get(group)
                    .is_some_and(|members| members.contains(&member));
                if contains && result.insert(*group) {
                    frontier.push(group.principal_id());
                }
            }
        }
        result
    }

    fn require_group(&self, group_id: GroupId) -> Result<(), GroupGraphError> {
        if self.groups.contains(&group_id) {
            Ok(())
        } else {
            Err(GroupGraphError::UnknownGroup)
        }
    }

    fn group_for_principal(&self, principal: PrincipalId) -> Option<GroupId> {
        self.groups
            .iter()
            .copied()
            .find(|group| group.principal_id() == principal)
    }

    fn reaches_group(&self, start: GroupId, target: GroupId) -> bool {
        let mut visited = BTreeSet::new();
        let mut frontier = vec![start];
        while let Some(group) = frontier.pop() {
            if group == target {
                return true;
            }
            if !visited.insert(group) {
                continue;
            }
            let child_groups = self
                .members
                .get(&group)
                .into_iter()
                .flatten()
                .filter_map(|principal| self.group_for_principal(*principal));
            frontier.extend(child_groups);
        }
        false
    }
}

/// Rejection of a hostile or invalid group-graph mutation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GroupGraphError {
    /// The containing group was not registered.
    #[error("containing group is unknown")]
    UnknownGroup,
    /// The requested edge creates direct or transitive self-membership.
    #[error("group membership would create a cycle")]
    Cycle,
    /// The deterministic proof-harness bound was reached.
    #[error("group graph exceeds its bounded capacity")]
    CapacityExceeded,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "fixed non-nil identifiers and policies are test fixtures"
    )]

    use super::{
        AccessActivationError, AccessActivationPolicy, AccessActivationRequest, AccessWindow,
        ActivationSubject, AssuranceLevel, GroupGraph, GroupGraphError, MembershipChange, OwnerSet,
        OwnerSetError, Rights, RightsError,
    };
    use crate::{DurationMicros, GrantId, GroupId, OperationId, PrincipalId, Revision, UnixMicros};

    fn group(value: u8) -> GroupId {
        GroupId::from_bytes([value; 16]).expect("fixture group ID is non-nil")
    }

    fn principal(value: u8) -> PrincipalId {
        PrincipalId::from_bytes([value; 16]).expect("fixture principal ID is non-nil")
    }

    #[test]
    fn nested_groups_reject_cycles_and_preserve_diamond_paths() {
        let mut graph = GroupGraph::default();
        for id in [group(1), group(2), group(3)] {
            assert_eq!(graph.register_group(id), Ok(true));
        }
        assert_eq!(
            graph.add_member(group(1), group(2).principal_id()),
            Ok(MembershipChange::Added)
        );
        assert_eq!(
            graph.add_member(group(1), group(3).principal_id()),
            Ok(MembershipChange::Added)
        );
        assert_eq!(
            graph.add_member(group(2), principal(9)),
            Ok(MembershipChange::Added)
        );
        assert_eq!(
            graph.add_member(group(3), principal(9)),
            Ok(MembershipChange::Added)
        );
        assert_eq!(
            graph.add_member(group(2), group(1).principal_id()),
            Err(GroupGraphError::Cycle)
        );

        assert_eq!(
            graph.remove_member(group(2), principal(9)),
            Ok(MembershipChange::Removed)
        );
        assert_eq!(
            graph.containing_groups(principal(9)),
            BTreeSet::from([group(1), group(3)])
        );
    }

    #[test]
    fn activation_intersects_request_session_source_and_policy_limits() {
        let policy = AccessActivationPolicy::new(
            DurationMicros::new(60),
            true,
            AssuranceLevel::RecentStepUp,
            AccessWindow::default(),
        )
        .expect("fixture policy is valid");
        let activation = policy
            .activate(AccessActivationRequest {
                operation_id: OperationId::from_bytes([1; 16]).expect("fixture ID is non-nil"),
                principal_id: principal(2),
                subject: ActivationSubject::Grant(
                    GrantId::from_bytes([3; 16]).expect("fixture ID is non-nil"),
                ),
                source_is_authorized: true,
                identity_revision: Revision::new(11),
                source_revision: Revision::new(12),
                policy_revision: Revision::new(13),
                reason: "restore damaged accounts",
                duration: DurationMicros::new(50),
                now: UnixMicros::new(100),
                session_expires_at: UnixMicros::new(130),
                assurance: AssuranceLevel::RecentStepUp,
                source_window: AccessWindow {
                    valid_from: Some(UnixMicros::new(90)),
                    valid_until: Some(UnixMicros::new(140)),
                },
            })
            .expect("fixture request is authorised");

        assert_eq!(activation.activated_at(), UnixMicros::new(100));
        assert_eq!(activation.expires_at(), UnixMicros::new(130));
        assert_eq!(activation.reason(), "restore damaged accounts");
        assert_eq!(activation.identity_revision(), Revision::new(11));
    }

    #[test]
    fn activation_rejects_missing_reason_duration_assurance_and_schedule() {
        let policy = AccessActivationPolicy::new(
            DurationMicros::new(60),
            true,
            AssuranceLevel::MultiFactor,
            AccessWindow::default(),
        )
        .expect("fixture policy is valid");
        let base = AccessActivationRequest {
            operation_id: OperationId::from_bytes([1; 16]).expect("fixture ID is non-nil"),
            principal_id: principal(2),
            subject: ActivationSubject::Group(group(3)),
            source_is_authorized: true,
            identity_revision: Revision::new(11),
            source_revision: Revision::new(12),
            policy_revision: Revision::new(13),
            reason: "needed",
            duration: DurationMicros::new(10),
            now: UnixMicros::new(100),
            session_expires_at: UnixMicros::new(200),
            assurance: AssuranceLevel::MultiFactor,
            source_window: AccessWindow::default(),
        };

        assert_eq!(
            policy.activate(AccessActivationRequest {
                reason: " ",
                ..base
            }),
            Err(AccessActivationError::InvalidReason)
        );
        assert_eq!(
            policy.activate(AccessActivationRequest {
                duration: DurationMicros::new(61),
                ..base
            }),
            Err(AccessActivationError::DurationOutsidePolicy)
        );
        assert_eq!(
            policy.activate(AccessActivationRequest {
                assurance: AssuranceLevel::SingleFactor,
                ..base
            }),
            Err(AccessActivationError::InsufficientAssurance)
        );
        assert_eq!(
            policy.activate(AccessActivationRequest {
                session_expires_at: UnixMicros::new(100),
                ..base
            }),
            Err(AccessActivationError::SourceInactive)
        );
        assert_eq!(
            policy.activate(AccessActivationRequest {
                source_is_authorized: false,
                ..base
            }),
            Err(AccessActivationError::SourceUnauthorized)
        );
    }

    #[test]
    fn owner_replacement_is_atomic_nonempty_and_revision_guarded() {
        let owners = OwnerSet::new(
            BTreeSet::from([principal(1), principal(2)]),
            Revision::new(4),
        )
        .expect("fixture owner set is valid");
        assert_eq!(
            owners.replace(Revision::new(3), BTreeSet::from([principal(3)])),
            Err(OwnerSetError::StaleRevision)
        );
        assert_eq!(
            owners.replace(Revision::new(4), BTreeSet::new()),
            Err(OwnerSetError::Ownerless)
        );
        let replaced = owners
            .replace(Revision::new(4), BTreeSet::from([principal(3)]))
            .expect("replacement retains one owner");
        assert_eq!(replaced.owners(), &BTreeSet::from([principal(3)]));
        assert_eq!(replaced.revision(), Revision::new(5));
    }

    #[test]
    fn rights_reject_unknown_bits_and_combine_allow_grants() {
        let rights = Rights::READ_DATA.union(Rights::WRITE_DATA);
        assert!(rights.contains(Rights::READ_DATA));
        assert!(!rights.contains(Rights::DELETE));
        assert_eq!(Rights::from_bits(rights.bits()), Ok(rights));
        assert_eq!(Rights::from_bits(1 << 31), Err(RightsError::UnknownBits));
    }

    use std::collections::BTreeSet;
}
