// SPDX-License-Identifier: GPL-2.0-only

//! Small value types shared by domain operations.

use std::fmt;

use thiserror::Error;

/// Failure returned while constructing an identifier from hostile input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IdentifierError {
    /// The textual representation was not exactly 32 hexadecimal characters.
    #[error("identifier must contain exactly 32 hexadecimal characters")]
    InvalidLength,
    /// At least one textual character was not lowercase hexadecimal.
    #[error("identifier must use lowercase hexadecimal characters")]
    InvalidCharacter,
    /// The all-zero identifier is reserved and cannot identify an entity.
    #[error("identifier must not be all zeroes")]
    Nil,
}

fn parse_identifier(value: &str) -> Result<[u8; 16], IdentifierError> {
    if value.len() != 32 {
        return Err(IdentifierError::InvalidLength);
    }
    let mut bytes = [0_u8; 16];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = decode_hex(pair[0]).ok_or(IdentifierError::InvalidCharacter)?;
        let low = decode_hex(pair[1]).ok_or(IdentifierError::InvalidCharacter)?;
        bytes[index] = (high << 4) | low;
    }
    validate_identifier(bytes)
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn validate_identifier(bytes: [u8; 16]) -> Result<[u8; 16], IdentifierError> {
    if bytes == [0; 16] {
        return Err(IdentifierError::Nil);
    }
    Ok(bytes)
}

macro_rules! define_identifier {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Constructs the identifier from its canonical 16 bytes.
            ///
            /// # Errors
            ///
            /// Returns [`IdentifierError::Nil`] for the reserved all-zero value.
            pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, IdentifierError> {
                validate_identifier(bytes).map(Self)
            }

            /// Parses the canonical lowercase 32-character hexadecimal representation.
            ///
            /// # Errors
            ///
            /// Returns an error for the wrong length, non-lowercase-hex input or the nil value.
            pub fn parse(value: &str) -> Result<Self, IdentifierError> {
                parse_identifier(value).map(Self)
            }

            /// Returns the canonical bytes.
            #[must_use]
            pub const fn as_bytes(self) -> [u8; 16] {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

define_identifier!(MeshId, "Stable identity of one `MeshSpan` mesh.");
define_identifier!(
    FederationRelationshipId,
    "Stable identity of one mutually approved federation relationship."
);
define_identifier!(
    FederationGrantId,
    "Stable identity of one scoped federation grant."
);
define_identifier!(
    FederationStorageAllocationId,
    "Stable identity of one disjoint provider-node federation storage allocation."
);
define_identifier!(
    FederationSuccessionId,
    "Stable identity of one pre-authorised federation ownership succession."
);
define_identifier!(
    QuarantineId,
    "Stable identity of one quarantined federated mutation."
);
define_identifier!(NodeId, "Stable identity of one daemon node.");
define_identifier!(HostId, "Stable identity of one physical or virtual host.");
define_identifier!(
    TargetId,
    "Stable identity of one registered storage target."
);
define_identifier!(PartitionId, "Stable identity of one metadata partition.");
define_identifier!(ScopeId, "Stable identity of one routed metadata scope.");
define_identifier!(
    PrincipalId,
    "Stable identity of one user or group principal."
);
define_identifier!(GroupId, "Stable identity of one group principal.");
define_identifier!(VolumeId, "Stable identity of one volume.");
define_identifier!(ObjectId, "Stable identity of one namespace object.");
define_identifier!(
    BranchId,
    "Stable identity of one writable namespace branch."
);
define_identifier!(
    NamespaceCommitId,
    "Stable identity of one immutable namespace commit."
);
define_identifier!(
    ObjectRevisionId,
    "Stable identity of one immutable namespace-object revision."
);
define_identifier!(
    FileVersionId,
    "Stable identity of one immutable regular-file version."
);
define_identifier!(
    ContentManifestId,
    "Stable identity of one immutable content manifest root."
);
define_identifier!(StageId, "Stable identity of one private write stage.");
define_identifier!(HandleId, "Stable identity of one fenced filesystem handle.");
define_identifier!(LockId, "Stable identity of one fenced byte-range lock.");
define_identifier!(GrantId, "Stable identity of one permission grant.");
define_identifier!(
    AuthenticationMethodId,
    "Stable identity of one user authentication method."
);
define_identifier!(ApiKeyId, "Stable public identity of one API key.");
define_identifier!(
    RecoveryCodeId,
    "Stable public identity of one single-use recovery code."
);
define_identifier!(SessionId, "Stable identity of one authentication session.");
define_identifier!(
    ActivationPolicyId,
    "Stable identity of one access-activation policy."
);
define_identifier!(
    ActivationId,
    "Stable identity of one accepted access activation."
);
define_identifier!(OwnerSetId, "Stable identity of one immutable owner set.");
define_identifier!(
    ComponentInstanceId,
    "Stable identity of one configured component instance."
);
define_identifier!(AuditEventId, "Stable identity of one audit event.");
define_identifier!(TagId, "Stable identity of one descriptive tag.");
define_identifier!(BackupId, "Stable identity of one metadata backup.");
define_identifier!(SnapshotId, "Stable identity of one immutable snapshot.");
define_identifier!(ClaimId, "Stable identity of one node-local claim bundle.");
define_identifier!(
    SnapshotScheduleId,
    "Stable identity of one volume snapshot schedule."
);
define_identifier!(
    JoinGrantId,
    "Stable identity of one administrator-issued node join grant."
);
define_identifier!(RoleId, "Stable identity of one system-administration role.");
define_identifier!(
    QuorumPlanId,
    "Stable identity of one immutable quorum plan."
);
define_identifier!(
    OperationId,
    "Stable idempotency identity of one logical mutation."
);
define_identifier!(FaultGroupId, "Stable identity of one fault group.");
define_identifier!(
    FaultGroupClassId,
    "Stable identity of one fault-group classification."
);

impl GroupId {
    /// Returns the principal identity represented by this group.
    #[must_use]
    pub const fn principal_id(self) -> PrincipalId {
        PrincipalId(self.0)
    }
}

/// Authoritative UTC instant represented as epoch microseconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnixMicros(i64);

impl UnixMicros {
    /// Constructs an instant from its exact epoch-microsecond value.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Returns the exact epoch-microsecond value.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Adds a non-negative duration without wrapping.
    #[must_use]
    pub fn checked_add(self, duration: DurationMicros) -> Option<Self> {
        let duration = i64::try_from(duration.get()).ok()?;
        self.0.checked_add(duration).map(Self)
    }
}

/// Non-negative duration represented as microseconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DurationMicros(u64);

impl DurationMicros {
    /// Constructs a duration from an exact number of microseconds.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the exact number of microseconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Monotonic revision within one named authority.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Revision(u64);

impl Revision {
    /// The first revision before any mutation is applied.
    pub const ZERO: Self = Self(0);

    /// Constructs a revision from its stored value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the stored revision value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances by exactly one revision without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionError::Exhausted`] at `u64::MAX`.
    pub fn next(self) -> Result<Self, RevisionError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(RevisionError::Exhausted)
    }
}

/// Failure to advance a monotonic revision.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RevisionError {
    /// The revision number space has been exhausted.
    #[error("revision space is exhausted")]
    Exhausted,
}

#[cfg(test)]
mod tests {
    use super::{IdentifierError, NodeId, Revision, RevisionError};

    #[test]
    fn identifiers_reject_noncanonical_and_nil_values() {
        assert_eq!(NodeId::parse("01"), Err(IdentifierError::InvalidLength));
        assert_eq!(
            NodeId::parse(&"A".repeat(32)),
            Err(IdentifierError::InvalidCharacter)
        );
        assert_eq!(NodeId::parse(&"0".repeat(32)), Err(IdentifierError::Nil));
    }

    #[test]
    fn identifier_round_trips_canonical_text() {
        let value = "018f1d207b4c7a1e9d2239a1558b4c61";
        assert_eq!(
            NodeId::parse(value).map(|identifier| identifier.to_string()),
            Ok(value.to_owned())
        );
    }

    #[test]
    fn revision_never_wraps() {
        assert_eq!(Revision::ZERO.next(), Ok(Revision::new(1)));
        assert_eq!(
            Revision::new(u64::MAX).next(),
            Err(RevisionError::Exhausted)
        );
    }
}
