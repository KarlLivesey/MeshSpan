// SPDX-License-Identifier: GPL-2.0-only

//! Typed authoritative state-machine commands and canonical request digests.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationId, ActivationPolicyId, AssuranceLevel, AuditEventId, ComponentInstanceId,
    DurationMicros, GrantId, GroupId, HostId, MeshId, NodeId, ObjectId, OperationId, OwnerSetId,
    PrincipalId, Revision, Rights, RoleId, UnixMicros, VolumeId,
};
use sha2::{Digest, Sha256};

use crate::RecordName;

/// Context applied identically to every state-machine command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandContext {
    /// Idempotency identity of the logical mutation.
    pub operation_id: OperationId,
    /// Authenticated principal responsible for the command.
    pub actor_principal_id: PrincipalId,
    /// Stable audit-event identity allocated before consensus.
    pub audit_event_id: AuditEventId,
    /// Authoritative instant supplied by the leader and recorded in the log.
    pub occurred_at: UnixMicros,
    /// Optional compare-and-swap state revision.
    pub expected_revision: Option<Revision>,
}

/// Closed authoritative command families implemented by the Stage 2 kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthoritativeCommand {
    /// Creates the first mesh, administrator, host, node and partition records.
    BootstrapMesh(BootstrapMesh),
    /// Creates one user principal.
    CreateUser(CreateUser),
    /// Creates one group principal.
    CreateGroup(CreateGroup),
    /// Adds one direct user/group membership and rebuilds exact closure rows.
    AddGroupMember(AddGroupMember),
    /// Creates a bounded self-service activation policy.
    CreateActivationPolicy(CreateActivationPolicy),
    /// Creates a volume root with one non-empty multi-principal owner set.
    CreateVolume(CreateVolume),
    /// Creates one folder or file record beneath an existing folder.
    CreateObject(CreateObject),
    /// Creates an allow-only global, volume or object permission grant.
    GrantPermission(GrantPermission),
    /// Activates one pre-authorised grant for the requesting user.
    ActivateGrant(ActivateGrant),
    /// Activates one pre-authorised group for the requesting user.
    ActivateGroup(ActivateGroup),
    /// Creates a versioned desired component configuration.
    CreateComponent(CreateComponent),
}

impl AuthoritativeCommand {
    /// Returns a deterministic digest over the complete semantic command and context.
    #[must_use]
    pub fn request_digest(&self, context: CommandContext) -> [u8; 32] {
        let mut digest = CanonicalDigest::new(b"meshspan.metadata.command.v1");
        digest.identifier(context.operation_id.as_bytes());
        digest.identifier(context.actor_principal_id.as_bytes());
        digest.identifier(context.audit_event_id.as_bytes());
        digest.signed(context.occurred_at.get());
        digest.optional_revision(context.expected_revision);
        self.update_digest(&mut digest);
        digest.finish()
    }

    fn update_digest(&self, digest: &mut CanonicalDigest) {
        match self {
            Self::BootstrapMesh(value) => value.update_digest(digest),
            Self::CreateUser(value) => value.update_digest(digest),
            Self::CreateGroup(value) => value.update_digest(digest),
            Self::AddGroupMember(value) => value.update_digest(digest),
            Self::CreateActivationPolicy(value) => value.update_digest(digest),
            Self::CreateVolume(value) => value.update_digest(digest),
            Self::CreateObject(value) => value.update_digest(digest),
            Self::GrantPermission(value) => value.update_digest(digest),
            Self::ActivateGrant(value) => value.update_digest(digest),
            Self::ActivateGroup(value) => value.update_digest(digest),
            Self::CreateComponent(value) => value.update_digest(digest),
        }
    }
}

/// Initial one-node mesh records committed atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapMesh {
    /// Mesh identity.
    pub mesh_id: MeshId,
    /// Mesh display/canonical name.
    pub mesh_name: RecordName,
    /// First administrator user principal.
    pub administrator_id: PrincipalId,
    /// Administrator display/canonical name.
    pub administrator_name: RecordName,
    /// Built-in system-administrator role identity.
    pub administrator_role_id: RoleId,
    /// First physical host.
    pub host_id: HostId,
    /// Host display/canonical name.
    pub host_name: RecordName,
    /// First daemon node.
    pub node_id: NodeId,
    /// Node display/canonical name.
    pub node_name: RecordName,
    /// Display/canonical name of the already identity-bound partition.
    pub partition_name: RecordName,
}

/// New user record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateUser {
    /// Principal identity.
    pub principal_id: PrincipalId,
    /// Display/canonical name.
    pub name: RecordName,
}

/// New group record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateGroup {
    /// Group/principal identity.
    pub group_id: GroupId,
    /// Display/canonical name.
    pub name: RecordName,
    /// Optional policy required before membership contributes rights.
    pub activation_policy_id: Option<ActivationPolicyId>,
}

/// One direct containing-group membership edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddGroupMember {
    /// Structurally containing group.
    pub containing_group_id: GroupId,
    /// User or group principal directly contained.
    pub member_principal_id: PrincipalId,
    /// Inclusive activation window start.
    pub valid_from: Option<UnixMicros>,
    /// Exclusive activation window end.
    pub valid_until: Option<UnixMicros>,
    /// Whether the user must explicitly activate this membership source.
    pub activation_required: bool,
}

/// Persisted self-service activation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateActivationPolicy {
    /// Stable policy identity.
    pub policy_id: ActivationPolicyId,
    /// Maximum active duration.
    pub maximum_duration: DurationMicros,
    /// Whether a non-blank reason is mandatory.
    pub reason_required: bool,
    /// Minimum current authentication assurance.
    pub minimum_assurance: AssuranceLevel,
    /// Inclusive absolute validity start.
    pub valid_from: Option<UnixMicros>,
    /// Exclusive absolute validity end.
    pub valid_until: Option<UnixMicros>,
}

/// New volume and root directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateVolume {
    /// Volume identity.
    pub volume_id: VolumeId,
    /// Volume display/canonical name.
    pub name: RecordName,
    /// Root directory identity.
    pub root_object_id: ObjectId,
    /// Immutable owner-set identity.
    pub owner_set_id: OwnerSetId,
    /// Non-empty user/group owner principals.
    pub owners: BoundedItems<PrincipalId>,
}

/// Namespace object kind stored as a closed integer contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceObjectKind {
    /// Directory that may contain child objects.
    Folder,
    /// Regular file metadata record.
    File,
}

/// New folder or file beneath an existing directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateObject {
    /// Object identity.
    pub object_id: ObjectId,
    /// Owning volume.
    pub volume_id: VolumeId,
    /// Existing parent folder.
    pub parent_object_id: ObjectId,
    /// File or folder.
    pub kind: NamespaceObjectKind,
    /// Display/canonical child name.
    pub name: RecordName,
    /// Immutable owner-set identity.
    pub owner_set_id: OwnerSetId,
    /// Non-empty user/group owner principals.
    pub owners: BoundedItems<PrincipalId>,
}

/// Permission scope with no ambiguous nullable combination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionScope {
    /// All present and future volumes/objects.
    Global,
    /// One volume and its objects.
    Volume(VolumeId),
    /// One exact object within its volume.
    Object {
        /// Containing volume.
        volume_id: VolumeId,
        /// Exact object.
        object_id: ObjectId,
    },
}

/// Allow-only inheritance behaviour.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantInheritance {
    /// Exact scoped object/volume only.
    Object,
    /// Descendants only.
    Descendants,
    /// Scoped object/volume and descendants.
    ObjectAndDescendants,
}

/// New allow-only permission grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantPermission {
    /// Grant identity.
    pub grant_id: GrantId,
    /// User or group receiving the rights.
    pub subject_principal_id: PrincipalId,
    /// Global, volume or object scope.
    pub scope: PermissionScope,
    /// Protocol-neutral non-empty rights.
    pub rights: Rights,
    /// Descendant behaviour.
    pub inheritance: GrantInheritance,
    /// Inclusive validity start.
    pub valid_from: Option<UnixMicros>,
    /// Exclusive validity end.
    pub valid_until: Option<UnixMicros>,
    /// Optional self-activation requirement.
    pub activation_policy_id: Option<ActivationPolicyId>,
}

/// One user's time-bounded activation of a pre-authorised grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateGrant {
    /// Activation record identity.
    pub activation_id: ActivationId,
    /// User receiving active rights.
    pub principal_id: PrincipalId,
    /// Exact grant being activated.
    pub grant_id: GrantId,
    /// Exact policy expected on the grant.
    pub policy_id: ActivationPolicyId,
    /// Audit reason supplied by the user.
    pub reason: String,
    /// Requested duration.
    pub duration: DurationMicros,
    /// Current session expiry.
    pub session_expires_at: UnixMicros,
    /// Current authentication assurance.
    pub assurance: AssuranceLevel,
    /// Digest binding the authentication ceremony/session.
    pub authentication_digest: [u8; 32],
}

/// One user's time-bounded activation of a pre-authorised group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivateGroup {
    /// Activation record identity.
    pub activation_id: ActivationId,
    /// User receiving active group-derived rights.
    pub principal_id: PrincipalId,
    /// Exact group being activated.
    pub group_id: GroupId,
    /// Exact policy expected on the group.
    pub policy_id: ActivationPolicyId,
    /// Bounded audit reason supplied by the user.
    pub reason: String,
    /// Requested duration.
    pub duration: DurationMicros,
    /// Current session expiry.
    pub session_expires_at: UnixMicros,
    /// Current authentication assurance.
    pub assurance: AssuranceLevel,
    /// Digest binding the authentication ceremony/session.
    pub authentication_digest: [u8; 32],
}

/// New desired component instance and its first configuration revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateComponent {
    /// Component instance identity.
    pub instance_id: ComponentInstanceId,
    /// Stable capability contract kind from `meshspan-contracts`.
    pub component_kind: u8,
    /// Display/canonical instance name.
    pub name: RecordName,
    /// Stable lowercase implementation identifier.
    pub implementation_id: String,
    /// Contract major version.
    pub contract_major: u16,
    /// Contract minor version.
    pub contract_minor: u16,
    /// Configuration schema version.
    pub schema_version: u32,
    /// Bounded canonical non-secret configuration.
    pub canonical_configuration: Vec<u8>,
    /// Digest of the canonical configuration.
    pub configuration_digest: [u8; 32],
}

macro_rules! digest_simple_record {
    ($type:ty, $tag:literal, |$value:ident, $digest:ident| $body:block) => {
        impl $type {
            fn update_digest(&self, digest: &mut CanonicalDigest) {
                let $value = self;
                let $digest = digest;
                $digest.bytes($tag);
                $body
            }
        }
    };
}

digest_simple_record!(BootstrapMesh, b"bootstrap", |value, digest| {
    digest.identifier(value.mesh_id.as_bytes());
    digest.name(&value.mesh_name);
    digest.identifier(value.administrator_id.as_bytes());
    digest.name(&value.administrator_name);
    digest.identifier(value.administrator_role_id.as_bytes());
    digest.identifier(value.host_id.as_bytes());
    digest.name(&value.host_name);
    digest.identifier(value.node_id.as_bytes());
    digest.name(&value.node_name);
    digest.name(&value.partition_name);
});
digest_simple_record!(CreateUser, b"create-user", |value, digest| {
    digest.identifier(value.principal_id.as_bytes());
    digest.name(&value.name);
});
digest_simple_record!(CreateGroup, b"create-group", |value, digest| {
    digest.identifier(value.group_id.as_bytes());
    digest.name(&value.name);
    digest.optional_identifier(value.activation_policy_id.map(ActivationPolicyId::as_bytes));
});
digest_simple_record!(AddGroupMember, b"add-group-member", |value, digest| {
    digest.identifier(value.containing_group_id.as_bytes());
    digest.identifier(value.member_principal_id.as_bytes());
    digest.optional_instant(value.valid_from);
    digest.optional_instant(value.valid_until);
    digest.boolean(value.activation_required);
});
digest_simple_record!(
    CreateActivationPolicy,
    b"activation-policy",
    |value, digest| {
        digest.identifier(value.policy_id.as_bytes());
        digest.unsigned(value.maximum_duration.get());
        digest.boolean(value.reason_required);
        digest.byte(assurance_code(value.minimum_assurance));
        digest.optional_instant(value.valid_from);
        digest.optional_instant(value.valid_until);
    }
);
digest_simple_record!(CreateVolume, b"create-volume", |value, digest| {
    digest.identifier(value.volume_id.as_bytes());
    digest.name(&value.name);
    digest.identifier(value.root_object_id.as_bytes());
    digest.identifier(value.owner_set_id.as_bytes());
    digest.principals(&value.owners);
});
digest_simple_record!(CreateObject, b"create-object", |value, digest| {
    digest.identifier(value.object_id.as_bytes());
    digest.identifier(value.volume_id.as_bytes());
    digest.identifier(value.parent_object_id.as_bytes());
    digest.byte(match value.kind {
        NamespaceObjectKind::Folder => 1,
        NamespaceObjectKind::File => 2,
    });
    digest.name(&value.name);
    digest.identifier(value.owner_set_id.as_bytes());
    digest.principals(&value.owners);
});
digest_simple_record!(GrantPermission, b"grant-permission", |value, digest| {
    digest.identifier(value.grant_id.as_bytes());
    digest.identifier(value.subject_principal_id.as_bytes());
    digest.permission_scope(value.scope);
    digest.unsigned(u64::from(value.rights.bits()));
    digest.byte(match value.inheritance {
        GrantInheritance::Object => 1,
        GrantInheritance::Descendants => 2,
        GrantInheritance::ObjectAndDescendants => 3,
    });
    digest.optional_instant(value.valid_from);
    digest.optional_instant(value.valid_until);
    digest.optional_identifier(value.activation_policy_id.map(ActivationPolicyId::as_bytes));
});
digest_simple_record!(ActivateGrant, b"activate-grant", |value, digest| {
    digest.identifier(value.activation_id.as_bytes());
    digest.identifier(value.principal_id.as_bytes());
    digest.identifier(value.grant_id.as_bytes());
    digest.identifier(value.policy_id.as_bytes());
    digest.bytes(value.reason.as_bytes());
    digest.unsigned(value.duration.get());
    digest.signed(value.session_expires_at.get());
    digest.byte(assurance_code(value.assurance));
    digest.bytes(&value.authentication_digest);
});
digest_simple_record!(ActivateGroup, b"activate-group", |value, digest| {
    digest.identifier(value.activation_id.as_bytes());
    digest.identifier(value.principal_id.as_bytes());
    digest.identifier(value.group_id.as_bytes());
    digest.identifier(value.policy_id.as_bytes());
    digest.bytes(value.reason.as_bytes());
    digest.unsigned(value.duration.get());
    digest.signed(value.session_expires_at.get());
    digest.byte(assurance_code(value.assurance));
    digest.bytes(&value.authentication_digest);
});
digest_simple_record!(CreateComponent, b"create-component", |value, digest| {
    digest.identifier(value.instance_id.as_bytes());
    digest.byte(value.component_kind);
    digest.name(&value.name);
    digest.bytes(value.implementation_id.as_bytes());
    digest.unsigned(u64::from(value.contract_major));
    digest.unsigned(u64::from(value.contract_minor));
    digest.unsigned(u64::from(value.schema_version));
    digest.bytes(&value.canonical_configuration);
    digest.bytes(&value.configuration_digest);
});

fn assurance_code(value: AssuranceLevel) -> u8 {
    match value {
        AssuranceLevel::SingleFactor => 1,
        AssuranceLevel::MultiFactor => 2,
        AssuranceLevel::RecentStepUp => 3,
    }
}

struct CanonicalDigest(Sha256);

impl CanonicalDigest {
    fn new(domain: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(domain);
        Self(digest)
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }

    fn byte(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn boolean(&mut self, value: bool) {
        self.byte(u8::from(value));
    }

    fn unsigned(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn signed(&mut self, value: i64) {
        self.0.update(value.to_be_bytes());
    }

    fn identifier(&mut self, value: [u8; 16]) {
        self.0.update(value);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.unsigned(u64::try_from(value.len()).unwrap_or(u64::MAX));
        self.0.update(value);
    }

    fn name(&mut self, value: &RecordName) {
        self.bytes(value.display().as_bytes());
        self.bytes(value.canonical().as_bytes());
    }

    fn optional_revision(&mut self, value: Option<Revision>) {
        self.optional_unsigned(value.map(Revision::get));
    }

    fn optional_instant(&mut self, value: Option<UnixMicros>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.signed(value.get());
            }
            None => self.byte(0),
        }
    }

    fn optional_identifier(&mut self, value: Option<[u8; 16]>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.identifier(value);
            }
            None => self.byte(0),
        }
    }

    fn optional_unsigned(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.byte(1);
                self.unsigned(value);
            }
            None => self.byte(0),
        }
    }

    fn principals(&mut self, values: &BoundedItems<PrincipalId>) {
        let mut identifiers: Vec<[u8; 16]> = values
            .as_slice()
            .iter()
            .map(|value| value.as_bytes())
            .collect();
        identifiers.sort_unstable();
        self.unsigned(u64::try_from(identifiers.len()).unwrap_or(u64::MAX));
        for identifier in identifiers {
            self.identifier(identifier);
        }
    }

    fn permission_scope(&mut self, scope: PermissionScope) {
        match scope {
            PermissionScope::Global => self.byte(1),
            PermissionScope::Volume(volume_id) => {
                self.byte(2);
                self.identifier(volume_id.as_bytes());
            }
            PermissionScope::Object {
                volume_id,
                object_id,
            } => {
                self.byte(3);
                self.identifier(volume_id.as_bytes());
                self.identifier(object_id.as_bytes());
            }
        }
    }
}
