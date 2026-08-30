// SPDX-License-Identifier: GPL-2.0-only

//! Typed grant issuance, immutable succession and explicit revocation commands.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    FederationGrant, FederationGrantId, FederationPolicy, FederationResourceScope, MeshId,
};

use crate::command::CanonicalDigest;

/// One swarm's independent upper bound contributing to effective grant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationGrantRestriction {
    /// Swarm imposing this non-broadenable restriction.
    pub imposing_mesh_id: MeshId,
    /// Typed namespace or storage ceiling.
    pub policy: FederationPolicy,
}

/// Issues one exact grant after intersecting every independent restriction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueFederationGrant {
    /// Fully constructed effective authority envelope.
    pub grant: FederationGrant,
    /// Unique restrictions, including one from each relationship side.
    pub restrictions: BoundedItems<FederationGrantRestriction>,
}

/// Replaces one immutable grant for renewal or a policy restriction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaceFederationGrant {
    /// Exact current grant being replaced.
    pub predecessor_grant_id: FederationGrantId,
    /// New immutable effective authority envelope.
    pub grant: FederationGrant,
    /// Complete new independent restriction set.
    pub restrictions: BoundedItems<FederationGrantRestriction>,
    /// `false` for renewal, `true` for an explicit narrowing.
    pub restricts_authority: bool,
    /// Bounded audit explanation.
    pub reason: String,
}

/// Revokes one exact live grant without deleting its authority evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeFederationGrant {
    /// Live grant being revoked.
    pub grant_id: FederationGrantId,
    /// Expected exact authority epoch.
    pub expected_authority_epoch: u64,
    /// Bounded audit explanation.
    pub reason: String,
}

impl IssueFederationGrant {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"issue-federation-grant");
        digest_grant(digest, &self.grant);
        digest_restrictions(digest, &self.restrictions);
    }
}

impl ReplaceFederationGrant {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"replace-federation-grant");
        digest.identifier(self.predecessor_grant_id.as_bytes());
        digest_grant(digest, &self.grant);
        digest_restrictions(digest, &self.restrictions);
        digest.boolean(self.restricts_authority);
        digest.bytes(self.reason.as_bytes());
    }
}

impl RevokeFederationGrant {
    pub(crate) fn update_digest(&self, digest: &mut CanonicalDigest) {
        digest.bytes(b"revoke-federation-grant");
        digest.identifier(self.grant_id.as_bytes());
        digest.unsigned(self.expected_authority_epoch);
        digest.bytes(self.reason.as_bytes());
    }
}

fn digest_restrictions(
    digest: &mut CanonicalDigest,
    restrictions: &BoundedItems<FederationGrantRestriction>,
) {
    digest.unsigned(u64::try_from(restrictions.len()).unwrap_or(u64::MAX));
    for restriction in restrictions.as_slice() {
        digest.identifier(restriction.imposing_mesh_id.as_bytes());
        digest_policy(digest, restriction.policy);
    }
}

pub(crate) fn policy_digest(policy: FederationPolicy) -> [u8; 32] {
    let mut digest = CanonicalDigest::new(b"meshspan.federation.policy.v1");
    digest_policy(&mut digest, policy);
    digest.finish()
}

fn digest_grant(digest: &mut CanonicalDigest, grant: &FederationGrant) {
    digest.identifier(grant.grant_id().as_bytes());
    digest.identifier(grant.relationship_id().as_bytes());
    digest.unsigned(u64::try_from(grant.route().meshes().len()).unwrap_or(u64::MAX));
    for mesh_id in grant.route().meshes() {
        digest.identifier(mesh_id.as_bytes());
    }
    digest.optional_identifier(grant.upstream_grant_id().map(FederationGrantId::as_bytes));
    digest_resource(digest, grant.resource());
    digest_policy(digest, grant.policy());
    digest.unsigned(grant.authority_epoch());
    digest.signed(grant.valid_from().get());
    digest.optional_instant(grant.valid_until());
}

pub(crate) fn digest_resource(digest: &mut CanonicalDigest, resource: FederationResourceScope) {
    match resource {
        FederationResourceScope::Volume {
            owner_mesh_id,
            volume_id,
        } => {
            digest.byte(1);
            digest.identifier(owner_mesh_id.as_bytes());
            digest.identifier(volume_id.as_bytes());
        }
        FederationResourceScope::Subtree {
            owner_mesh_id,
            volume_id,
            root_object_id,
        } => {
            digest.byte(2);
            digest.identifier(owner_mesh_id.as_bytes());
            digest.identifier(volume_id.as_bytes());
            digest.identifier(root_object_id.as_bytes());
        }
        FederationResourceScope::File {
            owner_mesh_id,
            volume_id,
            object_id,
        } => {
            digest.byte(3);
            digest.identifier(owner_mesh_id.as_bytes());
            digest.identifier(volume_id.as_bytes());
            digest.identifier(object_id.as_bytes());
        }
        FederationResourceScope::StorageCapacity { provider_mesh_id } => {
            digest.byte(4);
            digest.identifier(provider_mesh_id.as_bytes());
        }
    }
}

pub(crate) fn digest_policy(digest: &mut CanonicalDigest, policy: FederationPolicy) {
    match policy {
        FederationPolicy::Namespace(policy) => {
            digest.byte(1);
            digest.unsigned(u64::from(policy.access().rights().bits()));
            digest.boolean(policy.access().allows_downstream_delegation());
            digest.optional_unsigned(
                policy
                    .maximum_offline_duration()
                    .map(meshspan_domain::DurationMicros::get),
            );
        }
        FederationPolicy::Storage(policy) => {
            digest.byte(2);
            digest.unsigned(policy.maximum_storage_bytes());
            digest.boolean(policy.participation().counts_towards_protection());
            digest.boolean(policy.participation().serves_reads());
            digest.boolean(policy.allows_downstream_delegation());
            digest.optional_unsigned(
                policy
                    .maximum_offline_duration()
                    .map(meshspan_domain::DurationMicros::get),
            );
        }
    }
}
