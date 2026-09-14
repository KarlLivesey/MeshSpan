// SPDX-License-Identifier: GPL-2.0-only

//! Federation lifecycle commands must pass through real consensus, not direct SQL apply.

use super::{RunningAuthority, command_context};
use crate::ConsensusAuthenticationAuthority;
use meshspan_domain::{FederationRelationshipId, FederationRelationshipKind, MeshId, UnixMicros};
use meshspan_metadata::{
    ApproveFederationRelationship, AuthoritativeCommand, FederationGovernanceDirection,
    FederationIdentityOwner, FederationRelationshipState, FederationTrustIdentity,
    ProposeFederationRelationship, RecordName, RecoverFederationRelationship,
    RestrictFederationRelationship, RetireFederationRelationship, RevokeFederationRelationship,
    RotateFederationTrustIdentity,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_relationship_lifecycle_commits_and_replays_through_consensus()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunningAuthority::start().await?;
    let authority = ConsensusAuthenticationAuthority::new(
        fixture.reader.take().ok_or("reader")?,
        fixture.handle.clone(),
        tokio::runtime::Handle::current(),
    );
    let relationship_id = FederationRelationshipId::from_bytes([30; 16])?;
    let result = tokio::task::block_in_place(|| -> Result<(), Box<dyn std::error::Error>> {
        for (index, (command, state, epoch)) in lifecycle(relationship_id)?.into_iter().enumerate()
        {
            let marker = u8::try_from(index)? + 40;
            let context = command_context(
                fixture.administrator_id,
                marker,
                marker + 20,
                100 + i64::try_from(index)?,
                None,
            )?;
            let receipt = authority.commit_authoritative(context, &command)?;
            assert_eq!(receipt.request_digest, command.request_digest(context));
            assert_eq!(receipt.committed_revision.get(), u64::try_from(index)? + 2);
            let replay = authority.commit_authoritative(context, &command)?;
            assert_eq!(replay.committed_revision, receipt.committed_revision);
            assert_eq!(
                replay.disposition,
                meshspan_metadata::ApplyDisposition::Replayed
            );
            let record = authority
                .reader()
                .federation_relationship(relationship_id)?
                .ok_or("relationship")?;
            assert_eq!(record.state, state);
            assert_eq!(record.authority_epoch, epoch);
        }
        Ok(())
    });
    fixture.shutdown().await?;
    result
}

type LifecycleStep = (AuthoritativeCommand, FederationRelationshipState, u64);

pub(super) fn lifecycle(
    id: FederationRelationshipId,
) -> Result<Vec<LifecycleStep>, Box<dyn std::error::Error>> {
    use FederationRelationshipState::{Active, Proposed, Restricted, Retired, Revoked};
    Ok(vec![
        (
            AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
                relationship_id: id,
                remote_mesh_id: MeshId::from_bytes([31; 16])?,
                remote_name: RecordName::new("Office partner")?,
                kind: FederationRelationshipKind::Horizontal,
                governance_direction: FederationGovernanceDirection::None,
            }),
            Proposed,
            1,
        ),
        (
            AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
                relationship_id: id,
                expected_authority_epoch: 1,
                local_identity: identity(1, 32)?,
                remote_identity: identity(1, 33)?,
                governance_proof: None,
            }),
            Active,
            1,
        ),
        (
            AuthoritativeCommand::RotateFederationTrustIdentity(RotateFederationTrustIdentity {
                relationship_id: id,
                expected_authority_epoch: 1,
                owner: FederationIdentityOwner::Remote,
                identity: identity(2, 34)?,
            }),
            Active,
            1,
        ),
        (
            AuthoritativeCommand::RestrictFederationRelationship(RestrictFederationRelationship {
                relationship_id: id,
                expected_authority_epoch: 1,
                authority_epoch: 2,
                reason: "Restrict peer".into(),
            }),
            Restricted,
            2,
        ),
        (
            AuthoritativeCommand::RecoverFederationRelationship(RecoverFederationRelationship {
                relationship_id: id,
                expected_authority_epoch: 2,
                authority_epoch: 3,
                reason: "Restore peer".into(),
            }),
            Active,
            3,
        ),
        (
            AuthoritativeCommand::RevokeFederationRelationship(RevokeFederationRelationship {
                relationship_id: id,
                expected_authority_epoch: 3,
                authority_epoch: 4,
                reason: "Disconnect peer".into(),
            }),
            Revoked,
            4,
        ),
        (
            AuthoritativeCommand::RetireFederationRelationship(RetireFederationRelationship {
                relationship_id: id,
                expected_authority_epoch: 4,
                authority_epoch: 5,
                reason: "Retire peer".into(),
            }),
            Retired,
            5,
        ),
    ])
}

fn identity(
    generation: u64,
    marker: u8,
) -> Result<FederationTrustIdentity, Box<dyn std::error::Error>> {
    // Public Ed25519 fixture keys; this lifecycle test needs no private signer.
    let public = match marker {
        32 => "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        33 => "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        34 => "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        _ => return Err("unknown identity fixture".into()),
    };
    Ok(FederationTrustIdentity {
        generation,
        certificate_fingerprint: [marker; 32],
        verifying_key: crate::private_consensus_runtime::decode_hex(public)?
            .try_into()
            .map_err(|_| "public fixture length")?,
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(1000),
    })
}
