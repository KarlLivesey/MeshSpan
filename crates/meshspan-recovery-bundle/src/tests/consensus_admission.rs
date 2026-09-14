// SPDX-License-Identifier: GPL-2.0-only

use super::{SequentialRandom, authorization::claims};
use crate::{
    RecoveryConsensusAdmission, RecoveryConsensusAdmissionClaims, RecoveryStateTransfer,
    RecoveryStateTransferClaims, create_recovery_bundle,
};
use meshspan_domain::NodeId;

#[test]
fn consensus_permission_is_exact_and_not_a_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let source = claims()?;
    let (bundle, code, identity) =
        create_recovery_bundle(source.mesh_id, &mut SequentialRandom::new(141))?;
    let authority = bundle.open(&code)?;
    let claims = RecoveryConsensusAdmissionClaims {
        authorization: authority.authorize_recovery(source)?,
        state_digest: [23; 32],
        state_length: 8192,
    };
    let permission = authority.authorize_recovery_consensus(claims.clone())?;
    let encoded = permission.encode()?;
    let root = identity.root_certificate_der();
    assert_eq!(permission.claims(), &claims);
    assert_eq!(
        RecoveryConsensusAdmission::decode(root, &encoded)?,
        permission
    );
    assert!(encoded.starts_with(b"MSRCNSNS\x01"));
    let offset = 11 + claims.authorization.encode()?.len();
    assert_eq!(&encoded[offset..offset + 32], &[23; 32]);
    assert_eq!(&encoded[offset + 32..offset + 40], &8192_u64.to_be_bytes());
    for end in 0..encoded.len() {
        assert!(RecoveryConsensusAdmission::decode(root, &encoded[..end]).is_err());
    }
    for index in 0..encoded.len() {
        let mut damaged = encoded.clone();
        damaged[index] ^= 1;
        assert!(
            RecoveryConsensusAdmission::decode(root, &damaged).is_err(),
            "byte {index}"
        );
    }
    let mut excess = encoded.clone();
    excess.push(0);
    assert!(RecoveryConsensusAdmission::decode(root, &excess).is_err());
    assert!(RecoveryConsensusAdmission::decode(root, &[0; 513]).is_err());
    let (_, _, other) = create_recovery_bundle(source.mesh_id, &mut SequentialRandom::new(151))?;
    assert!(RecoveryConsensusAdmission::decode(other.root_certificate_der(), &encoded).is_err());
    let transfer = authority.authorize_state_transfer(RecoveryStateTransferClaims {
        authorization: claims.authorization.clone(),
        node_id: NodeId::from_bytes([24; 16])?,
        incarnation: 1,
        state_digest: claims.state_digest,
        state_length: claims.state_length,
        key_bundle_digest: [25; 32],
        key_bundle_length: 2048,
    })?;
    assert!(RecoveryConsensusAdmission::decode(root, &transfer.encode()?).is_err());
    assert!(RecoveryStateTransfer::decode(root, &encoded).is_err());
    let mut invalid = claims.clone();
    invalid.state_digest = [0; 32];
    assert!(authority.authorize_recovery_consensus(invalid).is_err());
    let mut invalid = claims;
    invalid.state_length = 0;
    assert!(authority.authorize_recovery_consensus(invalid).is_err());
    Ok(())
}
