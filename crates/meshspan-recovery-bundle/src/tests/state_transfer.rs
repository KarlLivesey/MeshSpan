// SPDX-License-Identifier: GPL-2.0-only

use super::{SequentialRandom, authorization::claims};
use crate::{RecoveryStateTransfer, RecoveryStateTransferClaims, create_recovery_bundle};
use meshspan_domain::NodeId;

#[test]
fn state_delivery_binds_both_files_recipient_and_root() -> Result<(), Box<dyn std::error::Error>> {
    let source = claims()?;
    let (bundle, code, identity) =
        create_recovery_bundle(source.mesh_id, &mut SequentialRandom::new(111))?;
    let authority = bundle.open(&code)?;
    let claims = RecoveryStateTransferClaims {
        authorization: authority.authorize_recovery(source)?,
        node_id: NodeId::from_bytes([9; 16])?,
        incarnation: 2,
        state_digest: [10; 32],
        state_length: 1_048_576,
        key_bundle_digest: [11; 32],
        key_bundle_length: 4096,
    };
    let transfer = authority.authorize_state_transfer(claims.clone())?;
    let encoded = transfer.encode()?;
    let root = identity.root_certificate_der();
    assert_eq!(RecoveryStateTransfer::decode(root, &encoded)?, transfer);
    assert_eq!(transfer.claims(), &claims);
    assert!(encoded.starts_with(b"MSRSTATE\x01"));
    let offset = 11 + claims.authorization.encode()?.len();
    assert_eq!(&encoded[offset..offset + 16], &[9; 16]);
    assert_eq!(&encoded[offset + 16..offset + 24], &2_u64.to_be_bytes());
    assert_eq!(&encoded[offset + 24..offset + 56], &[10; 32]);
    assert_eq!(
        &encoded[offset + 56..offset + 64],
        &1_048_576_u64.to_be_bytes()
    );
    assert_eq!(&encoded[offset + 64..offset + 96], &[11; 32]);
    assert_eq!(&encoded[offset + 96..offset + 104], &4096_u64.to_be_bytes());
    for end in 0..encoded.len() {
        assert!(RecoveryStateTransfer::decode(root, &encoded[..end]).is_err());
    }
    for index in 0..encoded.len() {
        let mut damaged = encoded.clone();
        damaged[index] ^= 1;
        assert!(
            RecoveryStateTransfer::decode(root, &damaged).is_err(),
            "byte {index} accepted"
        );
    }
    let (_, _, other) = create_recovery_bundle(source.mesh_id, &mut SequentialRandom::new(131))?;
    assert!(RecoveryStateTransfer::decode(other.root_certificate_der(), &encoded).is_err());
    let mut excess = encoded.clone();
    excess.push(0);
    assert!(RecoveryStateTransfer::decode(root, &excess).is_err());
    assert!(
        transfer
            .installation_message()?
            .starts_with(b"MeshSpan recovery state installation v1\0")
    );
    let mut invalid = claims;
    invalid.incarnation = 0;
    assert!(authority.authorize_state_transfer(invalid).is_err());
    Ok(())
}
