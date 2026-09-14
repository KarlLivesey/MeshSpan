// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{JoinGrantBundle, JoinGrantIssuanceKey};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn pairing_material_replays_exactly_and_binds_the_full_invitation() -> TestResult {
    let key = FederationPairingIssuanceKey::from_bytes([1; 32])?;
    let request = request()?;
    let invitation = FederationPairingInvitation::issue(&key, &request)?;
    let replay = FederationPairingInvitation::issue(&key, &request)?;
    let encoded = invitation.expose_encoded();
    assert_eq!(encoded.as_str(), replay.expose_encoded().as_str());
    let parsed = FederationPairingInvitation::parse(&encoded)?;
    assert_eq!(parsed.mesh_id(), request.mesh_id);
    assert_eq!(parsed.relationship_id(), invitation.relationship_id());
    assert_eq!(parsed.issued_at(), UnixMicros::new(100));
    assert_eq!(parsed.expires_at(), UnixMicros::new(1_000));
    assert_eq!(parsed.endpoint(), "https://office.example:8443");
    assert_eq!(parsed.certificate_fingerprint(), [5; 32]);
    assert_eq!(parsed.verifier(), invitation.verifier());
    assert!(!parsed.is_current(UnixMicros::new(99)));
    assert!(parsed.is_current(UnixMicros::new(100)));
    assert!(parsed.is_current(UnixMicros::new(999)));
    assert!(!parsed.is_current(UnixMicros::new(1000)));
    let changed = FederationPairingInvitation::issue(
        &key,
        &FederationPairingIssuance {
            expires_at: UnixMicros::new(1001),
            ..request
        },
    )?;
    assert_ne!(changed.verifier(), invitation.verifier());
    assert_ne!(changed.relationship_id(), invitation.relationship_id());
    Ok(())
}

#[test]
fn node_enrolment_and_federation_material_are_not_interchangeable() -> TestResult {
    let request = request()?;
    let key = FederationPairingIssuanceKey::from_bytes([1; 32])?;
    let pairing = FederationPairingInvitation::issue(&key, &request)?;
    let join = JoinGrantBundle::derive_issued(
        &JoinGrantIssuanceKey::from_bytes([1; 32])?,
        request.mesh_id,
        request.principal_id,
        request.operation_id,
        request.endpoint,
        request.certificate_fingerprint,
    )?;
    assert!(JoinGrantBundle::parse(&pairing.expose_encoded()).is_err());
    assert!(FederationPairingInvitation::parse(&join.expose_encoded()).is_err());
    assert_ne!(pairing.verifier(), join.secret_digest());
    Ok(())
}

#[test]
fn malformed_or_overlong_material_is_rejected_without_contacting_an_endpoint() -> TestResult {
    let key = FederationPairingIssuanceKey::from_bytes([1; 32])?;
    let request = request()?;
    for endpoint in [
        "http://office.example",
        "https://user@office.example",
        "https://office.example/path",
        "https://office.example?secret=x",
    ] {
        assert!(
            FederationPairingInvitation::issue(
                &key,
                &FederationPairingIssuance {
                    endpoint,
                    ..request
                }
            )
            .is_err()
        );
    }
    for expiry in [100, 99, i64::MAX] {
        assert!(
            FederationPairingInvitation::issue(
                &key,
                &FederationPairingIssuance {
                    expires_at: UnixMicros::new(expiry),
                    ..request
                }
            )
            .is_err()
        );
    }
    let encoded = FederationPairingInvitation::issue(&key, &request)?.expose_encoded();
    assert!(FederationPairingInvitation::parse(&format!("{}|extra", encoded.as_str())).is_err());
    assert!(FederationPairingInvitation::parse(&encoded.to_uppercase()).is_err());
    assert!(
        FederationPairingInvitation::parse(&"x".repeat(MAXIMUM_FEDERATION_PAIRING_CODE_BYTES + 1))
            .is_err()
    );
    Ok(())
}

fn request() -> Result<FederationPairingIssuance<'static>, Box<dyn std::error::Error>> {
    Ok(FederationPairingIssuance {
        mesh_id: MeshId::from_bytes([2; 16])?,
        principal_id: PrincipalId::from_bytes([3; 16])?,
        operation_id: OperationId::from_bytes([4; 16])?,
        issued_at: UnixMicros::new(100),
        expires_at: UnixMicros::new(1000),
        endpoint: "https://office.example:8443",
        certificate_fingerprint: [5; 32],
    })
}
