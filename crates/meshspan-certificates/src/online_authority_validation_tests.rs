// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    CertificateAuthority, OnlineCertificateAuthority, validate_online_authority_certificate,
};

#[test]
fn online_authority_reload_rejects_a_well_formed_mismatched_private_key()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CertificateAuthority::new()?;
    let first = root.issue_online_authority_from_seed([21; 32])?;
    let second = root.issue_online_authority_from_seed([22; 32])?;
    assert!(
        OnlineCertificateAuthority::from_pkcs8_and_certificate(
            second.private_key_pkcs8(),
            first.certificate_der(),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn online_authority_authentication_rejects_wrong_root_and_malformed_certificates()
-> Result<(), Box<dyn std::error::Error>> {
    let root = CertificateAuthority::new()?;
    let other = CertificateAuthority::new()?;
    let online = root.issue_online_authority_from_seed([23; 32])?;
    assert!(
        validate_online_authority_certificate(root.certificate_der(), root.certificate_der())
            .is_err()
    );
    assert!(
        OnlineCertificateAuthority::from_pkcs8_and_certificate(
            root.private_key_pkcs8(),
            root.certificate_der()
        )
        .is_err()
    );
    validate_online_authority_certificate(online.certificate_der(), root.certificate_der())?;
    assert!(
        validate_online_authority_certificate(online.certificate_der(), other.certificate_der())
            .is_err()
    );
    OnlineCertificateAuthority::from_pkcs8_and_certificate(
        online.private_key_pkcs8(),
        online.certificate_der(),
    )?;
    let mut trailing = online.certificate_der().to_vec();
    trailing.push(0);
    let leaf = root.issue_node("meshspan.internal")?;
    for certificate in [
        vec![],
        vec![1],
        vec![0; 8193],
        trailing,
        leaf.certificate_der().to_vec(),
    ] {
        assert!(
            OnlineCertificateAuthority::from_pkcs8_and_certificate(
                online.private_key_pkcs8(),
                &certificate
            )
            .is_err()
        );
        assert!(
            validate_online_authority_certificate(&certificate, root.certificate_der()).is_err()
        );
    }
    Ok(())
}
