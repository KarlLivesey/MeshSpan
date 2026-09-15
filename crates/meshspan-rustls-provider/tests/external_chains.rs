// SPDX-License-Identifier: GPL-2.0-only

//! Independently captured service chains, verified at their recorded capture time.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier as _;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error, RootCertStore};

const CAPTURE_TIME: u64 = 1_789_410_600;
const ISRG_X2: &[u8] = include_bytes!("fixtures/external/isrg-x2.der");
const GTS_R4: &[u8] = include_bytes!("fixtures/external/gts-r4.der");

struct CapturedChain {
    name: &'static str,
    root: &'static [u8],
    certificates: &'static [&'static [u8]],
}

const CHAINS: &[CapturedChain] = &[
    CapturedChain {
        name: "acme-v02.api.letsencrypt.org",
        root: ISRG_X2,
        certificates: &[
            include_bytes!("fixtures/external/acme-production-0.der"),
            include_bytes!("fixtures/external/acme-production-1.der"),
            include_bytes!("fixtures/external/acme-production-2.der"),
            include_bytes!("fixtures/external/acme-production-3.der"),
        ],
    },
    CapturedChain {
        name: "acme-staging-v02.api.letsencrypt.org",
        root: ISRG_X2,
        certificates: &[
            include_bytes!("fixtures/external/acme-staging-0.der"),
            include_bytes!("fixtures/external/acme-staging-1.der"),
            include_bytes!("fixtures/external/acme-staging-2.der"),
            include_bytes!("fixtures/external/acme-staging-3.der"),
        ],
    },
    CapturedChain {
        name: "api.cloudflare.com",
        root: GTS_R4,
        certificates: &[
            include_bytes!("fixtures/external/cloudflare-0.der"),
            include_bytes!("fixtures/external/cloudflare-1.der"),
            include_bytes!("fixtures/external/cloudflare-2.der"),
        ],
    },
    CapturedChain {
        name: "valid-isrgrootx2.letsencrypt.org",
        root: ISRG_X2,
        certificates: &[
            include_bytes!("fixtures/external/issued-public-0.der"),
            include_bytes!("fixtures/external/issued-public-1.der"),
            include_bytes!("fixtures/external/issued-public-2.der"),
        ],
    },
];

#[test]
fn captured_service_chains_validate_with_external_profile() {
    for chain in CHAINS {
        assert!(
            verify(
                chain,
                meshspan_rustls_provider::external_webpki_provider(),
                chain.name,
                CAPTURE_TIME
            )
            .is_ok(),
            "captured chain for {} must verify",
            chain.name
        );
    }
}

#[test]
fn captured_service_chains_reject_wrong_names_expiry_roots_and_tampering()
-> Result<(), Box<dyn std::error::Error>> {
    for chain in CHAINS {
        let provider = meshspan_rustls_provider::external_webpki_provider;
        assert!(matches!(
            verify(chain, provider(), "wrong.example.test", CAPTURE_TIME),
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForNameContext { .. }
            ))
        ));
        assert!(matches!(
            verify(chain, provider(), chain.name, 4_000_000_000),
            Err(Error::InvalidCertificate(
                CertificateError::ExpiredContext { .. }
            ))
        ));
        let wrong_root = if chain.root == ISRG_X2 {
            GTS_R4
        } else {
            ISRG_X2
        };
        let wrong_verifier = verifier(wrong_root, provider())?;
        assert_eq!(
            verify_with(
                chain,
                &wrong_verifier,
                chain.certificates[0],
                chain.name,
                CAPTURE_TIME
            ),
            Err(Error::InvalidCertificate(CertificateError::UnknownIssuer))
        );
        let mut altered = chain.certificates[0].to_vec();
        *altered.last_mut().ok_or("empty certificate fixture")? ^= 1;
        let verifier = verifier(chain.root, provider())?;
        assert_eq!(
            verify_with(chain, &verifier, &altered, chain.name, CAPTURE_TIME),
            Err(Error::InvalidCertificate(CertificateError::BadSignature))
        );
    }
    Ok(())
}

#[test]
fn private_identity_profile_still_rejects_external_p384_issuers() {
    for chain in CHAINS {
        assert!(
            verify(
                chain,
                meshspan_rustls_provider::internal_identity_provider(),
                chain.name,
                CAPTURE_TIME
            )
            .is_err()
        );
    }
}

#[test]
fn rsa_only_trust_path_remains_explicitly_unsupported() {
    let chain = CapturedChain {
        root: include_bytes!("fixtures/external/isrg-x1.der"),
        ..CHAINS[0]
    };
    assert!(
        verify(
            &chain,
            meshspan_rustls_provider::external_webpki_provider(),
            chain.name,
            CAPTURE_TIME
        )
        .is_err()
    );
}

fn verify(
    chain: &CapturedChain,
    provider: CryptoProvider,
    name: &str,
    seconds: u64,
) -> Result<(), Error> {
    verify_with(
        chain,
        verifier(chain.root, provider)?.as_ref(),
        chain.certificates[0],
        name,
        seconds,
    )
}

fn verifier(root: &[u8], provider: CryptoProvider) -> Result<Arc<WebPkiServerVerifier>, Error> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root))?;
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::new(provider))
        .build()
        .map_err(|error| Error::General(error.to_string()))
}

fn verify_with(
    chain: &CapturedChain,
    verifier: &WebPkiServerVerifier,
    leaf: &[u8],
    name: &str,
    seconds: u64,
) -> Result<(), Error> {
    let intermediates = chain.certificates[1..]
        .iter()
        .map(|bytes| CertificateDer::from(*bytes))
        .collect::<Vec<_>>();
    verifier
        .verify_server_cert(
            &CertificateDer::from(leaf),
            &intermediates,
            &ServerName::try_from(name)
                .map_err(|_| Error::General("invalid fixture DNS name".to_owned()))?,
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
        )
        .map(|_| ())
}
