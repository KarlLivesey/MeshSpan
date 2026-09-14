# External TLS chain corpus

Public certificate bytes captured on 2026-09-14 at approximately 18:30 UTC using
OpenSSL 3.6.4 (25 Aug 2026). These are offline compatibility fixtures, not trust
anchors selected by MeshSpan at runtime or proof of future endpoint availability.
Tests fix the validation time at 2026-09-14 18:30 UTC. Root certificates were
copied from the host system trust store and their fingerprints appear below.

For each hostname, the capture command was:

```sh
openssl s_client -connect HOST:443 -servername HOST -showcerts -verify_return_error
```

Every capture completed with `Verify return code: 0 (ok)`. A second OpenSSL
handshake to each ACME directory and the Cloudflare API used exactly TLS 1.3,
`-groups P-256`, `-ciphersuites TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`,
and `-sigalgs ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384`. All three negotiated
P-256 ECDHE, ChaCha20-Poly1305/SHA-256 and P-256 ECDSA transcript signatures, with
successful certificate verification. This records the existing traffic/key
exchange profile's compatibility at capture time; it is not live ACME issuance
or DNS mutation acceptance. Certificates are stored
in the server-supplied leaf-first order; PEM was converted with `openssl x509
-outform DER`. Captures contain only public certificates, with no TLS session
material. Endpoint versions and profiles:

| Prefix          | Host / service                                                  | Captured chain                                                     | Root used in offline verification |
| --------------- | --------------------------------------------------------------- | ------------------------------------------------------------------ | --------------------------------- |
| acme-production | acme-v02.api.letsencrypt.org, ACME v2                           | P-256 leaf, P-384 YE1, P-384 Root YE, X2 cross-signed by RSA X1    | ISRG Root X2                      |
| acme-staging    | acme-staging-v02.api.letsencrypt.org, ACME v2                   | P-256 leaf, P-384 YE2, P-384 Root YE, X2 cross-signed by RSA X1    | ISRG Root X2                      |
| cloudflare      | api.cloudflare.com, DNS provider API v4                         | P-256 leaf, P-256 WE1, P-384 GTS R4 cross-signed by RSA GlobalSign | GTS Root R4                       |
| issued-public   | valid-isrgrootx2.letsencrypt.org, public issuance test endpoint | P-256 leaf, P-384 YE2, P-384 Root YE                               | ISRG Root X2                      |

The Let's Encrypt leaf/intermediate links use ECDSA SHA-384. Cloudflare's leaf
uses ECDSA SHA-256; WE1 uses ECDSA SHA-384 signed by the P-384 root. The RSA
cross-signs are retained as captured, but current verification terminates at the
configured ECDSA trust anchor. Successful validation therefore does **not** claim
RSA support. OpenSSL also independently verified both captured ACME chains
against ISRG Root X1 alone, using `verify -CAfile ISRG_Root_X1.pem -untrusted
intermediates.pem -verify_hostname HOST -attime 1789410600 -purpose sslserver
leaf.pem`; both returned OK. A separate MeshSpan test explicitly rejects this
valid X1-only path because its RSA signature algorithm remains unsupported.

This corpus establishes P-256/SHA-256 and P-384/SHA-384 requirements. TLS remains
1.3 with the existing traffic ciphers and P-256 key exchange. Private identities
and all local/public publisher private keys remain P-256. RSA webhook/service
keys, RSA cross-root paths, and other issuer algorithms remain unsupported and
must fail closed. Arbitrary webhook or ACME endpoints have no universal chain
compatibility guarantee.

Algorithm provenance: [Let's Encrypt CA certificates](https://letsencrypt.org/ca/certificates/)
and the actual recorded certificate signatures, rather than assumptions based on
leaf key type. Root fingerprints can be checked against the CA trust stores.

## Independent local issuance fixture

`local-p384-*` was generated with the same installed OpenSSL, independently of
MeshSpan and RustCrypto. A new P-384 root signs a P-256 leaf using SHA-384. The
leaf has critical CA:FALSE/digitalSignature, serverAuth EKU, and SANs
`files.example.test` and `*.files.example.test`. It was checked with `openssl
verify -CAfile root.pem -verify_hostname files.example.test -purpose sslserver
leaf.pem`. The test time is fixed at Unix second 1789420000. The leaf is valid
from 2026-09-14 18:35:50 UTC through 2027-09-14 18:35:50 UTC. Only its test-only
PKCS#8 private key is retained; the root signing key was discarded. Never use
this public test key in a deployment.

Generation uses `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1`
for the root and `prime256v1` for the leaf, `req -new -x509 -sha384` for the root,
and `x509 -req -sha384 -set_serial 2 -days 365` for the signed CSR. These fixed
bytes intentionally need no OpenSSL binary, network or wall clock during tests.
They exercise the daemon's outbound client configuration, terminal ACME result
validator and automated publisher, including exact leaf key/name checks.

## SHA-256 fingerprints

- `acme-production-0.der`: `5d2136f3086b348a4189c99b2331fda999c248381b6e09d9ced94f43d071ac22`
- `acme-production-1.der`: `a2372d06431e9716365eeed47ec020351497d182fcc038e457e58168a03cac07`
- `acme-production-2.der`: `0fc0901cca2bae9e9fdbb02d50d02f1094f7b36672086991b9e897626dc485f0`
- `acme-production-3.der`: `ee5f7abd6981bb0255632cd8f49283451b4b18844d12040b44ee00f07b8fe2c6`
- `acme-staging-0.der`: `b3a7c608607076852bf8e2d8e95308daf6d127d0befd7c6d0d4584f3cccd6a1f`
- `acme-staging-1.der`: `97658de8c68dfa98ace1e5028a63d54a1aae911b3e21471076c6850cd08cbab4`
- `acme-staging-2.der`: `0fc0901cca2bae9e9fdbb02d50d02f1094f7b36672086991b9e897626dc485f0`
- `acme-staging-3.der`: `ee5f7abd6981bb0255632cd8f49283451b4b18844d12040b44ee00f07b8fe2c6`
- `cloudflare-0.der`: `4c05a808fb633dbc3e01fb1ab0086b54dab50cba59502caaf347e266c19dfc71`
- `cloudflare-1.der`: `1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96`
- `cloudflare-2.der`: `76b27b80a58027dc3cf1da68dac17010ed93997d0b603e2fadbe85012493b5a7`
- `gts-r4.der`: `349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d`
- `isrg-x1.der`: `96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6`
- `isrg-x2.der`: `69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470`
- `issued-public-0.der`: `5f0b1f1f11f8e9f141d1c9a87afb20cfcfb9ed0d25b67827d7eac1bd4d635796`
- `issued-public-1.der`: `97658de8c68dfa98ace1e5028a63d54a1aae911b3e21471076c6850cd08cbab4`
- `issued-public-2.der`: `0fc0901cca2bae9e9fdbb02d50d02f1094f7b36672086991b9e897626dc485f0`
- `local-p384-chain.pem`: `7107051ba47f891f5b3c93b01fa07eaa1e66bbec61e97cda808ec5f85a621840`
- `local-p384-leaf-key.der`: `fa25f386293e1d91d897b7e35f4f7ab790809f130ca91bbe51768557c1843501`
- `local-p384-leaf.der`: `75a5a544fdcb4337f3ca4c800559cc8843e2c45d4ee2f4be95834aa1dc22af56`
- `local-p384-root.der`: `5f0b340a09529eb8f6440eea54d21d6fee0331c43d1614406f2051a4409b01a2`
