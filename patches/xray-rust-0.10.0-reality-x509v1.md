# xray-rust v0.10.0 — REALITY X.509 v1 SPKI CertificateVerify Fix (MPL-2.0)

File: `crates/xray-transport/src/reality_rustls.rs` (`RealityServerVerifier::verify_tls13_signature`)

## Root Cause
`sing-box` and minimal `Xray-core` VLESS+REALITY servers (commonly deployed by Remnawave, Marzban,
Hiddify, 3x-ui, and 2026 Russian mobile-whitelist / RU-CIDR bridges) issue ephemeral Ed25519
REALITY leaf certificates without X.509v3 extensions (`version = v1`).
`RealityServerVerifier::verify_server_cert` validates the REALITY HMAC-SHA512 over the Ed25519 public key
via `x509_parser`, passing cleanly, but `verify_tls13_signature` delegated solely to
`rustls::crypto::verify_tls13_signature`, whose `rustls-webpki` parser rejects X.509 v1 with
`InvalidCertificate(Other(OtherError(UnsupportedCertVersion)))`.

## Fix
When `real_certificate` fallback was NOT taken (i.e., `verify_server_cert` strictly proved
`RealityCertificateVerification::Verified` via HMAC-SHA512), extract the leaf `SubjectPublicKeyInfo`
DER via `x509_parser::parse_x509_certificate` and verify the full RFC 8446 §4.4.3 TLS 1.3
`CertificateVerify` signature with `rustls::crypto::verify_tls13_signature_with_raw_key`.
Real-certificate fallback connections still enforce full X.509v3 `rustls-webpki` verification.
