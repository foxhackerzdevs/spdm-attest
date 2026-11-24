//! Cryptographic verification engine for SPDM signatures and X.509 certificate chains.

use crate::protocol::{ASYM_ALG_ECDSA_P256, ASYM_ALG_ECDSA_P384, ASYM_ALG_ED25519};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as Ed25519Verifier, VerifyingKey};
use p256::ecdsa::{
    signature::Verifier as P256Verifier, Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    signature::Verifier as P384Verifier, Signature as P384Signature,
    VerifyingKey as P384VerifyingKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use thiserror::Error;
use x509_parser::prelude::*;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Failed to parse X.509 certificate: {0}")]
    CertificateParseError(String),

    #[error("Empty certificate chain")]
    EmptyCertificateChain,

    #[error("Certificate chain verification failed: {0}")]
    ChainVerificationFailed(String),

    #[error("Unsupported public key algorithm in certificate")]
    UnsupportedPublicKeyAlgorithm,

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),

    #[error("Root CA mismatch or untrusted root")]
    UntrustedRootCa,

    #[error("IO or PEM decoding error: {0}")]
    PemError(String),
}

#[derive(Clone)]
pub enum DevicePublicKey {
    P384(P384VerifyingKey),
    P256(P256VerifyingKey),
    Ed25519(VerifyingKey),
}

impl fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P384(_) => write!(f, "DevicePublicKey::P384"),
            Self::P256(_) => write!(f, "DevicePublicKey::P256"),
            Self::Ed25519(_) => write!(f, "DevicePublicKey::Ed25519"),
        }
    }
}

impl DevicePublicKey {
    pub fn asym_algo(&self) -> u32 {
        match self {
            Self::P256(_) => ASYM_ALG_ECDSA_P256,
            Self::P384(_) => ASYM_ALG_ECDSA_P384,
            Self::Ed25519(_) => ASYM_ALG_ED25519,
        }
    }

    pub fn algo_name(&self) -> &'static str {
        match self {
            Self::P256(_) => "ECDSA-NIST-P256",
            Self::P384(_) => "ECDSA-NIST-P384",
            Self::Ed25519(_) => "Ed25519",
        }
    }

    /// Verifies a signature over `message` using this public key.
    /// Supports SPDM raw concatenated (r || s) format as well as DER format.
    pub fn verify_signature(&self, message: &[u8], sig_bytes: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::P384(vk) => {
                let sig = if sig_bytes.len() == 96 {
                    // SPDM standard: r (48 bytes) || s (48 bytes)
                    P384Signature::from_slice(sig_bytes)
                        .map_err(|e| CryptoError::InvalidSignatureFormat(e.to_string()))?
                } else {
                    P384Signature::from_der(sig_bytes)
                        .map_err(|e| CryptoError::InvalidSignatureFormat(e.to_string()))?
                };

                P384Verifier::verify(vk, message, &sig)
                    .map_err(|e| CryptoError::SignatureVerificationFailed(e.to_string()))
            }
            Self::P256(vk) => {
                let sig = if sig_bytes.len() == 64 {
                    // SPDM standard: r (32 bytes) || s (32 bytes)
                    P256Signature::from_slice(sig_bytes)
                        .map_err(|e| CryptoError::InvalidSignatureFormat(e.to_string()))?
                } else {
                    P256Signature::from_der(sig_bytes)
                        .map_err(|e| CryptoError::InvalidSignatureFormat(e.to_string()))?
                };

                P256Verifier::verify(vk, message, &sig)
                    .map_err(|e| CryptoError::SignatureVerificationFailed(e.to_string()))
            }
            Self::Ed25519(vk) => {
                if sig_bytes.len() != 64 {
                    return Err(CryptoError::InvalidSignatureFormat(format!(
                        "Expected 64 bytes for Ed25519 signature, got {}",
                        sig_bytes.len()
                    )));
                }
                let sig = Ed25519Signature::from_slice(sig_bytes)
                    .map_err(|e| CryptoError::InvalidSignatureFormat(e.to_string()))?;

                Ed25519Verifier::verify(vk, message, &sig)
                    .map_err(|e| CryptoError::SignatureVerificationFailed(e.to_string()))
            }
        }
    }
}

/// Parses a certificate chain from PEM or DER data and verifies its validity up to the Root CA.
/// Returns the responder (leaf) public key.
pub fn verify_certificate_chain(
    chain_pem_or_der: &[u8],
    root_ca_pem_or_der: &[u8],
) -> Result<DevicePublicKey, CryptoError> {
    let chain_certs = parse_certificates(chain_pem_or_der)?;
    if chain_certs.is_empty() {
        return Err(CryptoError::EmptyCertificateChain);
    }

    let root_certs = parse_certificates(root_ca_pem_or_der)?;
    if root_certs.is_empty() {
        return Err(CryptoError::CertificateParseError(
            "No Root CA found".to_string(),
        ));
    }
    let trusted_root = &root_certs[0];

    // Verify chain integrity: Each cert must be signed by the next, and top cert signed by Root CA
    let mut current_subject = &chain_certs[0];

    for (i, issuer_cert) in chain_certs.iter().skip(1).enumerate() {
        let current_parsed = current_subject
            .parse()
            .map_err(|e| CryptoError::CertificateParseError(e.to_string()))?;
        let issuer_parsed = issuer_cert
            .parse()
            .map_err(|e| CryptoError::CertificateParseError(e.to_string()))?;

        current_parsed
            .verify_signature(Some(issuer_parsed.public_key()))
            .map_err(|e| {
                CryptoError::ChainVerificationFailed(format!(
                    "Certificate {} verification failed against issuer: {:?}",
                    i, e
                ))
            })?;

        current_subject = issuer_cert;
    }

    // Verify top certificate in chain against the trusted Root CA
    let top_parsed = current_subject
        .parse()
        .map_err(|e| CryptoError::CertificateParseError(e.to_string()))?;
    let root_parsed = trusted_root
        .parse()
        .map_err(|e| CryptoError::CertificateParseError(e.to_string()))?;

    top_parsed
        .verify_signature(Some(root_parsed.public_key()))
        .map_err(|_e| CryptoError::UntrustedRootCa)?;

    // Extract public key from leaf certificate (first certificate in chain)
    let leaf_parsed = chain_certs[0]
        .parse()
        .map_err(|e| CryptoError::CertificateParseError(e.to_string()))?;

    extract_public_key(&leaf_parsed.tbs_certificate.subject_pki)
}

/// Internal certificate container supporting both DER slices and parsed representations.
pub struct RawCert(pub Vec<u8>);

impl RawCert {
    pub fn parse(
        &self,
    ) -> Result<X509Certificate<'_>, x509_parser::nom::Err<x509_parser::error::X509Error>> {
        parse_x509_certificate(&self.0).map(|(_, cert)| cert)
    }
}

pub fn parse_certificates(data: &[u8]) -> Result<Vec<RawCert>, CryptoError> {
    let mut certs = Vec::new();
    let text = String::from_utf8_lossy(data);

    if text.contains("-----BEGIN CERTIFICATE-----") {
        for cert in x509_parser::pem::Pem::iter_from_buffer(data) {
            let pem = cert.map_err(|e| CryptoError::PemError(e.to_string()))?;
            if pem.label == "CERTIFICATE" {
                certs.push(RawCert(pem.contents));
            }
        }
    } else {
        // Treat as raw DER
        certs.push(RawCert(data.to_vec()));
    }

    Ok(certs)
}

fn extract_public_key(spki: &SubjectPublicKeyInfo<'_>) -> Result<DevicePublicKey, CryptoError> {
    let alg_oid = spki.algorithm.algorithm.to_id_string();
    let raw_bytes = spki.subject_public_key.data.as_ref();

    // id-ecPublicKey = 1.2.840.10045.2.1
    if alg_oid == "1.2.840.10045.2.1" {
        if let Some(params) = &spki.algorithm.parameters {
            if let Ok(curve_oid) = params.as_oid() {
                let curve_str = curve_oid.to_id_string();
                // secp384r1 = 1.3.132.0.34
                if curve_str == "1.3.132.0.34" {
                    let vk = P384VerifyingKey::from_sec1_bytes(raw_bytes)
                        .map_err(|e| CryptoError::CertificateParseError(e.to_string()))?;
                    return Ok(DevicePublicKey::P384(vk));
                }
                // prime256v1 / secp256r1 = 1.2.840.10045.3.1.7
                if curve_str == "1.2.840.10045.3.1.7" {
                    let vk = P256VerifyingKey::from_sec1_bytes(raw_bytes)
                        .map_err(|e| CryptoError::CertificateParseError(e.to_string()))?;
                    return Ok(DevicePublicKey::P256(vk));
                }
            }
        }
    }

    // Ed25519 = 1.3.101.112
    if alg_oid == "1.3.101.112" {
        let key_bytes: [u8; 32] = raw_bytes.try_into().map_err(|_| {
            CryptoError::CertificateParseError("Invalid Ed25519 key length".to_string())
        })?;
        let vk = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CryptoError::CertificateParseError(e.to_string()))?;
        return Ok(DevicePublicKey::Ed25519(vk));
    }

    Err(CryptoError::UnsupportedPublicKeyAlgorithm)
}

pub fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn sha384_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn sha512_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}
