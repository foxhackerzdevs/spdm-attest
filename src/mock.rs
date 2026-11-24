//! Synthetic SPDM attestation evidence generator for testing and CI validation.

use crate::measurement::GoldenManifest;
use crate::protocol::{
    MeasurementBlock, MeasurementsResponse, SpdmHeader, CODE_MEASUREMENTS, DMTF_SPEC_MEASUREMENT,
    MEASUREMENT_TYPE_FIRMWARE_CONFIG, MEASUREMENT_TYPE_HARDWARE_CONFIG,
    MEASUREMENT_TYPE_IMMUTABLE_ROM, MEASUREMENT_TYPE_MUTABLE_FIRMWARE, SPDM_VERSION_1_2,
};
use p384::ecdsa::{signature::Signer, SigningKey};
use p384::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P384_SHA384,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MockError {
    #[error("Rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub struct MockAttestationBundle {
    pub root_ca_pem: String,
    pub cert_chain_pem: String,
    pub quote_bytes: Vec<u8>,
    pub nonce: [u8; 32],
    pub golden_manifest: GoldenManifest,
}

/// Generates a realistic mock SPDM 1.2 attestation evidence bundle with ECDSA P-384.
pub fn generate_mock_bundle(platform_name: &str) -> Result<MockAttestationBundle, MockError> {
    // 1. Generate Root CA (e.g., Manufacturer Root CA)
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
    let mut root_params = CertificateParams::default();
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CommonName, "Sovereign Silicon Manufacturer Root CA");
    root_dn.push(DnType::OrganizationName, "Fox Hackerz Hardware Security");
    root_params.distinguished_name = root_dn;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let root_cert = root_params.self_signed(&root_key)?;
    let root_ca_pem = root_cert.pem();

    // 2. Generate Device Identity Certificate (e.g. GPU DICE / SPDM Responder)
    let device_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
    let mut device_params = CertificateParams::default();
    let mut device_dn = DistinguishedName::new();
    device_dn.push(
        DnType::CommonName,
        format!("{} SPDM Responder Enclave", platform_name),
    );
    device_dn.push(DnType::OrganizationName, "Fox Hackerz Hardware Security");
    device_params.distinguished_name = device_dn;
    device_params.is_ca = IsCa::NoCa;

    let device_cert = device_params.signed_by(&device_key, &root_cert, &root_key)?;
    let device_cert_pem = device_cert.pem();
    let cert_chain_pem = format!("{}\n{}", device_cert_pem, root_ca_pem);

    // 3. Synthesize realistic GPU measurements (SHA-384 digests, 48 bytes each)
    let rom_digest = crate::crypto::sha384_digest(b"H100_SECURE_BOOT_ROM_V2.1.0_PROD");
    let fw_digest = crate::crypto::sha384_digest(b"NVIDIA_GPU_MICROCODE_550.54.15_CC_ENABLED");
    let hw_config_digest = crate::crypto::sha384_digest(b"PCIE_GEN5_SECURE_APM_CPR_ENCRYPTED");
    let vbios_digest = crate::crypto::sha384_digest(b"VBIOS_96.00.75.00.01_CONFIDENTIAL_COMPUTE");

    let blocks = vec![
        MeasurementBlock {
            index: 1,
            spec: DMTF_SPEC_MEASUREMENT,
            value_type: MEASUREMENT_TYPE_IMMUTABLE_ROM,
            value: rom_digest.clone(),
        },
        MeasurementBlock {
            index: 2,
            spec: DMTF_SPEC_MEASUREMENT,
            value_type: MEASUREMENT_TYPE_MUTABLE_FIRMWARE,
            value: fw_digest.clone(),
        },
        MeasurementBlock {
            index: 3,
            spec: DMTF_SPEC_MEASUREMENT,
            value_type: MEASUREMENT_TYPE_HARDWARE_CONFIG,
            value: hw_config_digest.clone(),
        },
        MeasurementBlock {
            index: 4,
            spec: DMTF_SPEC_MEASUREMENT,
            value_type: MEASUREMENT_TYPE_FIRMWARE_CONFIG,
            value: vbios_digest.clone(),
        },
    ];

    // 4. Build Golden Manifest
    let mut golden = GoldenManifest::new(platform_name, "v2.1.0-prod");
    golden.add_measurement(
        1,
        "Secure Boot ROM",
        "Primary Boot ROM Digest",
        hex::encode(&rom_digest),
    );
    golden.add_measurement(
        2,
        "GPU Microcode",
        "Kernel Microcode with CC",
        hex::encode(&fw_digest),
    );
    golden.add_measurement(
        3,
        "Hardware Security Config",
        "PCIe APM/CPR Security Registers",
        hex::encode(&hw_config_digest),
    );
    golden.add_measurement(
        4,
        "VBIOS Firmware",
        "Confidential Compute VBIOS Image",
        hex::encode(&vbios_digest),
    );

    // 5. Create SPDM Quote with Nonce
    let mut nonce = [0u8; 32];
    for (i, byte) in nonce.iter_mut().enumerate() {
        *byte = (i * 7 + 13) as u8;
    }

    let header = SpdmHeader::new(
        SPDM_VERSION_1_2,
        CODE_MEASUREMENTS,
        blocks.len() as u8,
        0x01,
    );
    let mut response = MeasurementsResponse {
        header,
        number_of_blocks: blocks.len() as u8,
        blocks,
        nonce: Some(nonce),
        opaque_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        signature: Vec::new(),
    };

    // 6. Sign the transcript with the device private key
    let transcript = response.signed_transcript();
    let signing_key = p384::SecretKey::from_pkcs8_der(&device_key.serialize_der())
        .map(|sk| SigningKey::from(&sk))
        .map_err(|e| MockError::Crypto(format!("Failed to parse device private key: {:?}", e)))?;

    let signature: p384::ecdsa::Signature = signing_key.sign(&transcript);
    // SPDM standard signature format: raw (r || s) = 96 bytes for P-384
    response.signature = signature.to_bytes().to_vec();

    let quote_bytes = response.to_bytes();

    Ok(MockAttestationBundle {
        root_ca_pem,
        cert_chain_pem,
        quote_bytes,
        nonce,
        golden_manifest: golden,
    })
}
