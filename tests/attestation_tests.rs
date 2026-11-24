use spdm_attest::crypto::{sha256_digest, DevicePublicKey};
use spdm_attest::measurement::ComparisonStatus;
use spdm_attest::mock::generate_mock_bundle;
use spdm_attest::protocol::{
    MeasurementBlock, MeasurementsResponse, SpdmHeader, ASYM_ALG_ECDSA_P384, ASYM_ALG_ED25519,
    CODE_MEASUREMENTS, DMTF_SPEC_MEASUREMENT, MEASUREMENT_TYPE_IMMUTABLE_ROM, SPDM_VERSION_1_2,
};
use spdm_attest::verifier::{verify_attestation, AttestationOptions};

#[test]
fn test_end_to_end_valid_attestation() {
    let bundle = generate_mock_bundle("NVIDIA-H100-SXM5").expect("generate mock bundle");

    let options = AttestationOptions {
        expected_nonce: Some(bundle.nonce),
        golden_manifest: Some(bundle.golden_manifest),
    };

    let report = verify_attestation(
        &bundle.quote_bytes,
        bundle.cert_chain_pem.as_bytes(),
        bundle.root_ca_pem.as_bytes(),
        &options,
    )
    .expect("attestation must succeed");

    assert!(report.success);
    assert_eq!(report.responder_algo, "ECDSA-NIST-P384");
    assert!(report.cert_chain_verified);
    assert!(report.signature_verified);
    assert!(report.nonce_verified);
    assert_eq!(report.total_blocks, 4);
    assert!(report
        .comparisons
        .iter()
        .all(|c| c.status == ComparisonStatus::Match));
    assert!(report.failure_reason.is_none());
}

#[test]
fn test_tampered_quote_signature_failure() {
    let bundle = generate_mock_bundle("NVIDIA-H100-SXM5").expect("generate mock bundle");

    // Tamper with one byte in the quote data
    let mut tampered_quote = bundle.quote_bytes.clone();
    tampered_quote[12] ^= 0xFF;

    let options = AttestationOptions {
        expected_nonce: Some(bundle.nonce),
        golden_manifest: Some(bundle.golden_manifest),
    };

    let result = verify_attestation(
        &tampered_quote,
        bundle.cert_chain_pem.as_bytes(),
        bundle.root_ca_pem.as_bytes(),
        &options,
    );

    assert!(
        result.is_err(),
        "Tampered quote must fail cryptographic verification"
    );
}

#[test]
fn test_replay_attack_nonce_mismatch() {
    let bundle = generate_mock_bundle("NVIDIA-H100-SXM5").expect("generate mock bundle");

    let mut wrong_nonce = bundle.nonce;
    wrong_nonce[0] ^= 0x01; // flip 1 bit

    let options = AttestationOptions {
        expected_nonce: Some(wrong_nonce),
        golden_manifest: Some(bundle.golden_manifest),
    };

    let result = verify_attestation(
        &bundle.quote_bytes,
        bundle.cert_chain_pem.as_bytes(),
        bundle.root_ca_pem.as_bytes(),
        &options,
    );

    match result {
        Err(spdm_attest::verifier::AttestationError::NonceMismatch) => (),
        other => panic!("Expected NonceMismatch, got {:?}", other),
    }
}

#[test]
fn test_mismatched_golden_measurements() {
    let bundle = generate_mock_bundle("NVIDIA-H100-SXM5").expect("generate mock bundle");

    let mut tampered_golden = bundle.golden_manifest.clone();
    // Tamper with expected microcode hash
    tampered_golden.measurements[1].expected_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();

    let options = AttestationOptions {
        expected_nonce: Some(bundle.nonce),
        golden_manifest: Some(tampered_golden),
    };

    let report = verify_attestation(
        &bundle.quote_bytes,
        bundle.cert_chain_pem.as_bytes(),
        bundle.root_ca_pem.as_bytes(),
        &options,
    )
    .expect("verification should complete but report failed status");

    assert!(
        !report.success,
        "Attestation must fail when golden baseline doesn't match"
    );
    assert!(report.failure_reason.is_some());
    assert_eq!(report.comparisons[1].status, ComparisonStatus::Mismatch);
}

#[test]
fn test_untrusted_root_ca() {
    let bundle = generate_mock_bundle("NVIDIA-H100-SXM5").expect("generate mock bundle");
    let other_bundle = generate_mock_bundle("OTHER-PLATFORM").expect("generate other bundle");

    let options = AttestationOptions {
        expected_nonce: Some(bundle.nonce),
        golden_manifest: None,
    };

    let result = verify_attestation(
        &bundle.quote_bytes,
        bundle.cert_chain_pem.as_bytes(),
        other_bundle.root_ca_pem.as_bytes(), // Different untrusted Root CA
        &options,
    );

    assert!(result.is_err(), "Untrusted root CA must fail verification");
}

#[test]
fn test_spdm_wire_format_roundtrip() {
    let block = MeasurementBlock {
        index: 1,
        spec: DMTF_SPEC_MEASUREMENT,
        value_type: MEASUREMENT_TYPE_IMMUTABLE_ROM,
        value: vec![0x11, 0x22, 0x33, 0x44],
    };

    let header = SpdmHeader::new(SPDM_VERSION_1_2, CODE_MEASUREMENTS, 1, 0x01);
    let nonce = [0xAA; 32];
    let signature = vec![0xBB; 96];

    let response = MeasurementsResponse {
        header,
        number_of_blocks: 1,
        blocks: vec![block.clone()],
        nonce: Some(nonce),
        opaque_data: vec![0xCC, 0xDD],
        signature: signature.clone(),
    };

    let bytes = response.to_bytes();
    let parsed =
        MeasurementsResponse::parse(&bytes, ASYM_ALG_ECDSA_P384).expect("parse wire format");

    assert_eq!(parsed.header.version, SPDM_VERSION_1_2);
    assert_eq!(parsed.header.code, CODE_MEASUREMENTS);
    assert_eq!(parsed.blocks.len(), 1);
    assert_eq!(parsed.blocks[0], block);
    assert_eq!(parsed.nonce, Some(nonce));
    assert_eq!(parsed.opaque_data, vec![0xCC, 0xDD]);
    assert_eq!(parsed.signature, signature);
}

#[test]
fn test_ed25519_quote_signature() {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let block = MeasurementBlock {
        index: 1,
        spec: DMTF_SPEC_MEASUREMENT,
        value_type: MEASUREMENT_TYPE_IMMUTABLE_ROM,
        value: sha256_digest(b"TEST_ROM"),
    };

    let header = SpdmHeader::new(SPDM_VERSION_1_2, CODE_MEASUREMENTS, 1, 0x01);
    let mut response = MeasurementsResponse {
        header,
        number_of_blocks: 1,
        blocks: vec![block],
        nonce: Some([0x55; 32]),
        opaque_data: vec![],
        signature: vec![],
    };

    let transcript = response.signed_transcript();
    let sig = signing_key.sign(&transcript);
    response.signature = sig.to_bytes().to_vec();

    let device_pubkey = DevicePublicKey::Ed25519(verifying_key);
    assert_eq!(device_pubkey.asym_algo(), ASYM_ALG_ED25519);

    assert!(device_pubkey
        .verify_signature(&transcript, &response.signature)
        .is_ok());

    // Verify negative tampering
    let mut bad_transcript = transcript.clone();
    bad_transcript[0] ^= 0x01;
    assert!(device_pubkey
        .verify_signature(&bad_transcript, &response.signature)
        .is_err());
}
