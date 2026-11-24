//! `spdm-attest`: Hardware-rooted PCIe SPDM 1.2/1.3 attestation quote and measurement validator.

use clap::{Parser, Subcommand};
use spdm_attest::{verify_attestation, AttestationOptions, GoldenManifest, MeasurementsResponse};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "spdm-attest",
    version = "0.1.0",
    about = "Hardware-rooted PCIe SPDM 1.2/1.3 attestation quote and measurement validator for Confidential GPU enclaves",
    long_about = "Verifies PCIe SPDM (Security Protocol and Data Model) responder certificate chains, \
                  NIST P-384 / Ed25519 measurement quote signatures, and golden PCR/firmware baselines \
                  before releasing KMS keys or loading model weights into GPU VRAM."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify an SPDM measurement quote against a cert chain, root CA, and golden manifest
    Verify {
        /// Path to binary SPDM quote file
        #[arg(short, long)]
        quote: PathBuf,

        /// Path to PEM/DER certificate chain file (Leaf -> Intermediate)
        #[arg(short, long)]
        cert_chain: PathBuf,

        /// Path to PEM/DER trusted manufacturer Root CA certificate
        #[arg(short, long)]
        root_ca: PathBuf,

        /// Optional 32-byte challenge nonce in hex format for replay protection
        #[arg(short, long)]
        nonce: Option<String>,

        /// Optional path to golden baseline measurement manifest (JSON)
        #[arg(short, long)]
        golden: Option<PathBuf>,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Inspect and decode an SPDM quote structure without cryptographic verification
    Inspect {
        /// Path to binary SPDM quote file
        #[arg(short, long)]
        quote: PathBuf,

        /// Expected asymmetric algorithm: p384 (default), p256, or ed25519
        #[arg(long, default_value = "p384")]
        algo: String,

        /// Output results as JSON
        #[arg(long)]
        json: bool,
    },

    /// Generate synthetic mock SPDM attestation evidence for CI/CD and testing
    MockGenerate {
        /// Directory where mock files will be generated
        #[arg(short, long, default_value = ".")]
        out_dir: PathBuf,

        /// Platform name to simulate
        #[arg(short, long, default_value = "NVIDIA-H100-SXM5-CC")]
        platform: String,
    },

    /// Extract measurements from a known-good quote and create a golden manifest
    GoldenCreate {
        /// Path to known-good binary SPDM quote file
        #[arg(short, long)]
        quote: PathBuf,

        /// Platform name (e.g., NVIDIA-H100, AMD-MI300X)
        #[arg(short, long)]
        platform: String,

        /// Firmware release version
        #[arg(short, long)]
        firmware_version: String,

        /// Path to output golden JSON file
        #[arg(short, long)]
        out: PathBuf,

        /// Expected asymmetric algorithm: p384 (default), p256, or ed25519
        #[arg(long, default_value = "p384")]
        algo: String,
    },
}

fn parse_nonce(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("Invalid hex nonce: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Nonce must be exactly 32 bytes (64 hex characters), got {} bytes",
            bytes.len()
        ));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

fn parse_algo(algo_str: &str) -> u32 {
    match algo_str.to_lowercase().as_str() {
        "p256" | "ecdsa-p256" => spdm_attest::protocol::ASYM_ALG_ECDSA_P256,
        "ed25519" => spdm_attest::protocol::ASYM_ALG_ED25519,
        _ => spdm_attest::protocol::ASYM_ALG_ECDSA_P384,
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify {
            quote,
            cert_chain,
            root_ca,
            nonce,
            golden,
            json,
        } => {
            let quote_bytes = match fs::read(&quote) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading quote file '{:?}': {}", quote, e);
                    return ExitCode::FAILURE;
                }
            };

            let cert_chain_bytes = match fs::read(&cert_chain) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading cert chain file '{:?}': {}", cert_chain, e);
                    return ExitCode::FAILURE;
                }
            };

            let root_ca_bytes = match fs::read(&root_ca) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading Root CA file '{:?}': {}", root_ca, e);
                    return ExitCode::FAILURE;
                }
            };

            let mut options = AttestationOptions::default();

            if let Some(n_str) = nonce {
                match parse_nonce(&n_str) {
                    Ok(n) => options.expected_nonce = Some(n),
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        return ExitCode::FAILURE;
                    }
                }
            }

            if let Some(g_path) = golden {
                match fs::read_to_string(&g_path) {
                    Ok(content) => match GoldenManifest::from_json(&content) {
                        Ok(manifest) => options.golden_manifest = Some(manifest),
                        Err(e) => {
                            eprintln!("Error parsing golden manifest '{:?}': {}", g_path, e);
                            return ExitCode::FAILURE;
                        }
                    },
                    Err(e) => {
                        eprintln!("Error reading golden manifest '{:?}': {}", g_path, e);
                        return ExitCode::FAILURE;
                    }
                }
            }

            match verify_attestation(&quote_bytes, &cert_chain_bytes, &root_ca_bytes, &options) {
                Ok(report) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    } else {
                        println!("============================================================");
                        println!(" 🛡️  SPDM Hardware Attestation Report");
                        println!("============================================================");
                        println!(
                            "Attestation Status : {}",
                            if report.success { "PASSED" } else { "FAILED" }
                        );
                        println!("SPDM Version       : {}", report.spdm_version);
                        println!("Responder Algo     : {}", report.responder_algo);
                        println!("Cert Chain Verified: {}", report.cert_chain_verified);
                        println!("Signature Verified : {}", report.signature_verified);
                        println!(
                            "Replay Check (Nonce): {}",
                            if report.nonce_verified {
                                "PASSED"
                            } else {
                                "SKIPPED/UNVERIFIED"
                            }
                        );
                        println!("Total Blocks       : {}", report.total_blocks);
                        println!("------------------------------------------------------------");
                        println!("Hardware Measurements:");
                        for comp in &report.comparisons {
                            let status_icon = match comp.status {
                                spdm_attest::ComparisonStatus::Match => "✅ MATCH",
                                spdm_attest::ComparisonStatus::Mismatch => "❌ MISMATCH",
                                spdm_attest::ComparisonStatus::Unexpected => "⚠️  UNEXPECTED",
                                spdm_attest::ComparisonStatus::Missing => "❓ MISSING",
                            };
                            println!(
                                "  [Block {}] {:<30} : {}",
                                comp.index, comp.component, status_icon
                            );
                            println!("    Digest: {}", comp.actual_hash);
                            if let Some(ref exp) = comp.expected_hash {
                                if comp.status != spdm_attest::ComparisonStatus::Match {
                                    println!("    Expected: {}", exp);
                                }
                            }
                        }
                        println!("============================================================");

                        if let Some(ref err) = report.failure_reason {
                            eprintln!("Failure reason: {}", err);
                        }
                    }

                    if report.success {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    eprintln!("❌ Attestation Verification Failed: {}", e);
                    ExitCode::FAILURE
                }
            }
        }

        Commands::Inspect { quote, algo, json } => {
            let quote_bytes = match fs::read(&quote) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading quote file '{:?}': {}", quote, e);
                    return ExitCode::FAILURE;
                }
            };

            let asym_algo = parse_algo(&algo);
            match MeasurementsResponse::parse(&quote_bytes, asym_algo) {
                Ok(resp) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                    } else {
                        println!("============================================================");
                        println!(" 🔍 SPDM Quote Inspection");
                        println!("============================================================");
                        println!("SPDM Version      : {:#04x}", resp.header.version);
                        println!(
                            "Message Code      : {:#04x} (MEASUREMENTS)",
                            resp.header.code
                        );
                        println!("Param1 / Blocks   : {}", resp.header.param1);
                        println!(
                            "Param2 / Flags    : {:#04x} (Signature Requested: {})",
                            resp.header.param2,
                            (resp.header.param2 & 0x01) != 0
                        );
                        if let Some(n) = resp.nonce {
                            println!("Nonce (32 bytes)  : {}", hex::encode(n));
                        } else {
                            println!("Nonce             : None");
                        }
                        println!("Opaque Data (len) : {} bytes", resp.opaque_data.len());
                        println!("Signature (len)   : {} bytes", resp.signature.len());
                        println!("------------------------------------------------------------");
                        println!("Measurement Records ({} blocks):", resp.blocks.len());
                        for b in &resp.blocks {
                            println!(
                                "  [Block {}] Type: {:#04x} ({})",
                                b.index,
                                b.value_type,
                                b.type_name()
                            );
                            println!(
                                "    Digest ({} bytes): {}",
                                b.value.len(),
                                hex::encode(&b.value)
                            );
                        }
                        println!("============================================================");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Failed to parse SPDM quote: {}", e);
                    ExitCode::FAILURE
                }
            }
        }

        Commands::MockGenerate { out_dir, platform } => {
            if let Err(e) = fs::create_dir_all(&out_dir) {
                eprintln!("Error creating output directory '{:?}': {}", out_dir, e);
                return ExitCode::FAILURE;
            }

            match spdm_attest::mock::generate_mock_bundle(&platform) {
                Ok(bundle) => {
                    let root_ca_path = out_dir.join("root_ca.pem");
                    let chain_path = out_dir.join("cert_chain.pem");
                    let quote_path = out_dir.join("quote.bin");
                    let nonce_path = out_dir.join("nonce.hex");
                    let golden_path = out_dir.join("golden.json");

                    fs::write(&root_ca_path, bundle.root_ca_pem).expect("write root_ca");
                    fs::write(&chain_path, bundle.cert_chain_pem).expect("write cert_chain");
                    fs::write(&quote_path, bundle.quote_bytes).expect("write quote");
                    fs::write(&nonce_path, hex::encode(bundle.nonce)).expect("write nonce");
                    fs::write(&golden_path, bundle.golden_manifest.to_json().unwrap())
                        .expect("write golden");

                    println!(
                        "✅ Generated synthetic SPDM attestation evidence for {}:",
                        platform
                    );
                    println!("  Root CA Cert      : {:?}", root_ca_path);
                    println!("  Device Cert Chain : {:?}", chain_path);
                    println!("  SPDM Quote (P-384): {:?}", quote_path);
                    println!("  Challenge Nonce   : {:?}", nonce_path);
                    println!("  Golden Baseline   : {:?}", golden_path);
                    println!("\nYou can verify this immediately with:");
                    println!("  spdm-attest verify --quote {:?} --cert-chain {:?} --root-ca {:?} --nonce $(cat {:?}) --golden {:?}",
                        quote_path, chain_path, root_ca_path, nonce_path, golden_path);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Failed to generate mock bundle: {}", e);
                    ExitCode::FAILURE
                }
            }
        }

        Commands::GoldenCreate {
            quote,
            platform,
            firmware_version,
            out,
            algo,
        } => {
            let quote_bytes = match fs::read(&quote) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Error reading quote file '{:?}': {}", quote, e);
                    return ExitCode::FAILURE;
                }
            };

            let asym_algo = parse_algo(&algo);
            match MeasurementsResponse::parse(&quote_bytes, asym_algo) {
                Ok(resp) => {
                    let mut manifest = GoldenManifest::new(platform, firmware_version);
                    for b in &resp.blocks {
                        manifest.add_measurement(
                            b.index,
                            b.type_name(),
                            format!("Measurement block {} from quote", b.index),
                            hex::encode(&b.value),
                        );
                    }

                    let json = manifest.to_json().expect("serialize golden");
                    if let Err(e) = fs::write(&out, json) {
                        eprintln!("Error writing golden manifest to '{:?}': {}", out, e);
                        return ExitCode::FAILURE;
                    }

                    println!(
                        "✅ Created golden manifest with {} measurements at {:?}",
                        resp.blocks.len(),
                        out
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Failed to parse SPDM quote: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
    }
}
