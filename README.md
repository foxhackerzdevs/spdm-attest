# 🛡️ spdm-attest

[![CI](https://github.com/foxhackerzdevs/spdm-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/foxhackerzdevs/spdm-attest/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/spdm-attest.svg)](https://crates.io/crates/spdm-attest)
[![docs.rs](https://docs.rs/spdm-attest/badge.svg)](https://docs.rs/spdm-attest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Layer 1/2](https://img.shields.io/badge/Security-Layer%201%2F2%20Hardware%20Attestation-red.svg)](https://github.com/foxhackerzdevs)

**Hardware-rooted PCIe SPDM 1.2/1.3 measurement quote and responder certificate verifier for Confidential GPU enclaves.**

`spdm-attest` completes **Layer 1 & 2** of the **Fox Hackerz Sovereign AI Zero-Trust Stack**: validating PCIe SPDM (Security Protocol and Data Model) quotes, manufacturer DICE certificate chains (NVIDIA/AMD Root CAs), and golden firmware/VBIOS baselines before KMS keys are released or models loaded into VRAM.

---

## 🏛️ The Confidential GPU Attestation Gap

In modern sovereign AI infrastructure, multi-tenant GPU clusters (NVIDIA H100/H200/B200 Blackwell, AMD Instinct MI300X) run inside Confidential Computing environments:
1. **The Host Cannot Be Trusted:** Hypervisors and host OS environments are outside the tenant's security perimeter.
2. **Silicon Root-of-Trust Attestation:** Before an inference enclave or key management service (KMS) releases decryption keys, it must cryptographically challenge the GPU over PCIe DOE (Data Object Exchange) using DMTF SPDM.
3. **Firmware & Microcode Integrity:** A compromised VBIOS, downgraded microcode, or disabled Confidential Compute (CC) mode allows host snooping over PCIe/NVLink.

`spdm-attest` provides an auditable, zero-bloat Rust binary and library to parse and cryptographically verify SPDM measurement quotes and certificate chains.

```
+----------------------------------------------------------------------------------------------------+
|                               FOX HACKERZ ZERO-TRUST SOVEREIGN AI STACK                            |
+----------------------------------------------------------------------------------------------------+
|  Layer 4: Artifact Gate  | stverify     | Model weight (.safetensors) parallel Ed25519 signer/gate|
|  Layer 3: Fabric Guard   | enclave-xdp  | eBPF/XDP driver-level RoCEv2 (UDP/4791) & CIDR monitor   |
|  Layer 1/2: Attestation  | spdm-attest  | PCIe SPDM 1.2/1.3 quote, DICE cert chain & PCR baseline  |
+----------------------------------------------------------------------------------------------------+
```

---

## ✨ Features

- **DMTF SPDM 1.2 / 1.3 Wire-Format Parser:** Strict binary decoding of `MEASUREMENTS` responses, `MeasurementBlocks`, DMTF metric records, and nonces.
- **Cryptographic Quote Verification:** Supports NIST P-384 (`TPM_ALG_ECDSA_ECC_NIST_P384`), NIST P-256, and Ed25519 quote signatures.
- **X.509 / DICE Certificate Chain Validation:** Validates device identity certificates through intermediate CAs up to a trusted hardware manufacturer Root CA.
- **Replay Protection:** Enforces fresh 32-byte initiator challenge nonces to prevent recorded quote replays.
- **Golden Baseline Manifests:** Compares hardware metrics (Secure Boot ROM, GPU Microcode, PCIe Security Registers, VBIOS) against known-good JSON baselines.
- **Synthetic Evidence Generator:** Includes `mock-generate` to synthesize valid SPDM bundles for local testing and CI without needing physical $40,000 accelerators.
- **Structured JSON & Exit Codes:** Emits detailed reports with per-measurement verdicts, designed for scripting in KMS boot pre-hooks.

---

## 📦 Installation

### From crates.io
```bash
cargo install spdm-attest
```

### From Source
```bash
git clone https://github.com/foxhackerzdevs/spdm-attest.git
cd spdm-attest
cargo build --release
```

---

## ⚡ Quick Start

### 1. Generate Synthetic Mock Evidence (For Testing / CI)
```bash
spdm-attest mock-generate --out-dir ./evidence --platform "NVIDIA-H100-SXM5"
```
Generated artifacts:
- `root_ca.pem`: Manufacturer Root CA
- `cert_chain.pem`: SPDM responder certificate chain
- `quote.bin`: Raw binary SPDM quote (ECDSA P-384 signed)
- `nonce.hex`: Fresh 32-byte challenge nonce
- `golden.json`: Golden baseline manifest

### 2. Inspect SPDM Quote Structure
```bash
spdm-attest inspect --quote ./evidence/quote.bin
```

### 3. Verify Attestation Quote & Golden Measurements
```bash
spdm-attest verify \
  --quote ./evidence/quote.bin \
  --cert-chain ./evidence/cert_chain.pem \
  --root-ca ./evidence/root_ca.pem \
  --nonce $(cat ./evidence/nonce.hex) \
  --golden ./evidence/golden.json
```

**Output:**
```text
============================================================
 🛡️  SPDM Hardware Attestation Report
============================================================
Attestation Status : PASSED
SPDM Version       : 0x12
Responder Algo     : ECDSA-NIST-P384
Cert Chain Verified: true
Signature Verified : true
Replay Check (Nonce): PASSED
Total Blocks       : 4
------------------------------------------------------------
Hardware Measurements:
  [Block 1] Secure Boot ROM                : ✅ MATCH
    Digest: d24c0b7550ae4bcb3af423e428be3af4ffdadc6bf3a8b29fe35e2024e5bf73739f67779005c31a1520d08fea83b12657
  [Block 2] GPU Microcode                  : ✅ MATCH
    Digest: 176b87d0d9464b40c29aa2818b4407be4dbddb32c416a7ed47200afff11061fef13a22ccd745ddf5ee266f4f638593a6
  [Block 3] Hardware Security Config       : ✅ MATCH
    Digest: 9e8f95dfee3064066f175fb512552c25f439b7a200ef65773e65af6403e9728df133f87d4be21de045fee0f85a6fb422
  [Block 4] VBIOS Firmware                 : ✅ MATCH
    Digest: 700d58c7e0d76385c0bf5b97dd261cc6adba6a06739e53ef73c08ad4b7f80933e1a2e8e4530b50538f41bec78d5940f5
============================================================
```

### 4. Machine-Readable JSON Output (for KMS Hook Scripts)
```bash
spdm-attest verify --quote ./evidence/quote.bin \
  --cert-chain ./evidence/cert_chain.pem \
  --root-ca ./evidence/root_ca.pem \
  --nonce $(cat ./evidence/nonce.hex) \
  --golden ./evidence/golden.json \
  --json
```

---

## 🛡️ Integration in KMS Boot Hook

In a Kubernetes or Confidential Virtual Machine (CVM) boot sequence, `spdm-attest` gates the retrieval of the model decryption key:

```bash
#!/bin/bash
set -euo pipefail

# 1. Challenge GPU over PCIe DOE
NONCE=$(openssl rand -hex 32)
spdm-tool challenge --nonce "$NONCE" --out-quote /tmp/quote.bin

# 2. Verify SPDM quote and firmware baseline
if ! spdm-attest verify \
    --quote /tmp/quote.bin \
    --cert-chain /etc/spdm/device_chain.pem \
    --root-ca /etc/spdm/nvidia_root_ca.pem \
    --nonce "$NONCE" \
    --golden /etc/spdm/golden_h100.json; then
  echo "CRITICAL: GPU hardware attestation failed! Aborting key release."
  exit 1
fi

# 3. Request KMS model decryption key
curl -s -X POST https://kms.internal/v1/unwrap-key \
  --data-binary "@/tmp/quote.bin" \
  -o /run/secrets/model_key.bin

echo "Hardware attested. Model key released."
```

---

## 🛠️ Rust Library Usage

```rust
use spdm_attest::{verify_attestation, AttestationOptions, GoldenManifest};

let quote_bytes = std::fs::read("quote.bin")?;
let chain_bytes = std::fs::read("cert_chain.pem")?;
let root_ca_bytes = std::fs::read("root_ca.pem")?;

let options = AttestationOptions {
    expected_nonce: Some(my_challenge_nonce),
    golden_manifest: Some(golden_manifest),
};

let report = verify_attestation(
    &quote_bytes,
    &chain_bytes,
    &root_ca_bytes,
    &options,
)?;

if report.success {
    println!("Hardware verified: {}", report.responder_algo);
}
```

---

## 📄 License

MIT License. Designed and maintained by [Fox Hackerz](https://github.com/foxhackerzdevs).
