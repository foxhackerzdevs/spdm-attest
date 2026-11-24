//! SPDM 1.2 / 1.3 Wire-Format Protocol Definitions and Serialization.
//!
//! Conforms to DMTF DSP0274 (Security Protocol and Data Model Specification).

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SPDM_VERSION_1_0: u8 = 0x10;
pub const SPDM_VERSION_1_1: u8 = 0x11;
pub const SPDM_VERSION_1_2: u8 = 0x12;
pub const SPDM_VERSION_1_3: u8 = 0x13;

pub const CODE_GET_VERSION: u8 = 0x84;
pub const CODE_VERSION: u8 = 0x04;
pub const CODE_GET_CAPABILITIES: u8 = 0xE1;
pub const CODE_CAPABILITIES: u8 = 0x61;
pub const CODE_NEGOTIATE_ALGORITHMS: u8 = 0xE3;
pub const CODE_ALGORITHMS: u8 = 0x63;
pub const CODE_GET_DIGESTS: u8 = 0x81;
pub const CODE_DIGESTS: u8 = 0x01;
pub const CODE_GET_CERTIFICATE: u8 = 0x82;
pub const CODE_CERTIFICATE: u8 = 0x02;
pub const CODE_CHALLENGE: u8 = 0x83;
pub const CODE_CHALLENGE_AUTH: u8 = 0x03;
pub const CODE_GET_MEASUREMENTS: u8 = 0xE0;
pub const CODE_MEASUREMENTS: u8 = 0x60;
pub const CODE_ERROR: u8 = 0x7F;

pub const HASH_ALG_SHA_256: u32 = 0x00000001;
pub const HASH_ALG_SHA_384: u32 = 0x00000002;
pub const HASH_ALG_SHA_512: u32 = 0x00000004;

pub const ASYM_ALG_ECDSA_P256: u32 = 0x00000001;
pub const ASYM_ALG_ECDSA_P384: u32 = 0x00000002;
pub const ASYM_ALG_ED25519: u32 = 0x00000040;

pub const DMTF_SPEC_MEASUREMENT: u8 = 0x01;

pub const MEASUREMENT_TYPE_IMMUTABLE_ROM: u8 = 0x01;
pub const MEASUREMENT_TYPE_MUTABLE_FIRMWARE: u8 = 0x02;
pub const MEASUREMENT_TYPE_HARDWARE_CONFIG: u8 = 0x03;
pub const MEASUREMENT_TYPE_FIRMWARE_CONFIG: u8 = 0x04;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Buffer too short: expected at least {expected} bytes, got {actual}")]
    BufferTooShort { expected: usize, actual: usize },

    #[error("Invalid SPDM header: version {version:#04x}, code {code:#04x}")]
    InvalidHeader { version: u8, code: u8 },

    #[error("Unsupported SPDM version: {0:#04x}")]
    UnsupportedVersion(u8),

    #[error("Unsupported hash algorithm: {0:#010x}")]
    UnsupportedHashAlgorithm(u32),

    #[error("Unsupported asymmetric algorithm: {0:#010x}")]
    UnsupportedAsymAlgorithm(u32),

    #[error("Malformed measurement block: {0}")]
    MalformedMeasurementBlock(String),

    #[error("Measurement record length mismatch: declared {declared}, parsed {parsed}")]
    MeasurementLengthMismatch { declared: usize, parsed: usize },

    #[error("Invalid signature length: {0}")]
    InvalidSignatureLength(usize),
}

/// Standard SPDM 4-byte message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpdmHeader {
    pub version: u8,
    pub code: u8,
    pub param1: u8,
    pub param2: u8,
}

impl SpdmHeader {
    pub const SIZE: usize = 4;

    pub fn new(version: u8, code: u8, param1: u8, param2: u8) -> Self {
        Self {
            version,
            code,
            param1,
            param2,
        }
    }

    pub fn parse(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < Self::SIZE {
            return Err(ProtocolError::BufferTooShort {
                expected: Self::SIZE,
                actual: buf.len(),
            });
        }
        Ok(Self {
            version: buf[0],
            code: buf[1],
            param1: buf[2],
            param2: buf[3],
        })
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.version);
        buf.push(self.code);
        buf.push(self.param1);
        buf.push(self.param2);
    }
}

/// DMTF Measurement Block representing a hardware or firmware metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementBlock {
    pub index: u8,
    pub spec: u8,
    pub value_type: u8,
    pub value: Vec<u8>,
}

impl MeasurementBlock {
    pub fn type_name(&self) -> &'static str {
        match self.value_type & 0x7F {
            MEASUREMENT_TYPE_IMMUTABLE_ROM => "Immutable Secure Boot ROM",
            MEASUREMENT_TYPE_MUTABLE_FIRMWARE => "Mutable Firmware / Microcode",
            MEASUREMENT_TYPE_HARDWARE_CONFIG => "Hardware Config / Security Registers",
            MEASUREMENT_TYPE_FIRMWARE_CONFIG => "Firmware Config / VBIOS",
            _ => "Unknown / Vendor-Defined",
        }
    }

    pub fn is_raw_bitstream(&self) -> bool {
        (self.value_type & 0x80) != 0
    }

    pub fn parse(buf: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if buf.len() < 4 {
            return Err(ProtocolError::BufferTooShort {
                expected: 4,
                actual: buf.len(),
            });
        }
        let index = buf[0];
        let spec = buf[1];
        let measurement_size = u16::from_le_bytes([buf[2], buf[3]]) as usize;

        if buf.len() < 4 + measurement_size {
            return Err(ProtocolError::BufferTooShort {
                expected: 4 + measurement_size,
                actual: buf.len(),
            });
        }

        let inner = &buf[4..4 + measurement_size];
        if spec == DMTF_SPEC_MEASUREMENT {
            if inner.len() < 3 {
                return Err(ProtocolError::MalformedMeasurementBlock(
                    "DMTF measurement payload too short".to_string(),
                ));
            }
            let value_type = inner[0];
            let val_size = u16::from_le_bytes([inner[1], inner[2]]) as usize;
            if inner.len() < 3 + val_size {
                return Err(ProtocolError::MalformedMeasurementBlock(
                    "DMTF measurement value length overflow".to_string(),
                ));
            }
            let value = inner[3..3 + val_size].to_vec();
            Ok((
                Self {
                    index,
                    spec,
                    value_type,
                    value,
                },
                4 + measurement_size,
            ))
        } else {
            Ok((
                Self {
                    index,
                    spec,
                    value_type: 0,
                    value: inner.to_vec(),
                },
                4 + measurement_size,
            ))
        }
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        buf.push(self.index);
        buf.push(self.spec);

        if self.spec == DMTF_SPEC_MEASUREMENT {
            let inner_size = (3 + self.value.len()) as u16;
            buf.extend_from_slice(&inner_size.to_le_bytes());
            buf.push(self.value_type);
            let val_size = self.value.len() as u16;
            buf.extend_from_slice(&val_size.to_le_bytes());
            buf.extend_from_slice(&self.value);
        } else {
            let inner_size = self.value.len() as u16;
            buf.extend_from_slice(&inner_size.to_le_bytes());
            buf.extend_from_slice(&self.value);
        }
    }
}

/// An SPDM MEASUREMENTS response containing hardware metrics, nonce, and signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementsResponse {
    pub header: SpdmHeader,
    pub number_of_blocks: u8,
    pub blocks: Vec<MeasurementBlock>,
    pub nonce: Option<[u8; 32]>,
    pub opaque_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl MeasurementsResponse {
    pub fn parse(buf: &[u8], asym_algo: u32) -> Result<Self, ProtocolError> {
        if buf.len() < 8 {
            return Err(ProtocolError::BufferTooShort {
                expected: 8,
                actual: buf.len(),
            });
        }

        let header = SpdmHeader::parse(buf)?;
        if header.code != CODE_MEASUREMENTS {
            return Err(ProtocolError::InvalidHeader {
                version: header.version,
                code: header.code,
            });
        }

        let number_of_blocks = header.param1;
        let sig_requested = (header.param2 & 0x01) != 0;

        // Record length is 24-bit little endian in bytes 4..7
        let record_len = (buf[4] as usize) | ((buf[5] as usize) << 8) | ((buf[6] as usize) << 16);
        let mut offset = 8;

        if buf.len() < offset + record_len {
            return Err(ProtocolError::BufferTooShort {
                expected: offset + record_len,
                actual: buf.len(),
            });
        }

        let record_end = offset + record_len;
        let mut blocks = Vec::new();

        while offset < record_end {
            let (block, consumed) = MeasurementBlock::parse(&buf[offset..record_end])?;
            blocks.push(block);
            offset += consumed;
        }

        let mut nonce = None;
        let mut opaque_data = Vec::new();
        let mut signature = Vec::new();

        if sig_requested {
            if buf.len() < offset + 32 {
                return Err(ProtocolError::BufferTooShort {
                    expected: offset + 32,
                    actual: buf.len(),
                });
            }
            let mut n = [0u8; 32];
            n.copy_from_slice(&buf[offset..offset + 32]);
            nonce = Some(n);
            offset += 32;

            if buf.len() < offset + 2 {
                return Err(ProtocolError::BufferTooShort {
                    expected: offset + 2,
                    actual: buf.len(),
                });
            }
            let opaque_len = u16::from_le_bytes([buf[offset], buf[offset + 1]]) as usize;
            offset += 2;

            if buf.len() < offset + opaque_len {
                return Err(ProtocolError::BufferTooShort {
                    expected: offset + opaque_len,
                    actual: buf.len(),
                });
            }
            opaque_data = buf[offset..offset + opaque_len].to_vec();
            offset += opaque_len;

            let expected_sig_len = match asym_algo {
                ASYM_ALG_ECDSA_P256 => 64,
                ASYM_ALG_ECDSA_P384 => 96,
                ASYM_ALG_ED25519 => 64,
                _ => return Err(ProtocolError::UnsupportedAsymAlgorithm(asym_algo)),
            };

            if buf.len() < offset + expected_sig_len {
                return Err(ProtocolError::BufferTooShort {
                    expected: offset + expected_sig_len,
                    actual: buf.len(),
                });
            }
            signature = buf[offset..offset + expected_sig_len].to_vec();
        }

        Ok(Self {
            header,
            number_of_blocks,
            blocks,
            nonce,
            opaque_data,
            signature,
        })
    }

    /// Serializes the response into raw SPDM binary format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut record_bytes = Vec::new();
        for b in &self.blocks {
            b.write_to(&mut record_bytes);
        }

        let record_len = record_bytes.len();
        let mut header = self.header;
        header.param1 = self.blocks.len() as u8;
        if self.nonce.is_some() && !self.signature.is_empty() {
            header.param2 |= 0x01;
        }

        header.write_to(&mut buf);
        // 24-bit record length + reserved byte
        buf.push((record_len & 0xFF) as u8);
        buf.push(((record_len >> 8) & 0xFF) as u8);
        buf.push(((record_len >> 16) & 0xFF) as u8);
        buf.push(0x00); // reserved

        buf.extend_from_slice(&record_bytes);

        if let Some(nonce) = self.nonce {
            buf.extend_from_slice(&nonce);
            let opaque_len = self.opaque_data.len() as u16;
            buf.extend_from_slice(&opaque_len.to_le_bytes());
            buf.extend_from_slice(&self.opaque_data);
            buf.extend_from_slice(&self.signature);
        }

        buf
    }

    /// Computes the transcript portion over which the signature is calculated (everything up to the signature).
    pub fn signed_transcript(&self) -> Vec<u8> {
        let full = self.to_bytes();
        let sig_len = self.signature.len();
        if full.len() >= sig_len {
            full[..full.len() - sig_len].to_vec()
        } else {
            full
        }
    }
}
