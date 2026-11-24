//! `spdm-attest`: Hardware-rooted PCIe SPDM 1.2/1.3 attestation quote and measurement validator.

pub mod crypto;
pub mod measurement;
pub mod mock;
pub mod protocol;
pub mod verifier;

pub use measurement::{
    compare_measurements, ComparisonStatus, GoldenManifest, MeasurementComparison,
};
pub use protocol::{MeasurementBlock, MeasurementsResponse, SpdmHeader};
pub use verifier::{verify_attestation, AttestationOptions, AttestationReport};
