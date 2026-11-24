//! Measurement blocks, golden baseline manifests, and hardware metric comparison.

use crate::protocol::{
    MeasurementBlock, MEASUREMENT_TYPE_FIRMWARE_CONFIG, MEASUREMENT_TYPE_HARDWARE_CONFIG,
    MEASUREMENT_TYPE_IMMUTABLE_ROM, MEASUREMENT_TYPE_MUTABLE_FIRMWARE,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An expected golden measurement for a hardware component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedMeasurement {
    pub index: u8,
    pub component: String,
    pub description: String,
    pub expected_hash: String,
}

/// A golden baseline manifest defining the known-good measurements for a specific GPU/TEE platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoldenManifest {
    pub platform: String,
    pub firmware_version: String,
    pub measurements: Vec<ExpectedMeasurement>,
}

impl GoldenManifest {
    pub fn new(platform: impl Into<String>, firmware_version: impl Into<String>) -> Self {
        Self {
            platform: platform.into(),
            firmware_version: firmware_version.into(),
            measurements: Vec::new(),
        }
    }

    pub fn add_measurement(
        &mut self,
        index: u8,
        component: impl Into<String>,
        description: impl Into<String>,
        hash_hex: impl Into<String>,
    ) {
        self.measurements.push(ExpectedMeasurement {
            index,
            component: component.into(),
            description: description.into(),
            expected_hash: hash_hex.into().to_lowercase(),
        });
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

/// The result of comparing actual measurements against golden baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementComparison {
    pub index: u8,
    pub component: String,
    pub actual_hash: String,
    pub expected_hash: Option<String>,
    pub status: ComparisonStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonStatus {
    Match,
    Mismatch,
    Unexpected,
    Missing,
}

/// Compares actual SPDM measurement blocks against a golden manifest.
pub fn compare_measurements(
    actual_blocks: &[MeasurementBlock],
    golden: &GoldenManifest,
) -> Vec<MeasurementComparison> {
    let mut golden_map: HashMap<u8, &ExpectedMeasurement> = HashMap::new();
    for exp in &golden.measurements {
        golden_map.insert(exp.index, exp);
    }

    let mut seen_indices = std::collections::HashSet::new();
    let mut comparisons = Vec::new();

    for block in actual_blocks {
        seen_indices.insert(block.index);
        let actual_hex = hex::encode(&block.value).to_lowercase();

        if let Some(expected) = golden_map.get(&block.index) {
            let status = if actual_hex == expected.expected_hash.to_lowercase() {
                ComparisonStatus::Match
            } else {
                ComparisonStatus::Mismatch
            };

            comparisons.push(MeasurementComparison {
                index: block.index,
                component: expected.component.clone(),
                actual_hash: actual_hex,
                expected_hash: Some(expected.expected_hash.clone()),
                status,
            });
        } else {
            let default_name = match block.value_type & 0x7F {
                MEASUREMENT_TYPE_IMMUTABLE_ROM => "Immutable Boot ROM",
                MEASUREMENT_TYPE_MUTABLE_FIRMWARE => "Mutable Microcode",
                MEASUREMENT_TYPE_HARDWARE_CONFIG => "Security Hardware Config",
                MEASUREMENT_TYPE_FIRMWARE_CONFIG => "VBIOS Config",
                _ => "Unspecified Component",
            };

            comparisons.push(MeasurementComparison {
                index: block.index,
                component: format!("{} (Block {})", default_name, block.index),
                actual_hash: actual_hex,
                expected_hash: None,
                status: ComparisonStatus::Unexpected,
            });
        }
    }

    // Check for missing expected measurements
    for exp in &golden.measurements {
        if !seen_indices.contains(&exp.index) {
            comparisons.push(MeasurementComparison {
                index: exp.index,
                component: exp.component.clone(),
                actual_hash: String::new(),
                expected_hash: Some(exp.expected_hash.clone()),
                status: ComparisonStatus::Missing,
            });
        }
    }

    comparisons.sort_by_key(|c| c.index);
    comparisons
}
