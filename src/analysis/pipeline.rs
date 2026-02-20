use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::{
    analysis::cfa::{AnalyzerState, SectionAddress},
    obj::ObjInfo,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SeedSource {
    KnownFunction,
    Symbol,
    SectionStart,
    Discovered,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FunctionSeed {
    pub address: SectionAddress,
    pub source: SeedSource,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PipelineDigest {
    pub functions: BTreeMap<SectionAddress, Option<SectionAddress>>,
    pub jump_tables: BTreeMap<SectionAddress, u32>,
}

impl PipelineDigest {
    pub fn from_state(state: &AnalyzerState) -> Self {
        Self {
            functions: state.functions.iter().map(|(&addr, info)| (addr, info.end)).collect(),
            jump_tables: state.jump_tables.clone(),
        }
    }

    pub fn diff(&self, other: &Self) -> Vec<String> {
        let mut diffs = Vec::new();

        let function_keys =
            self.functions.keys().chain(other.functions.keys()).copied().collect::<BTreeSet<_>>();
        for key in function_keys {
            let left = self.functions.get(&key);
            let right = other.functions.get(&key);
            if left != right {
                diffs.push(format!(
                    "function mismatch at {key}: left {:?}, right {:?}",
                    left, right
                ));
            }
        }

        let jump_keys = self
            .jump_tables
            .keys()
            .chain(other.jump_tables.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for key in jump_keys {
            let left = self.jump_tables.get(&key);
            let right = other.jump_tables.get(&key);
            if left != right {
                diffs.push(format!(
                    "jump-table mismatch at {key}: left {:?}, right {:?}",
                    left, right
                ));
            }
        }

        diffs
    }
}

pub trait CfaPipelineEngine {
    fn run(&mut self, obj: &ObjInfo) -> Result<PipelineDigest>;
}

pub struct LegacyPipelineEngine {
    pub state: AnalyzerState,
}

impl LegacyPipelineEngine {
    pub fn new(skip_ranges: BTreeMap<SectionAddress, SectionAddress>) -> Self {
        Self { state: AnalyzerState::new(skip_ranges) }
    }
}

impl CfaPipelineEngine for LegacyPipelineEngine {
    fn run(&mut self, obj: &ObjInfo) -> Result<PipelineDigest> {
        self.state.detect_functions(obj)?;
        self.state.validate_invariants(obj)?;
        Ok(PipelineDigest::from_state(&self.state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_digest_diff_is_empty_for_identical_inputs() {
        let mut left = PipelineDigest::default();
        left.functions
            .insert(SectionAddress::new(0, 0x1000), Some(SectionAddress::new(0, 0x1020)));
        left.jump_tables.insert(SectionAddress::new(0, 0x2000), 0x30);

        let mut right = PipelineDigest::default();
        right
            .functions
            .insert(SectionAddress::new(0, 0x1000), Some(SectionAddress::new(0, 0x1020)));
        right.jump_tables.insert(SectionAddress::new(0, 0x2000), 0x30);

        assert!(left.diff(&right).is_empty());
    }

    #[test]
    fn pipeline_digest_diff_reports_function_and_jump_table_deltas() {
        let mut left = PipelineDigest::default();
        left.functions
            .insert(SectionAddress::new(0, 0x1000), Some(SectionAddress::new(0, 0x1020)));
        left.jump_tables.insert(SectionAddress::new(0, 0x2000), 0x30);

        let mut right = PipelineDigest::default();
        right
            .functions
            .insert(SectionAddress::new(0, 0x1000), Some(SectionAddress::new(0, 0x101C)));
        right.jump_tables.insert(SectionAddress::new(0, 0x2000), 0x40);

        let diffs = left.diff(&right);
        assert_eq!(diffs.len(), 2, "expected one function and one jump-table delta");
    }
}
