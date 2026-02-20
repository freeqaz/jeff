use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::{
    analysis::cfa::{AnalyzerState, SectionAddress},
    obj::{ObjInfo, ObjSectionKind, ObjSymbolKind},
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
pub struct SeedDiscoveryOutput {
    pub seeds: Vec<FunctionSeed>,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct SliceExplorationOutput {
    pub processed_seed_count: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct FinalizationOutput {
    pub function_count: usize,
    pub jump_table_count: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ApplyOutput {
    pub function_symbol_count: usize,
    pub jump_table_symbol_count: usize,
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

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PipelineRunReport {
    pub seed_discovery: SeedDiscoveryOutput,
    pub slice_exploration: SliceExplorationOutput,
    pub finalization: FinalizationOutput,
    pub digest: PipelineDigest,
}

pub trait CfaPipelineEngine {
    fn phase_seed_discovery(&mut self, obj: &ObjInfo) -> Result<SeedDiscoveryOutput>;

    fn phase_slice_exploration(
        &mut self,
        obj: &ObjInfo,
        seed: &SeedDiscoveryOutput,
    ) -> Result<SliceExplorationOutput>;

    fn phase_finalization(&mut self, obj: &ObjInfo) -> Result<FinalizationOutput>;

    fn phase_apply(&self, obj: &mut ObjInfo) -> Result<ApplyOutput>;

    fn digest(&self) -> PipelineDigest;

    fn run_with_report(&mut self, obj: &ObjInfo) -> Result<PipelineRunReport> {
        let seed_discovery = self.phase_seed_discovery(obj)?;
        let slice_exploration = self.phase_slice_exploration(obj, &seed_discovery)?;
        let finalization = self.phase_finalization(obj)?;
        let digest = self.digest();
        Ok(PipelineRunReport { seed_discovery, slice_exploration, finalization, digest })
    }

    fn run(&mut self, obj: &ObjInfo) -> Result<PipelineDigest> {
        Ok(self.run_with_report(obj)?.digest)
    }
}

pub struct LegacyPipelineEngine {
    pub state: AnalyzerState,
}

impl LegacyPipelineEngine {
    pub fn new(skip_ranges: BTreeMap<SectionAddress, SectionAddress>) -> Self {
        Self { state: AnalyzerState::new(skip_ranges) }
    }

    fn classify_seed_source(obj: &ObjInfo, address: SectionAddress) -> SeedSource {
        if obj.known_functions.contains_key(&address) {
            return SeedSource::KnownFunction;
        }
        if obj
            .symbols
            .kind_at_section_address(address.section, address.address, ObjSymbolKind::Function)
            .ok()
            .flatten()
            .is_some()
        {
            return SeedSource::Symbol;
        }
        if matches!(
            obj.sections.get(address.section),
            Some(section)
                if section.kind == ObjSectionKind::Code && section.address as u32 == address.address
        ) {
            return SeedSource::SectionStart;
        }
        SeedSource::Discovered
    }
}

impl CfaPipelineEngine for LegacyPipelineEngine {
    fn phase_seed_discovery(&mut self, obj: &ObjInfo) -> Result<SeedDiscoveryOutput> {
        let seeds = self
            .state
            .phase_seed_discovery(obj)?
            .into_iter()
            .map(|address| FunctionSeed {
                address,
                source: Self::classify_seed_source(obj, address),
            })
            .collect();
        Ok(SeedDiscoveryOutput { seeds })
    }

    fn phase_slice_exploration(
        &mut self,
        obj: &ObjInfo,
        seed: &SeedDiscoveryOutput,
    ) -> Result<SliceExplorationOutput> {
        let seed_addrs = seed.seeds.iter().map(|entry| entry.address).collect::<Vec<_>>();
        self.state.phase_slice_seeded_functions(obj, &seed_addrs)?;
        Ok(SliceExplorationOutput { processed_seed_count: seed_addrs.len() })
    }

    fn phase_finalization(&mut self, obj: &ObjInfo) -> Result<FinalizationOutput> {
        self.state.phase_discover_remaining_functions(obj)?;
        self.state.phase_finalize_and_validate(obj)?;
        Ok(FinalizationOutput {
            function_count: self.state.functions.len(),
            jump_table_count: self.state.jump_tables.len(),
        })
    }

    fn phase_apply(&self, obj: &mut ObjInfo) -> Result<ApplyOutput> {
        let function_symbol_count =
            self.state.functions.values().filter(|info| info.end.is_some()).count();
        let jump_table_symbol_count = self.state.jump_tables.len();
        self.state.apply(obj)?;
        Ok(ApplyOutput { function_symbol_count, jump_table_symbol_count })
    }

    fn digest(&self) -> PipelineDigest {
        PipelineDigest::from_state(&self.state)
    }
}

#[cfg(test)]
fn make_code_section(base_addr: u32, instructions: &[u32]) -> crate::obj::ObjSection {
    let data: Vec<u8> = instructions.iter().flat_map(|w| w.to_be_bytes()).collect();
    crate::obj::ObjSection {
        name: ".text".into(),
        kind: ObjSectionKind::Code,
        address: base_addr as u64,
        size: data.len() as u64,
        data,
        align: 4,
        ..Default::default()
    }
}

#[cfg(test)]
fn make_obj(base_addr: u32, instructions: &[u32]) -> ObjInfo {
    ObjInfo::new(
        crate::obj::ObjKind::Executable,
        crate::obj::ObjArchitecture::PowerPc,
        "pipeline-shadow-test".into(),
        vec![],
        vec![make_code_section(base_addr, instructions)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOP: u32 = 0x60000000;
    const BLR: u32 = 0x4E800020;

    #[test]
    fn pipeline_digest_diff_is_empty_for_identical_inputs() {
        let mut left = PipelineDigest::default();
        left.functions.insert(SectionAddress::new(0, 0x1000), Some(SectionAddress::new(0, 0x1020)));
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
        left.functions.insert(SectionAddress::new(0, 0x1000), Some(SectionAddress::new(0, 0x1020)));
        left.jump_tables.insert(SectionAddress::new(0, 0x2000), 0x30);

        let mut right = PipelineDigest::default();
        right
            .functions
            .insert(SectionAddress::new(0, 0x1000), Some(SectionAddress::new(0, 0x101C)));
        right.jump_tables.insert(SectionAddress::new(0, 0x2000), 0x40);

        let diffs = left.diff(&right);
        assert_eq!(diffs.len(), 2, "expected one function and one jump-table delta");
    }

    #[test]
    fn seed_phase_reports_known_function_source() {
        let mut obj = make_obj(0x1000, &[NOP, BLR, NOP, NOP]);
        let known = SectionAddress::new(0, 0x1000);
        obj.known_functions.insert(known, Some(8));

        let mut engine = LegacyPipelineEngine::new(BTreeMap::new());
        let seed = engine
            .phase_seed_discovery(&obj)
            .expect("seed phase should succeed for known function");
        assert!(
            seed.seeds
                .iter()
                .any(|entry| entry.address == known && entry.source == SeedSource::KnownFunction),
            "known function seed should preserve provenance"
        );
    }

    #[test]
    fn legacy_pipeline_run_matches_manual_phase_sequence() {
        let mut obj = make_obj(0x1000, &[NOP, BLR]);
        obj.known_functions.insert(SectionAddress::new(0, 0x1000), Some(8));

        let mut manual = LegacyPipelineEngine::new(BTreeMap::new());
        let seed = manual.phase_seed_discovery(&obj).expect("manual seed phase should succeed");
        manual.phase_slice_exploration(&obj, &seed).expect("manual slice phase should succeed");
        manual.phase_finalization(&obj).expect("manual finalization should succeed");
        let manual_digest = manual.digest();

        let mut engine = LegacyPipelineEngine::new(BTreeMap::new());
        let pipeline_digest = engine.run(&obj).expect("pipeline run should succeed");
        let diffs = manual_digest.diff(&pipeline_digest);
        assert!(
            diffs.is_empty(),
            "pipeline run should match manual phase execution, diffs: {diffs:?}"
        );
    }
}
