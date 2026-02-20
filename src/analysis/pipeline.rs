use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;

use crate::{
    analysis::cfa::{AnalyzerState, FunctionInfo, SectionAddress},
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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PipelineDiffKind {
    FunctionPresence,
    FunctionEnd,
    JumpTablePresence,
    JumpTableSize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PipelineDiffEntry {
    pub kind: PipelineDiffKind,
    pub address: SectionAddress,
    pub left: String,
    pub right: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PipelineDiffSummary {
    pub function_presence: usize,
    pub function_end: usize,
    pub jump_table_presence: usize,
    pub jump_table_size: usize,
}

impl PipelineDiffSummary {
    pub fn total(&self) -> usize {
        self.function_presence + self.function_end + self.jump_table_presence + self.jump_table_size
    }
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

    pub fn diff_entries(&self, other: &Self) -> Vec<PipelineDiffEntry> {
        let mut diffs = Vec::new();

        let function_keys =
            self.functions.keys().chain(other.functions.keys()).copied().collect::<BTreeSet<_>>();
        for key in function_keys {
            let left = self.functions.get(&key);
            let right = other.functions.get(&key);
            if left != right {
                let kind = match (left, right) {
                    (Some(_), Some(_)) => PipelineDiffKind::FunctionEnd,
                    _ => PipelineDiffKind::FunctionPresence,
                };
                diffs.push(PipelineDiffEntry {
                    kind,
                    address: key,
                    left: format!("{left:?}"),
                    right: format!("{right:?}"),
                });
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
                let kind = match (left, right) {
                    (Some(_), Some(_)) => PipelineDiffKind::JumpTableSize,
                    _ => PipelineDiffKind::JumpTablePresence,
                };
                diffs.push(PipelineDiffEntry {
                    kind,
                    address: key,
                    left: format!("{left:?}"),
                    right: format!("{right:?}"),
                });
            }
        }

        diffs
    }

    pub fn diff_summary(&self, other: &Self) -> PipelineDiffSummary {
        self.diff_entries(other).into_iter().fold(
            PipelineDiffSummary::default(),
            |mut out, diff| {
                match diff.kind {
                    PipelineDiffKind::FunctionPresence => out.function_presence += 1,
                    PipelineDiffKind::FunctionEnd => out.function_end += 1,
                    PipelineDiffKind::JumpTablePresence => out.jump_table_presence += 1,
                    PipelineDiffKind::JumpTableSize => out.jump_table_size += 1,
                }
                out
            },
        )
    }

    pub fn diff(&self, other: &Self) -> Vec<String> {
        self.diff_entries(other)
            .into_iter()
            .map(|entry| {
                format!(
                    "{:?} mismatch at {}: left {}, right {}",
                    entry.kind, entry.address, entry.left, entry.right
                )
            })
            .collect()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PipelineRunReport {
    pub seed_discovery: SeedDiscoveryOutput,
    pub slice_exploration: SliceExplorationOutput,
    pub finalization: FinalizationOutput,
    pub digest: PipelineDigest,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct PhaseCheckpointDigest {
    pub seed_count: usize,
    pub processed_seed_count: usize,
    pub function_count: usize,
    pub jump_table_count: usize,
}

impl PhaseCheckpointDigest {
    pub fn from_run_report(report: &PipelineRunReport) -> Self {
        Self {
            seed_count: report.seed_discovery.seeds.len(),
            processed_seed_count: report.slice_exploration.processed_seed_count,
            function_count: report.finalization.function_count,
            jump_table_count: report.finalization.jump_table_count,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PhaseCheckpointDiffKind {
    SeedCount,
    ProcessedSeedCount,
    FunctionCount,
    JumpTableCount,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PhaseCheckpointDiffEntry {
    pub kind: PhaseCheckpointDiffKind,
    pub left: usize,
    pub right: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct PhaseCheckpointDiffSummary {
    pub seed_count: usize,
    pub processed_seed_count: usize,
    pub function_count: usize,
    pub jump_table_count: usize,
}

impl PhaseCheckpointDiffSummary {
    pub fn total(&self) -> usize {
        self.seed_count + self.processed_seed_count + self.function_count + self.jump_table_count
    }
}

pub fn phase_checkpoint_diff_entries(
    left: &PipelineRunReport,
    right: &PipelineRunReport,
) -> Vec<PhaseCheckpointDiffEntry> {
    let left_digest = PhaseCheckpointDigest::from_run_report(left);
    let right_digest = PhaseCheckpointDigest::from_run_report(right);
    let mut diffs = Vec::new();

    if left_digest.seed_count != right_digest.seed_count {
        diffs.push(PhaseCheckpointDiffEntry {
            kind: PhaseCheckpointDiffKind::SeedCount,
            left: left_digest.seed_count,
            right: right_digest.seed_count,
        });
    }
    if left_digest.processed_seed_count != right_digest.processed_seed_count {
        diffs.push(PhaseCheckpointDiffEntry {
            kind: PhaseCheckpointDiffKind::ProcessedSeedCount,
            left: left_digest.processed_seed_count,
            right: right_digest.processed_seed_count,
        });
    }
    if left_digest.function_count != right_digest.function_count {
        diffs.push(PhaseCheckpointDiffEntry {
            kind: PhaseCheckpointDiffKind::FunctionCount,
            left: left_digest.function_count,
            right: right_digest.function_count,
        });
    }
    if left_digest.jump_table_count != right_digest.jump_table_count {
        diffs.push(PhaseCheckpointDiffEntry {
            kind: PhaseCheckpointDiffKind::JumpTableCount,
            left: left_digest.jump_table_count,
            right: right_digest.jump_table_count,
        });
    }

    diffs
}

pub fn compare_phase_checkpoints(
    left: &PipelineRunReport,
    right: &PipelineRunReport,
) -> PhaseCheckpointDiffSummary {
    phase_checkpoint_diff_entries(left, right).into_iter().fold(
        PhaseCheckpointDiffSummary::default(),
        |mut out, diff| {
            match diff.kind {
                PhaseCheckpointDiffKind::SeedCount => out.seed_count += 1,
                PhaseCheckpointDiffKind::ProcessedSeedCount => out.processed_seed_count += 1,
                PhaseCheckpointDiffKind::FunctionCount => out.function_count += 1,
                PhaseCheckpointDiffKind::JumpTableCount => out.jump_table_count += 1,
            }
            out
        },
    )
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

impl LegacyPipelineEngine {
    pub fn new(skip_ranges: BTreeMap<SectionAddress, SectionAddress>) -> Self {
        Self { state: AnalyzerState::new(skip_ranges) }
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
                source: classify_seed_source(obj, address),
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

pub struct CandidatePipelineEngine {
    pub state: AnalyzerState,
    pub config: CandidatePipelineConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct CandidatePipelineConfig {
    /// Candidate-only seed refinement (default-off): drop seeds that are not in code sections.
    pub strict_code_seeds: bool,
}

impl CandidatePipelineEngine {
    pub fn new(skip_ranges: BTreeMap<SectionAddress, SectionAddress>) -> Self {
        Self::new_with_config(skip_ranges, CandidatePipelineConfig::default())
    }

    pub fn new_with_config(
        skip_ranges: BTreeMap<SectionAddress, SectionAddress>,
        config: CandidatePipelineConfig,
    ) -> Self {
        Self { state: AnalyzerState::new(skip_ranges), config }
    }

    fn candidate_seed_discovery(&mut self, obj: &ObjInfo) -> Vec<FunctionSeed> {
        // Candidate path intentionally owns this phase implementation so future seed
        // heuristics can diverge without touching legacy analyzer internals.
        for (&addr, &size) in &obj.known_functions {
            self.state.functions.insert(
                addr,
                FunctionInfo { analyzed: false, end: size.map(|known_size| addr + known_size), slices: None },
            );
        }

        for (_, symbol) in obj.symbols.by_kind(ObjSymbolKind::Function) {
            let Some(section_index) = symbol.section else { continue };
            let start = SectionAddress::new(section_index, symbol.address as u32);
            self.state.functions.insert(
                start,
                FunctionInfo {
                    analyzed: false,
                    end: if symbol.size_known { Some(start + symbol.size as u32) } else { None },
                    slices: None,
                },
            );
        }

        for (section_index, section) in obj.sections.by_kind(ObjSectionKind::Code) {
            let section_start = SectionAddress::new(section_index, section.address as u32);
            if obj
                .symbols
                .by_name(&format!("except_data_{:08X}", section_start.address + 8))
                .ok()
                .flatten()
                .is_some()
            {
                continue;
            }
            self.state.functions.entry(section_start).or_default();
        }

        let seeds = self
            .state
            .functions
            .keys()
            .copied()
            .map(|address| FunctionSeed { address, source: classify_seed_source(obj, address) })
            .filter(|seed| {
                if !self.config.strict_code_seeds {
                    return true;
                }
                matches!(
                    obj.sections.get(seed.address.section),
                    Some(section)
                        if section.kind == ObjSectionKind::Code
                            && section.contains(seed.address.address)
                )
            })
            .collect();

        seeds
    }

    fn candidate_slice_exploration(
        &mut self,
        obj: &ObjInfo,
        seed: &SeedDiscoveryOutput,
    ) -> Result<SliceExplorationOutput> {
        let seed_addrs = seed.seeds.iter().map(|entry| entry.address).collect::<Vec<_>>();
        for &addr in &seed_addrs {
            self.state.process_function_at(obj, addr)?;

            // Keep parity with legacy seeded-known-function checks.
            if let Some(value) = obj.known_functions.get(&addr) {
                if let Some(func) = self.state.functions.get(&addr) {
                    if let Some(known_size) = value {
                        let known_end = addr + *known_size;
                        assert_eq!(
                            func.end.is_some(),
                            true,
                            "Function at {} has no detected end rather than known end {}. There must be an error in processing!",
                            addr,
                            known_end
                        );
                        let func_end = func.end.unwrap();
                        if func_end < known_end {
                            panic!(
                                "Function at {} has known end addr {}, but during processing, ending was found to be {} (smaller than expected)!",
                                addr,
                                known_end,
                                func_end
                            );
                        } else if func_end != known_end {
                            log::info!(
                                "Candidate pipeline function at {} extends beyond pdata end {} to {} (likely tail block inclusion)",
                                addr,
                                known_end,
                                func_end
                            );
                        }
                    }
                } else {
                    unreachable!();
                }
            }
        }
        Ok(SliceExplorationOutput { processed_seed_count: seed_addrs.len() })
    }

    fn candidate_finalization(&mut self, obj: &ObjInfo) -> Result<FinalizationOutput> {
        self.state.phase_discover_remaining_functions(obj)?;
        self.state.phase_finalize_and_validate(obj)?;
        Ok(FinalizationOutput {
            function_count: self.state.functions.len(),
            jump_table_count: self.state.jump_tables.len(),
        })
    }
}

impl CfaPipelineEngine for CandidatePipelineEngine {
    fn phase_seed_discovery(&mut self, obj: &ObjInfo) -> Result<SeedDiscoveryOutput> {
        Ok(SeedDiscoveryOutput { seeds: self.candidate_seed_discovery(obj) })
    }

    fn phase_slice_exploration(
        &mut self,
        obj: &ObjInfo,
        seed: &SeedDiscoveryOutput,
    ) -> Result<SliceExplorationOutput> {
        self.candidate_slice_exploration(obj, seed)
    }

    fn phase_finalization(&mut self, obj: &ObjInfo) -> Result<FinalizationOutput> {
        self.candidate_finalization(obj)
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
    use std::fs::File;

    use serde::{de::Error, Deserialize, Deserializer};

    use super::*;
    use crate::obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSymbol, ObjSymbolKind};

    const NOP: u32 = 0x60000000;
    const BLR: u32 = 0x4E800020;

    fn bytestr_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        if hex_str.len() % 2 != 0 {
            return Err(D::Error::custom("hex string must have even length"));
        }
        (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
            .collect::<std::result::Result<Vec<u8>, _>>()
            .map_err(D::Error::custom)
    }

    fn get_fn_start<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        if hex_str.len() != 8 {
            return Err(D::Error::custom(format!("expected 8 hex chars, got {}", hex_str.len())));
        }
        u32::from_str_radix(&hex_str, 16).map_err(D::Error::custom)
    }

    #[derive(Debug, Deserialize)]
    struct ShadowFixture {
        test_id: u32,
        #[serde(deserialize_with = "get_fn_start")]
        function_start: u32,
        #[serde(deserialize_with = "bytestr_to_bytes")]
        function_bytes: Vec<u8>,
        #[serde(deserialize_with = "get_fn_start")]
        jump_table_start: u32,
        #[serde(deserialize_with = "bytestr_to_bytes")]
        jump_table_bytes: Vec<u8>,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Default)]
    struct ShadowCorpusFixtureReport {
        test_id: u32,
        diff_summary: PipelineDiffSummary,
        diff_entries: Vec<PipelineDiffEntry>,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Default)]
    struct ShadowCorpusReport {
        fixture_count: usize,
        mismatch_count: usize,
        totals: PipelineDiffSummary,
        fixtures: Vec<ShadowCorpusFixtureReport>,
    }

    impl ShadowCorpusReport {
        fn total_diffs(&self) -> usize {
            self.totals.total()
        }
    }

    fn make_code_section_bytes(base_addr: u32, data: &[u8]) -> ObjSection {
        ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: base_addr as u64,
            size: data.len() as u64,
            data: data.to_vec(),
            align: 0x10000,
            ..Default::default()
        }
    }

    fn make_data_section_bytes(base_addr: u32, data: &[u8]) -> ObjSection {
        ObjSection {
            name: ".rdata".into(),
            kind: ObjSectionKind::ReadOnlyData,
            address: base_addr as u64,
            size: data.len() as u64,
            data: data.to_vec(),
            align: 0x10000,
            ..Default::default()
        }
    }

    fn fixture_obj(fixture: &ShadowFixture) -> ObjInfo {
        let code = make_code_section_bytes(fixture.function_start, &fixture.function_bytes);
        let sections = if fixture.jump_table_start != 0 {
            vec![make_data_section_bytes(fixture.jump_table_start, &fixture.jump_table_bytes), code]
        } else {
            vec![code]
        };
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            format!("pipeline-shadow-fixture-{}", fixture.test_id),
            vec![],
            sections,
        )
    }

    fn accumulate_summary(total: &mut PipelineDiffSummary, add: &PipelineDiffSummary) {
        total.function_presence += add.function_presence;
        total.function_end += add.function_end;
        total.jump_table_presence += add.jump_table_presence;
        total.jump_table_size += add.jump_table_size;
    }

    fn run_shadow_corpus_parity(
        fixtures: &[ShadowFixture],
        selected: Option<&[u32]>,
    ) -> ShadowCorpusReport {
        let mut report = ShadowCorpusReport::default();

        for fixture in fixtures
            .iter()
            .filter(|entry| selected.map_or(true, |ids| ids.contains(&entry.test_id)))
        {
            let obj = fixture_obj(fixture);

            let mut baseline = AnalyzerState::new(BTreeMap::new());
            baseline.detect_functions(&obj).unwrap_or_else(|e| {
                panic!("baseline detect_functions failed for {}: {e:#}", fixture.test_id)
            });
            let baseline_digest = PipelineDigest::from_state(&baseline);

            let mut pipeline = CandidatePipelineEngine::new(BTreeMap::new());
            let pipeline_digest = pipeline.run(&obj).unwrap_or_else(|e| {
                panic!("candidate pipeline run failed for {}: {e:#}", fixture.test_id)
            });

            let diff_summary = baseline_digest.diff_summary(&pipeline_digest);
            let diff_entries = baseline_digest.diff_entries(&pipeline_digest);
            if diff_summary.total() != 0 {
                report.mismatch_count += 1;
            }
            accumulate_summary(&mut report.totals, &diff_summary);
            report.fixtures.push(ShadowCorpusFixtureReport {
                test_id: fixture.test_id,
                diff_summary,
                diff_entries,
            });
        }

        report.fixture_count = report.fixtures.len();
        report
    }

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
    fn pipeline_digest_diff_summary_categorizes_delta_types() {
        let mut left = PipelineDigest::default();
        left.functions.insert(SectionAddress::new(0, 0x1000), Some(SectionAddress::new(0, 0x1020)));
        left.functions.insert(SectionAddress::new(0, 0x1100), Some(SectionAddress::new(0, 0x1120)));
        left.jump_tables.insert(SectionAddress::new(0, 0x2000), 0x30);
        left.jump_tables.insert(SectionAddress::new(0, 0x2100), 0x10);

        let mut right = PipelineDigest::default();
        right
            .functions
            .insert(SectionAddress::new(0, 0x1000), Some(SectionAddress::new(0, 0x101C)));
        right.jump_tables.insert(SectionAddress::new(0, 0x2000), 0x40);
        right.jump_tables.insert(SectionAddress::new(0, 0x2200), 0x08);

        let summary = left.diff_summary(&right);
        assert_eq!(summary.function_end, 1);
        assert_eq!(summary.function_presence, 1);
        assert_eq!(summary.jump_table_size, 1);
        assert_eq!(summary.jump_table_presence, 2);
        assert_eq!(summary.total(), 5);
    }

    #[test]
    fn phase_checkpoint_diff_is_empty_for_identical_reports() {
        let report = PipelineRunReport {
            seed_discovery: SeedDiscoveryOutput {
                seeds: vec![
                    FunctionSeed {
                        address: SectionAddress::new(0, 0x1000),
                        source: SeedSource::KnownFunction,
                    },
                    FunctionSeed {
                        address: SectionAddress::new(0, 0x2000),
                        source: SeedSource::Discovered,
                    },
                ],
            },
            slice_exploration: SliceExplorationOutput { processed_seed_count: 2 },
            finalization: FinalizationOutput { function_count: 4, jump_table_count: 1 },
            digest: PipelineDigest::default(),
        };

        let summary = compare_phase_checkpoints(&report, &report);
        assert_eq!(summary.total(), 0, "identical reports should have zero checkpoint diffs");
        assert!(phase_checkpoint_diff_entries(&report, &report).is_empty());
    }

    #[test]
    fn phase_checkpoint_diff_summary_categorizes_delta_types() {
        let left = PipelineRunReport {
            seed_discovery: SeedDiscoveryOutput {
                seeds: vec![
                    FunctionSeed {
                        address: SectionAddress::new(0, 0x1000),
                        source: SeedSource::KnownFunction,
                    },
                    FunctionSeed {
                        address: SectionAddress::new(0, 0x2000),
                        source: SeedSource::SectionStart,
                    },
                ],
            },
            slice_exploration: SliceExplorationOutput { processed_seed_count: 2 },
            finalization: FinalizationOutput { function_count: 6, jump_table_count: 3 },
            digest: PipelineDigest::default(),
        };
        let right = PipelineRunReport {
            seed_discovery: SeedDiscoveryOutput {
                seeds: vec![FunctionSeed {
                    address: SectionAddress::new(0, 0x1000),
                    source: SeedSource::KnownFunction,
                }],
            },
            slice_exploration: SliceExplorationOutput { processed_seed_count: 1 },
            finalization: FinalizationOutput { function_count: 5, jump_table_count: 1 },
            digest: PipelineDigest::default(),
        };

        let summary = compare_phase_checkpoints(&left, &right);
        assert_eq!(summary.seed_count, 1);
        assert_eq!(summary.processed_seed_count, 1);
        assert_eq!(summary.function_count, 1);
        assert_eq!(summary.jump_table_count, 1);
        assert_eq!(summary.total(), 4);

        let entries = phase_checkpoint_diff_entries(&left, &right);
        assert_eq!(entries.len(), 4);
        assert!(entries.iter().any(|entry| entry.kind == PhaseCheckpointDiffKind::SeedCount));
        assert!(entries
            .iter()
            .any(|entry| entry.kind == PhaseCheckpointDiffKind::ProcessedSeedCount));
        assert!(entries.iter().any(|entry| entry.kind == PhaseCheckpointDiffKind::FunctionCount));
        assert!(entries.iter().any(|entry| entry.kind == PhaseCheckpointDiffKind::JumpTableCount));
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
    fn candidate_seed_phase_matches_legacy_seed_phase() {
        let mut obj = make_obj(0x1000, &[NOP, BLR, NOP, BLR]);
        obj.known_functions.insert(SectionAddress::new(0, 0x1000), Some(8));

        let mut legacy = LegacyPipelineEngine::new(BTreeMap::new());
        let legacy_seed = legacy
            .phase_seed_discovery(&obj)
            .expect("legacy seed phase should succeed");

        let mut candidate = CandidatePipelineEngine::new(BTreeMap::new());
        let candidate_seed = candidate
            .phase_seed_discovery(&obj)
            .expect("candidate seed phase should succeed");

        assert_eq!(
            candidate_seed, legacy_seed,
            "candidate seed output must match legacy output during parity stage"
        );

        let legacy_functions = legacy
            .state
            .functions
            .iter()
            .map(|(&addr, info)| (addr, info.end))
            .collect::<BTreeMap<_, _>>();
        let candidate_functions = candidate
            .state
            .functions
            .iter()
            .map(|(&addr, info)| (addr, info.end))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            candidate_functions, legacy_functions,
            "candidate seed phase should materialize the same initial function map"
        );
    }

    #[test]
    fn candidate_seed_phase_strict_code_filter_drops_non_code_function_symbol() {
        let code = make_code_section_bytes(0x1000, &[0x60, 0x00, 0x00, 0x00, 0x4E, 0x80, 0x00, 0x20]);
        let data = make_data_section_bytes(0x2000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "candidate-seed-filter-test".into(),
            vec![],
            vec![data, code],
        );
        obj.add_symbol(
            ObjSymbol {
                name: "bad_data_function".into(),
                address: 0x2000,
                section: Some(0),
                size: 4,
                size_known: true,
                kind: ObjSymbolKind::Function,
                ..Default::default()
            },
            false,
        )
        .expect("should add non-code function symbol for filter test");

        let mut default_candidate = CandidatePipelineEngine::new(BTreeMap::new());
        let default_seed = default_candidate
            .phase_seed_discovery(&obj)
            .expect("default candidate seed should succeed");
        assert!(
            default_seed
                .seeds
                .iter()
                .any(|seed| seed.address == SectionAddress::new(0, 0x2000)),
            "default candidate mode should still include non-code symbol seed for parity"
        );

        let mut strict_candidate = CandidatePipelineEngine::new_with_config(
            BTreeMap::new(),
            CandidatePipelineConfig { strict_code_seeds: true },
        );
        let strict_seed = strict_candidate
            .phase_seed_discovery(&obj)
            .expect("strict candidate seed should succeed");
        assert!(
            !strict_seed
                .seeds
                .iter()
                .any(|seed| seed.address == SectionAddress::new(0, 0x2000)),
            "strict code-seed mode should drop non-code function symbol seeds"
        );
        assert!(
            strict_seed
                .seeds
                .iter()
                .any(|seed| seed.address == SectionAddress::new(1, 0x1000)),
            "strict code-seed mode should preserve valid code section seeds"
        );
    }

    #[test]
    fn candidate_slice_phase_matches_legacy_slice_phase() {
        let mut obj = make_obj(0x1000, &[NOP, BLR, NOP, BLR]);
        obj.known_functions.insert(SectionAddress::new(0, 0x1000), Some(8));

        let mut legacy = LegacyPipelineEngine::new(BTreeMap::new());
        let legacy_seed = legacy
            .phase_seed_discovery(&obj)
            .expect("legacy seed phase should succeed");
        let legacy_slice = legacy
            .phase_slice_exploration(&obj, &legacy_seed)
            .expect("legacy slice phase should succeed");
        let legacy_digest = legacy.digest();

        let mut candidate = CandidatePipelineEngine::new(BTreeMap::new());
        let candidate_seed = candidate
            .phase_seed_discovery(&obj)
            .expect("candidate seed phase should succeed");
        let candidate_slice = candidate
            .phase_slice_exploration(&obj, &candidate_seed)
            .expect("candidate slice phase should succeed");
        let candidate_digest = candidate.digest();

        assert_eq!(
            candidate_slice, legacy_slice,
            "candidate slice output should match legacy during parity stage"
        );
        assert_eq!(
            candidate_digest.diff_summary(&legacy_digest).total(),
            0,
            "candidate slice stage should preserve legacy digest parity"
        );
    }

    #[test]
    fn candidate_finalization_phase_matches_legacy_finalization_phase() {
        let mut obj = make_obj(0x1000, &[NOP, BLR, NOP, BLR, NOP, BLR]);
        obj.known_functions.insert(SectionAddress::new(0, 0x1000), Some(8));

        let mut legacy = LegacyPipelineEngine::new(BTreeMap::new());
        let legacy_seed = legacy
            .phase_seed_discovery(&obj)
            .expect("legacy seed phase should succeed");
        legacy
            .phase_slice_exploration(&obj, &legacy_seed)
            .expect("legacy slice phase should succeed");
        let legacy_finalization = legacy
            .phase_finalization(&obj)
            .expect("legacy finalization should succeed");
        let legacy_digest = legacy.digest();

        let mut candidate = CandidatePipelineEngine::new(BTreeMap::new());
        let candidate_seed = candidate
            .phase_seed_discovery(&obj)
            .expect("candidate seed phase should succeed");
        candidate
            .phase_slice_exploration(&obj, &candidate_seed)
            .expect("candidate slice phase should succeed");
        let candidate_finalization = candidate
            .phase_finalization(&obj)
            .expect("candidate finalization should succeed");
        let candidate_digest = candidate.digest();

        assert_eq!(
            candidate_finalization, legacy_finalization,
            "candidate finalization output should match legacy during parity stage"
        );
        assert_eq!(
            candidate_digest.diff_summary(&legacy_digest).total(),
            0,
            "candidate finalization stage should preserve legacy digest parity"
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

    #[test]
    fn candidate_pipeline_run_matches_legacy_pipeline_digest() {
        let mut obj = make_obj(0x1000, &[NOP, BLR, NOP, NOP, BLR]);
        obj.known_functions.insert(SectionAddress::new(0, 0x1000), Some(8));

        let mut legacy = LegacyPipelineEngine::new(BTreeMap::new());
        let legacy_digest = legacy.run(&obj).expect("legacy pipeline run should succeed");

        let mut candidate = CandidatePipelineEngine::new(BTreeMap::new());
        let candidate_digest = candidate.run(&obj).expect("candidate pipeline run should succeed");

        let diffs = legacy_digest.diff(&candidate_digest);
        assert!(
            diffs.is_empty(),
            "candidate pipeline should match legacy digest during parity stage, diffs: {diffs:?}"
        );
    }

    #[test]
    fn shadow_corpus_full_fixtures_match_legacy_pipeline_digest() {
        let fixtures: Vec<ShadowFixture> =
            serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml").unwrap())
                .expect("failed to read CFA fixture corpus");
        let report = run_shadow_corpus_parity(&fixtures, None);
        assert_eq!(report.fixture_count, fixtures.len(), "all fixtures should be shadow-checked");
        assert_eq!(
            report.mismatch_count,
            0,
            "shadow corpus has mismatched fixtures: {:?}",
            report
                .fixtures
                .iter()
                .filter(|fixture| fixture.diff_summary.total() != 0)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            report.total_diffs(),
            0,
            "shadow corpus diff totals should be zero: {:?}",
            report
        );
    }
}
