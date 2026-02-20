use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU32,
};

use powerpc::{Ins, Opcode};

use crate::analysis::{
    disassemble,
    cfa::SectionAddress,
    vm::{Cr, Gpr, GprSourceLocation, GprValue, JumpTableType, StepResult, VM},
    RelocationTarget,
};
use crate::obj::{ObjInfo, ObjSectionKind};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Confidence2 {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Value2 {
    Top,
    Const(u64),
    Address(RelocationTarget),
    Range {
        min: u64,
        max: u64,
        step: u64,
    },
    IndexedLoad {
        table_addr: RelocationTarget,
        max_offset: Option<NonZeroU32>,
        relative_base: Option<RelocationTarget>,
    },
    CompareTag {
        crf: u8,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Provenance2 {
    None,
    Reg { reg: u8, revision: usize },
    StackSlot { offset: i16, revision: usize },
    Memory { address: RelocationTarget, revision: usize },
    LegacyMemory { slot: usize, revision: usize },
    LegacyMemoryOffset { base_slot: usize, offset_register: u8, revision: usize },
    Derived(Vec<Provenance2>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValueFact2 {
    pub value: Value2,
    pub provenance: Provenance2,
    pub confidence: Confidence2,
}

impl ValueFact2 {
    pub fn top() -> Self {
        Self { value: Value2::Top, provenance: Provenance2::None, confidence: Confidence2::Low }
    }
}

impl Default for ValueFact2 {
    fn default() -> Self {
        Self::top()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Vm2 {
    pub gpr: [ValueFact2; 32],
    pub cr: [ValueFact2; 8],
    pub lr: ValueFact2,
    pub ctr: ValueFact2,
    pub stack_slots: BTreeMap<i16, ValueFact2>,
    pub current_revision: usize,
}

impl Default for Vm2 {
    fn default() -> Self {
        Self {
            gpr: std::array::from_fn(|_| ValueFact2::default()),
            cr: std::array::from_fn(|_| ValueFact2::default()),
            lr: ValueFact2::default(),
            ctr: ValueFact2::default(),
            stack_slots: BTreeMap::new(),
            current_revision: 0,
        }
    }
}

impl Vm2 {
    pub fn new() -> Self {
        Self::default()
    }

    fn map_legacy_value(value: GprValue) -> (Value2, Confidence2) {
        match value {
            GprValue::Unknown => (Value2::Top, Confidence2::Low),
            GprValue::Constant(value) => (Value2::Const(value), Confidence2::High),
            GprValue::Address(address) => (Value2::Address(address), Confidence2::High),
            GprValue::ComparisonResult(crf) => (Value2::CompareTag { crf }, Confidence2::Medium),
            GprValue::Range { min, max, step } => (
                Value2::Range { min, max, step },
                if step == 0 { Confidence2::Low } else { Confidence2::High },
            ),
            GprValue::LoadIndexed { jump_table_type, jump_table_address, max_offset } => (
                Value2::IndexedLoad {
                    table_addr: jump_table_address,
                    max_offset,
                    relative_base: match jump_table_type {
                        JumpTableType::Absolute => None,
                        JumpTableType::RelativeBytes(base)
                        | JumpTableType::RelativeBytesTimes4(base)
                        | JumpTableType::RelativeShorts(base)
                        | JumpTableType::RelativeShortsTimes2(base) => base,
                    },
                },
                if max_offset.is_some() { Confidence2::High } else { Confidence2::Medium },
            ),
        }
    }

    fn map_legacy_provenance(gpr: &Gpr) -> Provenance2 {
        match gpr.source.kind {
            GprSourceLocation::Unknown => Provenance2::None,
            GprSourceLocation::Register(reg) => {
                Provenance2::Reg { reg: reg as u8, revision: gpr.source.version }
            }
            GprSourceLocation::Stack(offset) => {
                Provenance2::StackSlot { offset: offset as i16, revision: gpr.source.version }
            }
            GprSourceLocation::Memory(address) => {
                Provenance2::LegacyMemory { slot: address, revision: gpr.source.version }
            }
            GprSourceLocation::MemoryOffset { address, offset_register } => {
                Provenance2::LegacyMemoryOffset {
                    base_slot: address,
                    offset_register: offset_register as u8,
                    revision: gpr.source.version,
                }
            }
        }
    }

    fn fact_from_legacy_gpr(gpr: &Gpr) -> ValueFact2 {
        let (value, confidence) = Self::map_legacy_value(gpr.value);
        ValueFact2 { value, provenance: Self::map_legacy_provenance(gpr), confidence }
    }

    fn fact_from_legacy_value(value: GprValue) -> ValueFact2 {
        let (mapped, confidence) = Self::map_legacy_value(value);
        ValueFact2 { value: mapped, provenance: Provenance2::None, confidence }
    }

    fn fact_from_legacy_cr(crf: usize, cr: &Cr) -> ValueFact2 {
        if cr.left == GprValue::Unknown && cr.right == GprValue::Unknown {
            ValueFact2::top()
        } else {
            ValueFact2 {
                value: Value2::CompareTag { crf: crf as u8 },
                provenance: Provenance2::None,
                confidence: Confidence2::Medium,
            }
        }
    }

    pub fn from_legacy_vm(legacy: &VM) -> Self {
        let mut vm2 = Self::new();
        for reg in 0..32 {
            vm2.gpr[reg] = Self::fact_from_legacy_gpr(&legacy.gpr[reg]);
        }
        for crf in 0..8 {
            vm2.cr[crf] = Self::fact_from_legacy_cr(crf, &legacy.cr[crf]);
        }
        vm2.lr = Self::fact_from_legacy_value(legacy.lr);
        vm2.ctr = Self::fact_from_legacy_value(legacy.ctr);
        vm2.stack_slots = legacy
            .stack_slots
            .iter()
            .map(|(&offset, gpr)| (offset, Self::fact_from_legacy_gpr(gpr)))
            .collect();
        vm2.current_revision = legacy.gpr.iter().map(|gpr| gpr.version).max().unwrap_or_default();
        vm2
    }

    #[inline]
    pub fn next_revision(&mut self) -> usize {
        self.current_revision += 1;
        self.current_revision
    }

    #[inline]
    pub fn set_reg(
        &mut self,
        reg: u8,
        value: Value2,
        provenance: Provenance2,
        confidence: Confidence2,
    ) {
        self.gpr[reg as usize] = ValueFact2 { value, provenance, confidence };
    }

    #[inline]
    pub fn reg(&self, reg: u8) -> &ValueFact2 {
        &self.gpr[reg as usize]
    }

    #[inline]
    pub fn write_stack_slot(&mut self, offset: i16, fact: ValueFact2) {
        self.stack_slots.insert(offset, fact);
    }

    #[inline]
    pub fn read_stack_slot(&self, offset: i16) -> Option<&ValueFact2> {
        self.stack_slots.get(&offset)
    }

    /// Best-effort native VM2 runtime-shadow step.
    /// Returns `true` when the opcode is handled natively; callers should bridge from legacy VM
    /// state when `false`.
    pub fn step_shadow_native(&mut self, ins: Ins) -> bool {
        match ins.op {
            // `ori rX, rX, 0` / `nop`: no semantic state change.
            Opcode::Ori if ins.field_uimm() == 0 && ins.field_ra() == ins.field_rs() => true,
            // Non-link branches do not update architectural value state tracked by VM2.
            Opcode::B | Opcode::Bc | Opcode::Bcctr | Opcode::Bclr if !ins.field_lk() => true,
            // Illegal decode terminates execution in both VMs without mutating tracked facts.
            Opcode::Illegal => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BranchFact2 {
    pub target: Option<SectionAddress>,
    pub vm: Vm2,
    pub confidence: Confidence2,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VmShadowLocation {
    Gpr(u8),
    Cr(u8),
    Lr,
    Ctr,
    StackSlot(i16),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VmShadowDiffKind {
    Presence,
    Value,
    Provenance,
    Confidence,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VmShadowDiffEntry {
    pub location: VmShadowLocation,
    pub kind: VmShadowDiffKind,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct VmShadowDiffSummary {
    pub presence: usize,
    pub value: usize,
    pub provenance: usize,
    pub confidence: usize,
}

impl VmShadowDiffSummary {
    pub fn total(&self) -> usize {
        self.presence + self.value + self.provenance + self.confidence
    }

    pub fn accumulate(&mut self, other: &Self) {
        self.presence += other.presence;
        self.value += other.value;
        self.provenance += other.provenance;
        self.confidence += other.confidence;
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct VmShadowDiffReport {
    pub entries: Vec<VmShadowDiffEntry>,
    pub summary: VmShadowDiffSummary,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct VmCorpusShadowFixtureResult {
    pub test_id: u32,
    pub summary: VmShadowDiffSummary,
    pub entries: Vec<VmShadowDiffEntry>,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct VmCorpusShadowReport {
    pub fixture_count: usize,
    pub mismatch_count: usize,
    pub totals: VmShadowDiffSummary,
    pub fixtures: Vec<VmCorpusShadowFixtureResult>,
}

impl VmCorpusShadowReport {
    pub fn total_diffs(&self) -> usize {
        self.totals.total()
    }

    pub fn push_fixture(&mut self, fixture: VmCorpusShadowFixtureResult) {
        if fixture.summary.total() != 0 {
            self.mismatch_count += 1;
        }
        self.totals.accumulate(&fixture.summary);
        self.fixtures.push(fixture);
        self.fixture_count = self.fixtures.len();
    }
}

pub const DEFAULT_RUNTIME_VM_SHADOW_MAX_FUNCTIONS: usize = 16;
pub const DEFAULT_RUNTIME_VM_SHADOW_MAX_STEPS_PER_FUNCTION: usize = 128;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct VmRuntimeShadowConfig {
    pub max_functions: usize,
    pub max_steps_per_function: usize,
}

impl Default for VmRuntimeShadowConfig {
    fn default() -> Self {
        Self {
            max_functions: DEFAULT_RUNTIME_VM_SHADOW_MAX_FUNCTIONS,
            max_steps_per_function: DEFAULT_RUNTIME_VM_SHADOW_MAX_STEPS_PER_FUNCTION,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VmRuntimeShadowFunctionReport {
    pub start: SectionAddress,
    pub steps_sampled: usize,
    pub native_steps: usize,
    pub bridged_steps: usize,
    pub summary: VmShadowDiffSummary,
}

impl VmRuntimeShadowFunctionReport {
    pub fn total_diffs(&self) -> usize {
        self.summary.total()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct VmRuntimeShadowReport {
    pub summary: VmShadowDiffSummary,
    pub functions_requested: usize,
    pub functions_sampled: usize,
    pub steps_sampled: usize,
    pub native_steps: usize,
    pub bridged_steps: usize,
    pub function_reports: Vec<VmRuntimeShadowFunctionReport>,
}

impl VmRuntimeShadowReport {
    pub fn total_diffs(&self) -> usize {
        self.summary.total()
    }

    pub fn functions_with_diffs(&self) -> usize {
        self.function_reports.iter().filter(|report| report.total_diffs() != 0).count()
    }
}

impl VmShadowDiffReport {
    fn push(
        &mut self,
        location: VmShadowLocation,
        kind: VmShadowDiffKind,
        expected: String,
        actual: String,
    ) {
        match kind {
            VmShadowDiffKind::Presence => self.summary.presence += 1,
            VmShadowDiffKind::Value => self.summary.value += 1,
            VmShadowDiffKind::Provenance => self.summary.provenance += 1,
            VmShadowDiffKind::Confidence => self.summary.confidence += 1,
        }
        self.entries.push(VmShadowDiffEntry { location, kind, expected, actual });
    }

    fn compare_fact(
        &mut self,
        location: VmShadowLocation,
        expected: &ValueFact2,
        actual: &ValueFact2,
    ) {
        if expected.value != actual.value {
            self.push(
                location,
                VmShadowDiffKind::Value,
                format!("{:?}", expected.value),
                format!("{:?}", actual.value),
            );
        }
        if expected.provenance != actual.provenance {
            self.push(
                location,
                VmShadowDiffKind::Provenance,
                format!("{:?}", expected.provenance),
                format!("{:?}", actual.provenance),
            );
        }
        if expected.confidence != actual.confidence {
            self.push(
                location,
                VmShadowDiffKind::Confidence,
                format!("{:?}", expected.confidence),
                format!("{:?}", actual.confidence),
            );
        }
    }

    pub fn from_legacy_pair(legacy: &VM, candidate: &Vm2) -> Self {
        let mut report = Self::default();

        for reg in 0..32 {
            let expected = Vm2::fact_from_legacy_gpr(&legacy.gpr[reg]);
            report.compare_fact(VmShadowLocation::Gpr(reg as u8), &expected, &candidate.gpr[reg]);
        }
        for crf in 0..8 {
            let expected = Vm2::fact_from_legacy_cr(crf, &legacy.cr[crf]);
            report.compare_fact(VmShadowLocation::Cr(crf as u8), &expected, &candidate.cr[crf]);
        }

        let expected_lr = Vm2::fact_from_legacy_value(legacy.lr);
        report.compare_fact(VmShadowLocation::Lr, &expected_lr, &candidate.lr);
        let expected_ctr = Vm2::fact_from_legacy_value(legacy.ctr);
        report.compare_fact(VmShadowLocation::Ctr, &expected_ctr, &candidate.ctr);

        let slot_keys = legacy
            .stack_slots
            .keys()
            .chain(candidate.stack_slots.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for offset in slot_keys {
            let expected = legacy.stack_slots.get(&offset).map(Vm2::fact_from_legacy_gpr);
            let actual = candidate.stack_slots.get(&offset);
            match (expected.as_ref(), actual) {
                (Some(expected), Some(actual)) => {
                    report.compare_fact(VmShadowLocation::StackSlot(offset), expected, actual);
                }
                (Some(expected), None) => report.push(
                    VmShadowLocation::StackSlot(offset),
                    VmShadowDiffKind::Presence,
                    format!("{expected:?}"),
                    "None".into(),
                ),
                (None, Some(actual)) => report.push(
                    VmShadowLocation::StackSlot(offset),
                    VmShadowDiffKind::Presence,
                    "None".into(),
                    format!("{actual:?}"),
                ),
                (None, None) => {}
            }
        }

        report
    }
}

pub fn runtime_vm_shadow_report(
    obj: &ObjInfo,
    function_starts: &[SectionAddress],
    config: VmRuntimeShadowConfig,
) -> VmRuntimeShadowReport {
    runtime_vm_shadow_report_with_mode(obj, function_starts, config, false)
}

pub fn runtime_vm_shadow_report_with_mode(
    obj: &ObjInfo,
    function_starts: &[SectionAddress],
    config: VmRuntimeShadowConfig,
    native_vm2: bool,
) -> VmRuntimeShadowReport {
    let mut report = VmRuntimeShadowReport::default();
    if config.max_functions == 0 || config.max_steps_per_function == 0 {
        return report;
    }

    let selected = function_starts.iter().take(config.max_functions).copied().collect::<Vec<_>>();
    report.functions_requested = selected.len();

    for start in selected {
        let Some(section) = obj.sections.get(start.section) else {
            continue;
        };
        if section.kind != ObjSectionKind::Code || !section.contains(start.address) {
            continue;
        }
        report.functions_sampled += 1;
        let mut function_report = VmRuntimeShadowFunctionReport {
            start,
            steps_sampled: 0,
            native_steps: 0,
            bridged_steps: 0,
            summary: Default::default(),
        };

        let mut vm = VM::new_from_obj(obj);
        let mut vm2_native = native_vm2.then(Vm2::new);
        let mut addr = start;
        for _ in 0..config.max_steps_per_function {
            if !section.contains(addr.address) {
                break;
            }
            let Some(ins) = disassemble(section, addr.address) else {
                break;
            };
            function_report.steps_sampled += 1;
            report.steps_sampled += 1;

            let native_handled = if let Some(vm2) = vm2_native.as_mut() {
                vm2.step_shadow_native(ins)
            } else {
                false
            };
            let result = vm.step(obj, addr, ins);
            if let Some(vm2) = vm2_native.as_mut() {
                if native_handled {
                    function_report.native_steps += 1;
                    report.native_steps += 1;
                } else {
                    *vm2 = Vm2::from_legacy_vm(&vm);
                    function_report.bridged_steps += 1;
                    report.bridged_steps += 1;
                }
                let diff = VmShadowDiffReport::from_legacy_pair(&vm, vm2);
                function_report.summary.accumulate(&diff.summary);
            } else {
                // Baseline mode maps candidate facts from legacy VM state.
                let candidate = Vm2::from_legacy_vm(&vm);
                let diff = VmShadowDiffReport::from_legacy_pair(&vm, &candidate);
                function_report.summary.accumulate(&diff.summary);
            }

            match result {
                StepResult::Continue | StepResult::LoadStore { .. } | StepResult::Branch(_) => {
                    addr += 4;
                }
                StepResult::Illegal | StepResult::Jump(_) => break,
            }
        }
        report.summary.accumulate(&function_report.summary);
        report.function_reports.push(function_report);
    }
    report
}

pub fn runtime_vm_shadow_summary(
    obj: &ObjInfo,
    function_starts: &[SectionAddress],
    config: VmRuntimeShadowConfig,
) -> VmShadowDiffSummary {
    runtime_vm_shadow_report_with_mode(obj, function_starts, config, false).summary
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use powerpc::{Extensions, Ins};
    use serde::{de::Error, Deserialize, Deserializer};

    use crate::{
        analysis::vm::{BranchTarget, StepResult},
        obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind},
    };

    const MAX_VM_SHADOW_STEPS_PER_FIXTURE: usize = 256;

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

    #[test]
    fn vm2_defaults_to_top_values() {
        let vm = Vm2::new();
        assert_eq!(vm.gpr[0].value, Value2::Top);
        assert_eq!(vm.cr[0].value, Value2::Top);
        assert_eq!(vm.lr.value, Value2::Top);
        assert_eq!(vm.ctr.value, Value2::Top);
    }

    #[test]
    fn vm2_stack_slot_roundtrip_preserves_fact() {
        let mut vm = Vm2::new();
        let fact = ValueFact2 {
            value: Value2::Range { min: 0, max: 0x20, step: 1 },
            provenance: Provenance2::StackSlot { offset: 0x50, revision: 3 },
            confidence: Confidence2::High,
        };
        vm.write_stack_slot(0x50, fact.clone());
        assert_eq!(vm.read_stack_slot(0x50), Some(&fact));
    }

    #[test]
    fn runtime_vm_shadow_summary_is_zero_for_legacy_mapped_candidate() {
        let obj = make_obj_with_words(0x1000, &[0x6000_0000, 0x4E80_0020]);
        let starts = [SectionAddress::new(0, 0x1000)];
        let summary = runtime_vm_shadow_summary(
            &obj,
            &starts,
            VmRuntimeShadowConfig { max_functions: 1, max_steps_per_function: 16 },
        );
        assert_eq!(
            summary.total(),
            0,
            "legacy-vs-mapped candidate runtime shadow should start as zero-delta baseline"
        );
    }

    #[test]
    fn runtime_vm_shadow_summary_respects_zero_limits() {
        let obj = make_obj_with_words(0x1000, &[0x6000_0000, 0x4E80_0020]);
        let starts = [SectionAddress::new(0, 0x1000)];
        let summary_zero_funcs = runtime_vm_shadow_summary(
            &obj,
            &starts,
            VmRuntimeShadowConfig { max_functions: 0, max_steps_per_function: 16 },
        );
        assert_eq!(summary_zero_funcs.total(), 0);

        let summary_zero_steps = runtime_vm_shadow_summary(
            &obj,
            &starts,
            VmRuntimeShadowConfig { max_functions: 1, max_steps_per_function: 0 },
        );
        assert_eq!(summary_zero_steps.total(), 0);
    }

    #[test]
    fn runtime_vm_shadow_report_tracks_sampling_counts() {
        let obj = make_obj_with_words(0x1000, &[0x6000_0000, 0x4E80_0020]);
        let starts = [SectionAddress::new(0, 0x1000)];
        let report = runtime_vm_shadow_report(
            &obj,
            &starts,
            VmRuntimeShadowConfig { max_functions: 1, max_steps_per_function: 16 },
        );
        assert_eq!(report.functions_requested, 1);
        assert_eq!(report.functions_sampled, 1);
        assert_eq!(report.function_reports.len(), 1);
        assert_eq!(report.function_reports[0].start, SectionAddress::new(0, 0x1000));
        assert!(
            report.steps_sampled >= 1,
            "runtime shadow report should record at least one sampled step"
        );
        assert_eq!(report.function_reports[0].steps_sampled, report.steps_sampled);
        assert_eq!(report.native_steps, 0);
        assert_eq!(report.bridged_steps, 0);
        assert_eq!(report.function_reports[0].native_steps, 0);
        assert_eq!(report.function_reports[0].bridged_steps, 0);
        assert_eq!(report.functions_with_diffs(), 0);
        assert_eq!(report.total_diffs(), 0);
    }

    #[test]
    fn runtime_vm_shadow_report_native_mode_tracks_native_and_bridged_steps() {
        let obj = make_obj_with_words(0x1000, &[0x6000_0000, 0x3860_0001, 0x4E80_0020]);
        let starts = [SectionAddress::new(0, 0x1000)];
        let report = runtime_vm_shadow_report_with_mode(
            &obj,
            &starts,
            VmRuntimeShadowConfig { max_functions: 1, max_steps_per_function: 16 },
            true,
        );
        assert_eq!(report.functions_requested, 1);
        assert_eq!(report.functions_sampled, 1);
        assert_eq!(report.function_reports.len(), 1);
        let function_report = &report.function_reports[0];
        assert!(
            function_report.native_steps >= 1,
            "expected at least one natively handled step in native mode"
        );
        assert!(
            function_report.bridged_steps >= 1,
            "expected at least one bridged step in native mode"
        );
        assert_eq!(report.native_steps, function_report.native_steps);
        assert_eq!(report.bridged_steps, function_report.bridged_steps);
        assert_eq!(report.total_diffs(), 0);
    }

    #[test]
    fn runtime_vm_shadow_report_skips_non_code_functions() {
        let section = ObjSection {
            name: ".data".into(),
            kind: ObjSectionKind::Data,
            address: 0x1000,
            size: 8,
            data: vec![0; 8],
            align: 4,
            ..Default::default()
        };
        let obj = ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "vm2-shadow-test".into(),
            vec![],
            vec![section],
        );
        let starts = [SectionAddress::new(0, 0x1000)];
        let report = runtime_vm_shadow_report(
            &obj,
            &starts,
            VmRuntimeShadowConfig { max_functions: 1, max_steps_per_function: 16 },
        );
        assert_eq!(report.functions_requested, 1);
        assert_eq!(report.functions_sampled, 0);
        assert_eq!(report.steps_sampled, 0);
        assert_eq!(report.native_steps, 0);
        assert_eq!(report.bridged_steps, 0);
        assert!(report.function_reports.is_empty());
        assert_eq!(report.total_diffs(), 0);
    }

    fn make_obj_with_size(base: u32, size: usize) -> ObjInfo {
        let section = ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: base as u64,
            size: size as u64,
            data: vec![0u8; size],
            align: 4,
            ..Default::default()
        };
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "vm2-shadow-test".into(),
            vec![],
            vec![section],
        )
    }

    fn make_obj_with_words(base: u32, words: &[u32]) -> ObjInfo {
        let data: Vec<u8> = words.iter().flat_map(|word| word.to_be_bytes()).collect();
        let section = ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: base as u64,
            size: data.len() as u64,
            data,
            align: 4,
            ..Default::default()
        };
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "vm2-shadow-test".into(),
            vec![],
            vec![section],
        )
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
            format!("vm2-shadow-fixture-{}", fixture.test_id),
            vec![],
            sections,
        )
    }

    fn collect_linear_vm_samples(
        obj: &ObjInfo,
        function_start: SectionAddress,
        max_steps: usize,
    ) -> Vec<VM> {
        let mut vm = VM::new_from_obj(obj);
        let mut samples = vec![(*vm).clone()];
        let mut addr = function_start;
        let section = &obj.sections[function_start.section];

        for _ in 0..max_steps {
            if !section.contains(addr.address) {
                break;
            }
            let Some(ins) = crate::analysis::disassemble(section, addr.address) else {
                break;
            };
            let result = vm.step(obj, addr, ins);
            samples.push((*vm).clone());
            match result {
                StepResult::Continue | StepResult::LoadStore { .. } | StepResult::Branch(_) => {
                    addr += 4;
                }
                StepResult::Illegal | StepResult::Jump(_) => break,
            }
        }

        samples
    }

    fn run_vm_shadow_for_fixture(fixture: &ShadowFixture) -> VmCorpusShadowFixtureResult {
        let obj = fixture_obj(fixture);
        let (section_index, _) =
            obj.sections.at_address(fixture.function_start).unwrap_or_else(|e| {
                panic!("failed to locate function start for {}: {e:#}", fixture.test_id)
            });
        let function_start = SectionAddress::new(section_index, fixture.function_start);
        let samples =
            collect_linear_vm_samples(&obj, function_start, MAX_VM_SHADOW_STEPS_PER_FIXTURE);

        let mut result =
            VmCorpusShadowFixtureResult { test_id: fixture.test_id, ..Default::default() };
        for sample in samples {
            let vm2 = Vm2::from_legacy_vm(&sample);
            let diff = VmShadowDiffReport::from_legacy_pair(&sample, &vm2);
            result.summary.accumulate(&diff.summary);
            result.entries.extend(diff.entries);
        }
        result
    }

    fn run_vm_shadow_corpus(
        fixtures: &[ShadowFixture],
        selected: Option<&[u32]>,
    ) -> VmCorpusShadowReport {
        let mut report = VmCorpusShadowReport::default();
        for fixture in fixtures
            .iter()
            .filter(|entry| selected.map_or(true, |ids| ids.contains(&entry.test_id)))
        {
            report.push_fixture(run_vm_shadow_for_fixture(fixture));
        }
        report
    }

    fn step(vm: &mut VM, obj: &ObjInfo, addr: u32, code: u32) -> StepResult {
        vm.step(obj, SectionAddress::new(0, addr), Ins::new(code, Extensions::xenon()))
    }

    #[test]
    fn vm2_from_legacy_vm_maps_core_value_and_provenance() {
        let mut legacy = VM::default();
        legacy.gpr[3].value = GprValue::Constant(0x1234);
        legacy.gpr[3].source.kind = GprSourceLocation::Register(5);
        legacy.gpr[3].source.version = 7;
        legacy.gpr[4].value = GprValue::Range { min: 1, max: 9, step: 2 };
        legacy.gpr[4].source.kind = GprSourceLocation::Stack(0x50);
        legacy.gpr[4].source.version = 11;
        legacy.gpr[6].value = GprValue::LoadIndexed {
            jump_table_type: JumpTableType::RelativeBytesTimes4(Some(RelocationTarget::Address(
                SectionAddress::new(0, 0x200),
            ))),
            jump_table_address: RelocationTarget::Address(SectionAddress::new(0, 0x100)),
            max_offset: NonZeroU32::new(0x20),
        };
        legacy.gpr[6].source.kind =
            GprSourceLocation::MemoryOffset { address: 0x80, offset_register: 9 };
        legacy.gpr[6].source.version = 13;
        legacy.ctr = legacy.gpr[6].value;

        let vm2 = Vm2::from_legacy_vm(&legacy);
        assert_eq!(vm2.reg(3).value, Value2::Const(0x1234));
        assert_eq!(vm2.reg(3).provenance, Provenance2::Reg { reg: 5, revision: 7 });
        assert_eq!(vm2.reg(4).value, Value2::Range { min: 1, max: 9, step: 2 });
        assert_eq!(vm2.reg(4).provenance, Provenance2::StackSlot { offset: 0x50, revision: 11 });
        assert_eq!(
            vm2.reg(6).value,
            Value2::IndexedLoad {
                table_addr: RelocationTarget::Address(SectionAddress::new(0, 0x100)),
                max_offset: NonZeroU32::new(0x20),
                relative_base: Some(RelocationTarget::Address(SectionAddress::new(0, 0x200))),
            }
        );
        assert_eq!(
            vm2.reg(6).provenance,
            Provenance2::LegacyMemoryOffset { base_slot: 0x80, offset_register: 9, revision: 13 }
        );
        assert_eq!(
            vm2.ctr.value,
            Value2::IndexedLoad {
                table_addr: RelocationTarget::Address(SectionAddress::new(0, 0x100)),
                max_offset: NonZeroU32::new(0x20),
                relative_base: Some(RelocationTarget::Address(SectionAddress::new(0, 0x200))),
            }
        );
    }

    #[test]
    fn vm2_shadow_tracks_relative_jump_table_from_legacy_vm_execution() {
        let obj = make_obj_with_size(0x0, 0x400);
        let mut legacy = VM::new_from_obj(&obj);
        legacy.gpr[11].value = GprValue::Range { min: 0, max: 0x10, step: 1 };
        legacy.last_modified_cr = 0;
        legacy.cr[0].right = GprValue::Constant(0x10);

        let _ = step(&mut legacy, &obj, 0x0000, 0x3D80_0000); // lis r12, 0
        let _ = step(&mut legacy, &obj, 0x0004, 0x398C_0100); // addi r12, r12, 0x100
        let _ = step(&mut legacy, &obj, 0x0008, 0x7C0C_58AE); // lbzx r0, r12, r11
        let _ = step(&mut legacy, &obj, 0x000C, 0x5400_103A); // slwi r0, r0, 2
        let _ = step(&mut legacy, &obj, 0x0010, 0x3D80_0000); // lis r12, 0
        let _ = step(&mut legacy, &obj, 0x0014, 0x398C_0200); // addi r12, r12, 0x200
        let _ = step(&mut legacy, &obj, 0x0018, 0x7D8C_0214); // add r12, r12, r0
        let _ = step(&mut legacy, &obj, 0x001C, 0x7D89_03A6); // mtctr r12
        let StepResult::Jump(BranchTarget::JumpTable { .. }) =
            step(&mut legacy, &obj, 0x0020, 0x4E80_0420)
        else {
            panic!("expected jump-table branch from legacy VM");
        };

        let vm2 = Vm2::from_legacy_vm(&legacy);
        assert_eq!(
            vm2.ctr.value,
            Value2::IndexedLoad {
                table_addr: RelocationTarget::Address(SectionAddress::new(0, 0x100)),
                max_offset: NonZeroU32::new(0x10),
                relative_base: Some(RelocationTarget::Address(SectionAddress::new(0, 0x200))),
            }
        );
        assert_eq!(vm2.ctr.confidence, Confidence2::High);
    }

    #[test]
    fn vm2_shadow_diff_report_is_empty_for_exact_legacy_mapping() {
        let mut legacy = VM::default();
        legacy.gpr[3].value = GprValue::Constant(0x1234);
        legacy.gpr[3].source.kind = GprSourceLocation::Register(9);
        legacy.gpr[3].source.version = 7;
        legacy.gpr[7].value = GprValue::Range { min: 0, max: 0x20, step: 2 };
        legacy.gpr[7].source.kind = GprSourceLocation::Stack(0x50);
        legacy.gpr[7].source.version = 11;
        legacy.stack_slots.insert(0x50, legacy.gpr[7]);
        legacy.lr = GprValue::Constant(0x2000);
        legacy.ctr = GprValue::Constant(0x3000);
        legacy.cr[0] = crate::analysis::vm::Cr {
            left: GprValue::Constant(1),
            right: GprValue::Constant(2),
            signed: false,
        };

        let vm2 = Vm2::from_legacy_vm(&legacy);
        let report = VmShadowDiffReport::from_legacy_pair(&legacy, &vm2);
        assert_eq!(
            report.summary.total(),
            0,
            "legacy-to-vm2 mapping should produce zero shadow diffs, got {:?}",
            report.entries
        );
        assert!(report.entries.is_empty(), "zero-diff report should have no entries");
    }

    #[test]
    fn vm2_shadow_diff_report_categorizes_mismatch_types() {
        let mut legacy = VM::default();
        legacy.gpr[3].value = GprValue::Constant(0x100);
        legacy.gpr[4].value = GprValue::Constant(0x200);
        legacy.gpr[4].source.kind = GprSourceLocation::Register(8);
        legacy.gpr[4].source.version = 2;
        legacy.gpr[5].value = GprValue::Constant(0x300);
        legacy.stack_slots.insert(0x20, legacy.gpr[3]);

        let mut vm2 = Vm2::from_legacy_vm(&legacy);
        vm2.gpr[3].value = Value2::Const(0x101);
        vm2.gpr[4].provenance = Provenance2::None;
        vm2.gpr[5].confidence = Confidence2::Low;
        vm2.stack_slots.remove(&0x20);

        let report = VmShadowDiffReport::from_legacy_pair(&legacy, &vm2);
        assert_eq!(report.summary.value, 1);
        assert_eq!(report.summary.provenance, 1);
        assert_eq!(report.summary.confidence, 1);
        assert_eq!(report.summary.presence, 1);
        assert_eq!(report.summary.total(), 4);
        assert_eq!(report.entries.len(), 4);
        assert!(report.entries.iter().any(|entry| entry.location == VmShadowLocation::Gpr(3)
            && entry.kind == VmShadowDiffKind::Value));
        assert!(report.entries.iter().any(|entry| entry.location == VmShadowLocation::Gpr(4)
            && entry.kind == VmShadowDiffKind::Provenance));
        assert!(report.entries.iter().any(|entry| entry.location == VmShadowLocation::Gpr(5)
            && entry.kind == VmShadowDiffKind::Confidence));
        assert!(report
            .entries
            .iter()
            .any(|entry| entry.location == VmShadowLocation::StackSlot(0x20)
                && entry.kind == VmShadowDiffKind::Presence));
    }

    #[test]
    fn vm_corpus_shadow_report_accumulates_fixture_summaries() {
        let mut report = VmCorpusShadowReport::default();
        report.push_fixture(VmCorpusShadowFixtureResult {
            test_id: 1,
            summary: VmShadowDiffSummary { value: 2, ..Default::default() },
            entries: vec![],
        });
        report.push_fixture(VmCorpusShadowFixtureResult {
            test_id: 2,
            summary: VmShadowDiffSummary { presence: 1, confidence: 3, ..Default::default() },
            entries: vec![],
        });
        report.push_fixture(VmCorpusShadowFixtureResult {
            test_id: 3,
            summary: VmShadowDiffSummary::default(),
            entries: vec![],
        });

        assert_eq!(report.fixture_count, 3);
        assert_eq!(report.mismatch_count, 2);
        assert_eq!(report.totals.presence, 1);
        assert_eq!(report.totals.value, 2);
        assert_eq!(report.totals.provenance, 0);
        assert_eq!(report.totals.confidence, 3);
        assert_eq!(report.total_diffs(), 6);
    }

    #[test]
    fn vm2_shadow_selected_corpus_has_zero_unresolved_deltas() {
        let fixtures: Vec<ShadowFixture> =
            serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml").unwrap())
                .expect("failed to read CFA fixture corpus");
        let selected = [1u32, 4u32, 8u32, 12u32, 19u32];
        let expected_fixture_count =
            fixtures.iter().filter(|fixture| selected.contains(&fixture.test_id)).count();

        let report = run_vm_shadow_corpus(&fixtures, Some(&selected));
        assert_eq!(report.fixture_count, expected_fixture_count);
        assert_eq!(
            report.mismatch_count,
            0,
            "vm selected corpus has mismatched fixtures: {:?}",
            report
                .fixtures
                .iter()
                .filter(|fixture| fixture.summary.total() != 0)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            report.total_diffs(),
            0,
            "vm selected corpus diff totals should be zero: {:?}",
            report
        );
    }

    #[test]
    fn vm2_shadow_full_corpus_has_zero_unresolved_deltas() {
        let fixtures: Vec<ShadowFixture> =
            serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml").unwrap())
                .expect("failed to read CFA fixture corpus");
        let report = run_vm_shadow_corpus(&fixtures, None);

        assert_eq!(report.fixture_count, fixtures.len());
        assert_eq!(
            report.mismatch_count,
            0,
            "vm full corpus has mismatched fixtures: {:?}",
            report
                .fixtures
                .iter()
                .filter(|fixture| fixture.summary.total() != 0)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            report.total_diffs(),
            0,
            "vm full corpus diff totals should be zero: {:?}",
            report
        );
    }
}
