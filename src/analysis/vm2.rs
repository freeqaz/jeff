use std::{collections::BTreeMap, num::NonZeroU32};

use crate::analysis::{
    cfa::SectionAddress,
    vm::{Gpr, GprSourceLocation, GprValue, JumpTableType, VM},
    RelocationTarget,
};

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
    Range { min: u64, max: u64, step: u64 },
    IndexedLoad {
        table_addr: RelocationTarget,
        max_offset: Option<NonZeroU32>,
        relative_base: Option<RelocationTarget>,
    },
    CompareTag { crf: u8 },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Provenance2 {
    None,
    Reg { reg: u8, revision: usize },
    StackSlot { offset: i16, revision: usize },
    Memory { address: RelocationTarget, revision: usize },
    LegacyMemory { slot: usize, revision: usize },
    LegacyMemoryOffset {
        base_slot: usize,
        offset_register: u8,
        revision: usize,
    },
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
    fn default() -> Self { Self::top() }
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
    pub fn new() -> Self { Self::default() }

    fn map_legacy_value(value: GprValue) -> (Value2, Confidence2) {
        match value {
            GprValue::Unknown => (Value2::Top, Confidence2::Low),
            GprValue::Constant(value) => (Value2::Const(value), Confidence2::High),
            GprValue::Address(address) => (Value2::Address(address), Confidence2::High),
            GprValue::ComparisonResult(crf) => (Value2::CompareTag { crf }, Confidence2::Medium),
            GprValue::Range { min, max, step } => {
                (Value2::Range { min, max, step }, if step == 0 { Confidence2::Low } else { Confidence2::High })
            }
            GprValue::LoadIndexed {
                jump_table_type,
                jump_table_address,
                max_offset,
            } => (
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
            GprSourceLocation::Register(reg) => Provenance2::Reg {
                reg: reg as u8,
                revision: gpr.source.version,
            },
            GprSourceLocation::Stack(offset) => Provenance2::StackSlot {
                offset: offset as i16,
                revision: gpr.source.version,
            },
            GprSourceLocation::Memory(address) => Provenance2::LegacyMemory {
                slot: address,
                revision: gpr.source.version,
            },
            GprSourceLocation::MemoryOffset {
                address,
                offset_register,
            } => Provenance2::LegacyMemoryOffset {
                base_slot: address,
                offset_register: offset_register as u8,
                revision: gpr.source.version,
            },
        }
    }

    fn fact_from_legacy_gpr(gpr: &Gpr) -> ValueFact2 {
        let (value, confidence) = Self::map_legacy_value(gpr.value);
        ValueFact2 {
            value,
            provenance: Self::map_legacy_provenance(gpr),
            confidence,
        }
    }

    fn fact_from_legacy_value(value: GprValue) -> ValueFact2 {
        let (mapped, confidence) = Self::map_legacy_value(value);
        ValueFact2 { value: mapped, provenance: Provenance2::None, confidence }
    }

    pub fn from_legacy_vm(legacy: &VM) -> Self {
        let mut vm2 = Self::new();
        for reg in 0..32 {
            vm2.gpr[reg] = Self::fact_from_legacy_gpr(&legacy.gpr[reg]);
        }
        for crf in 0..8 {
            let cr = &legacy.cr[crf];
            vm2.cr[crf] = if cr.left == GprValue::Unknown && cr.right == GprValue::Unknown {
                ValueFact2::top()
            } else {
                ValueFact2 {
                    value: Value2::CompareTag { crf: crf as u8 },
                    provenance: Provenance2::None,
                    confidence: Confidence2::Medium,
                }
            };
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
    pub fn set_reg(&mut self, reg: u8, value: Value2, provenance: Provenance2, confidence: Confidence2) {
        self.gpr[reg as usize] = ValueFact2 { value, provenance, confidence };
    }

    #[inline]
    pub fn reg(&self, reg: u8) -> &ValueFact2 { &self.gpr[reg as usize] }

    #[inline]
    pub fn write_stack_slot(&mut self, offset: i16, fact: ValueFact2) {
        self.stack_slots.insert(offset, fact);
    }

    #[inline]
    pub fn read_stack_slot(&self, offset: i16) -> Option<&ValueFact2> { self.stack_slots.get(&offset) }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BranchFact2 {
    pub target: Option<SectionAddress>,
    pub vm: Vm2,
    pub confidence: Confidence2,
}

#[cfg(test)]
mod tests {
    use super::*;
    use powerpc::{Extensions, Ins};

    use crate::{
        analysis::vm::{BranchTarget, StepResult},
        obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind},
    };

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
        legacy.gpr[6].source.kind = GprSourceLocation::MemoryOffset {
            address: 0x80,
            offset_register: 9,
        };
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
}
