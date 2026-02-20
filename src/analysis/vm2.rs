use std::{collections::BTreeMap, num::NonZeroU32};

use crate::analysis::{cfa::SectionAddress, RelocationTarget};

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
}
