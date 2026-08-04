use std::{collections::BTreeMap, num::NonZeroU32};

use powerpc::{Argument, Ins, Opcode, GPR};

use crate::{
    analysis::{cfa::SectionAddress, disassemble, relocation_target_for, RelocationTarget},
    obj::{ObjInfo, ObjKind},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpTableType {
    // the table came from an lwzx, contains absolute addresses
    Absolute,
    // the table came from an lbzx, contains relative byte offsets (no rlwinm before the bctr)
    RelativeBytes(Option<RelocationTarget>),
    // the table came from an lbzx, contains relative byte offsets that we must multiply by 4
    RelativeBytesTimes4(Option<RelocationTarget>),
    // the table came from an lhzx, contains relative short offsets (no rlwinm before the bctr)
    RelativeShorts(Option<RelocationTarget>),
    // the table came from an lhzx, contains relative short offsets that we must multiply by 2
    RelativeShortsTimes2(Option<RelocationTarget>),
}

/// Renamed from Value — the abstract value tracked for a register.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Value {
    #[default]
    /// Value is unknown (lattice top)
    Unknown,
    /// Value is a constant
    Constant(u64),
    /// Value is a known relocated address
    Address(RelocationTarget),
    /// Comparison result (CR field)
    ComparisonResult(u8),
    /// Value is within a range
    Range { min: u64, max: u64, step: u64 },
    /// Value is loaded from an address with a max offset (jump table)
    LoadIndexed {
        jump_table_type: JumpTableType,
        jump_table_address: RelocationTarget,
        max_offset: Option<NonZeroU32>,
    },
}

/// Collapses GprSourceLocation + GprSource: where a value came from.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Provenance {
    #[default]
    None,
    Register { reg: u8, revision: usize },
    Stack { offset: usize, revision: usize },
    Memory { address: usize, revision: usize },
    MemoryOffset { address: usize, offset_register: u8, revision: usize },
}

/// Replaces Gpr — value + provenance + revision + relocation metadata.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct RegState {
    pub value: Value,
    pub provenance: Provenance,
    pub revision: usize,
    /// Address that loads the hi part of this GPR
    pub hi_addr: Option<SectionAddress>,
    /// Address that loads the lo part of this GPR
    pub lo_addr: Option<SectionAddress>,
}


impl RegState {
    fn set_direct(&mut self, value: Value, src_reg: Option<u8>) {
        self.value = value;
        self.hi_addr = None;
        self.lo_addr = None;
        self.set_source(src_reg);
    }

    fn set_hi(&mut self, value: Value, addr: SectionAddress, src_reg: Option<u8>) {
        self.value = value;
        self.hi_addr = Some(addr);
        self.lo_addr = None;
        self.set_source(src_reg);
    }

    fn set_lo(&mut self, value: Value, addr: SectionAddress, hi_gpr: RegState, src_reg: Option<u8>) {
        self.value = value;
        self.hi_addr = hi_gpr.hi_addr;
        self.lo_addr = Some(hi_gpr.lo_addr.unwrap_or(addr));
        self.set_source(src_reg);
    }

    fn set_source(&mut self, src_reg: Option<u8>) {
        match src_reg {
            Some(reg_num) => {
                self.provenance = Provenance::Register {
                    reg: reg_num,
                    revision: self.revision,
                };
            }
            None => {
                self.provenance = Provenance::None;
            }
        }
        self.revision += 1;
    }

    fn address(&self, obj: &ObjInfo, ins_addr: SectionAddress) -> Option<RelocationTarget> {
        match self.value {
            Value::Constant(value) => section_address_for(obj, ins_addr, value as u32),
            Value::Address(target) => Some(target),
            _ => None,
        }
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Cr {
    /// The left-hand value of this comparison
    pub left: Value,
    /// The right-hand value of this comparison
    pub right: Value,
    /// Whether this comparison is signed
    pub signed: bool,
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct VM {
    /// General purpose registers
    pub gpr: [RegState; 32],
    /// Condition registers
    pub cr: [Cr; 8],
    /// Link register
    pub lr: RegState,
    /// Count register
    pub ctr: RegState,
    /// The last modified CR
    pub last_modified_cr: u8,
    /// Stack slot tracking: maps r1-relative offsets to stored register states
    pub stack_slots: BTreeMap<i16, RegState>,
}

impl VM {
    pub fn gpr_value(&self, reg: u8) -> Value {
        self.gpr[reg as usize].value
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BranchTarget {
    /// Unknown branch target (CTR without known value)
    Unknown,
    /// Branch to LR
    Return,
    /// Branch to address
    Address(RelocationTarget),
    /// Branch to jump table
    JumpTable {
        jump_table_type: JumpTableType,
        jump_table_address: RelocationTarget,
        size: Option<NonZeroU32>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Branch {
    /// Branch target
    pub target: BranchTarget,
    /// Branch with link
    pub link: bool,
    /// VM state for this branch
    pub vm: Box<VM>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum StepResult {
    /// Continue normally
    Continue,
    /// Load from / store to
    LoadStore { address: RelocationTarget, source: RegState, source_reg: u8 },
    /// Hit illegal instruction
    Illegal,
    /// Jump without affecting VM state
    Jump(BranchTarget),
    /// Branch with split VM states
    Branch(Vec<Branch>),
}

pub fn section_address_for(
    obj: &ObjInfo,
    ins_addr: SectionAddress,
    target_addr: u32,
) -> Option<RelocationTarget> {
    if let Some(target) = relocation_target_for(obj, ins_addr, None).ok().flatten() {
        return Some(target);
    }
    if obj.kind == ObjKind::Executable {
        let (section_index, _) = obj.sections.at_address(target_addr).ok()?;
        return Some(RelocationTarget::Address(SectionAddress::new(section_index, target_addr)));
    }
    if obj.sections[ins_addr.section].contains(target_addr) {
        Some(RelocationTarget::Address(SectionAddress::new(ins_addr.section, target_addr)))
    } else {
        None
    }
}

impl VM {
    #[inline]
    pub fn new() -> Box<Self> {
        Box::default()
    }

    #[inline]
    pub fn new_from_obj(obj: &ObjInfo) -> Box<Self> {
        Self::new_with_base(obj.sda2_base, obj.sda_base)
    }

    #[inline]
    pub fn new_with_base(sda2_base: Option<u32>, sda_base: Option<u32>) -> Box<Self> {
        let mut vm = Self::new();
        if let Some(value) = sda2_base {
            vm.gpr[2].value = Value::Constant(value as u64);
        }
        if let Some(value) = sda_base {
            vm.gpr[13].value = Value::Constant(value as u64);
        }
        vm
    }

    /// When calling a function, only preserve SDA bases
    #[inline]
    pub fn clone_for_link(&self) -> Box<Self> {
        let mut vm = Self::new();
        vm.gpr[2].value = self.gpr[2].value;
        vm.gpr[13].value = self.gpr[13].value;
        vm
    }

    /// When returning from a function call, only dedicated
    /// and nonvolatile registers are preserved
    #[inline]
    pub fn clone_for_return(&self) -> Box<Self> {
        let mut vm = Self::new();
        // Dedicated registers
        vm.gpr[1].value = self.gpr[1].value;
        vm.gpr[2].value = self.gpr[2].value;
        vm.gpr[13].value = self.gpr[13].value;
        // Non-volatile registers
        for i in 14..32 {
            vm.gpr[i] = self.gpr[i];
        }
        vm
    }

    #[inline]
    pub fn clone_all(&self) -> Box<Self> {
        Box::new(self.clone())
    }

    pub fn step(&mut self, obj: &ObjInfo, ins_addr: SectionAddress, ins: Ins) -> StepResult {
        match ins.op {
            Opcode::Illegal => {
                // Distinguish inter-function alignment padding from a real
                // decoder gap. MSVC pads .text with a single 0x00000000 word to
                // 8-align the next function, so a linear walk that steps past a
                // hard terminator (b / blr / bctr) lands on one. Measured on RB3
                // retail (45410914): all 265 sites are exactly 0x00000000, 262
                // sit immediately after an unconditional terminator, 264 are at
                // addr % 8 == 4, and all 265 fall in gaps between .pdata extents
                // — i.e. none is inside any function. That is expected scan
                // behaviour, not a finding, so it must not be reported as one.
                //
                // A NON-zero illegal word is a different animal: it means the
                // disassembler could not decode a word that really is inside
                // code (e.g. a VMX128 form we don't model). Keep that visible at
                // debug and include the word so it is actionable.
                //
                // This was a bare println! that bypassed tracing entirely, so it
                // could not be filtered by RUST_LOG at all — 311 unfilterable
                // lines per split.
                if ins.code == 0 {
                    log::trace!("Alignment padding at {:#010X} (0x00000000)", ins_addr.address);
                } else {
                    log::debug!(
                        "Undecodable instruction {:#010X} at {:#010X}",
                        ins.code,
                        ins_addr.address,
                    );
                }
                return StepResult::Illegal;
            }
            // add rD, rA, rB
            Opcode::Add => {
                let left = self.gpr[ins.field_ra() as usize].value;
                let right = self.gpr[ins.field_rb() as usize].value;
                let value = match (left, right) {
                    (Value::Constant(left), Value::Constant(right)) => {
                        Value::Constant(left.wrapping_add(right))
                    }
                    (
                        Value::Address(RelocationTarget::Address(left)),
                        Value::Constant(right),
                    ) => Value::Address(RelocationTarget::Address(
                        left.wrapping_add(right as u32),
                    )),
                    (
                        Value::Constant(left),
                        Value::Address(RelocationTarget::Address(right)),
                    ) => Value::Address(RelocationTarget::Address(
                        right.wrapping_add(left as u32),
                    )),
                    (
                        Value::Constant(left),
                        Value::LoadIndexed {
                            jump_table_type: jt,
                            jump_table_address: ja,
                            max_offset: m,
                        },
                    ) => {
                        match jt {
                            // if we reached this point, this should be a relative jump table
                            JumpTableType::Absolute => {
                                // this probably isn't a jump table anyway, so just keep the load indexed value
                                Value::LoadIndexed {
                                    jump_table_type: jt,
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                            // anyways, mark down the relative address we should be adding offsets to
                            JumpTableType::RelativeBytes(addr) => {
                                assert!(
                                    addr.is_none(),
                                    "Relative addr should not be known at this point!"
                                );
                                Value::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeBytes(Some(
                                        RelocationTarget::Address(SectionAddress::new(
                                            ins_addr.section,
                                            left as u32,
                                        )),
                                    )),
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                            JumpTableType::RelativeBytesTimes4(addr) => {
                                assert!(
                                    addr.is_none(),
                                    "Relative addr should not be known at this point!"
                                );
                                Value::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeBytesTimes4(Some(
                                        RelocationTarget::Address(SectionAddress::new(
                                            ins_addr.section,
                                            left as u32,
                                        )),
                                    )),
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                            JumpTableType::RelativeShorts(addr) => {
                                assert!(
                                    addr.is_none(),
                                    "Relative addr should not be known at this point!"
                                );
                                Value::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeShorts(Some(
                                        RelocationTarget::Address(SectionAddress::new(
                                            ins_addr.section,
                                            left as u32,
                                        )),
                                    )),
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                            JumpTableType::RelativeShortsTimes2(addr) => {
                                assert!(
                                    addr.is_none(),
                                    "Relative addr should not be known at this point!"
                                );
                                Value::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeShortsTimes2(Some(
                                        RelocationTarget::Address(SectionAddress::new(
                                            ins_addr.section,
                                            left as u32,
                                        )),
                                    )),
                                    jump_table_address: ja,
                                    max_offset: m,
                                }
                            }
                        }
                    }
                    _ => Value::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // addis rD, rA, SIMM
            Opcode::Addis => {
                if let Some(target) =
                    relocation_target_for(obj, ins_addr, None /* TODO */).ok().flatten()
                {
                    debug_assert_eq!(ins.field_ra(), 0);
                    self.gpr[ins.field_rd() as usize].set_hi(
                        Value::Address(target),
                        ins_addr,
                        None,
                    );
                } else {
                    let left = if ins.field_ra() == 0 {
                        Value::Constant(0)
                    } else {
                        self.gpr[ins.field_ra() as usize].value
                    };
                    let value = match left {
                        Value::Constant(value) => {
                            Value::Constant(value.wrapping_add((ins.field_simm() as u64) << 16))
                        }
                        _ => Value::Unknown,
                    };
                    if ins.field_ra() == 0 {
                        // lis rD, SIMM
                        self.gpr[ins.field_rd() as usize].set_hi(value, ins_addr, None);
                    } else {
                        self.gpr[ins.field_rd() as usize].set_direct(value, None);
                    }
                }
            }
            // addi rD, rA, SIMM
            // addic rD, rA, SIMM
            // addic. rD, rA, SIMM
            Opcode::Addi | Opcode::Addic | Opcode::Addic_ => {
                if let Some(target) =
                    relocation_target_for(obj, ins_addr, None /* TODO */).ok().flatten()
                {
                    self.gpr[ins.field_rd() as usize].set_lo(
                        Value::Address(target),
                        ins_addr,
                        self.gpr[ins.field_ra() as usize],
                        None,
                    );
                } else {
                    let load_zero = ins.field_ra() == 0 && ins.op == Opcode::Addi;
                    let left = if load_zero {
                        Value::Constant(0)
                    } else {
                        self.gpr[ins.field_ra() as usize].value
                    };
                    let value = match left {
                        Value::Constant(value) => {
                            Value::Constant(value.wrapping_add(ins.field_simm() as u64))
                        }
                        Value::Address(RelocationTarget::Address(address)) => Value::Address(
                            RelocationTarget::Address(address.offset(ins.field_simm() as i32)),
                        ),
                        _ => Value::Unknown,
                    };
                    if load_zero {
                        // li rD, SIMM
                        self.gpr[ins.field_rd() as usize].set_direct(value, None);
                    } else {
                        self.gpr[ins.field_rd() as usize].set_lo(
                            value,
                            ins_addr,
                            self.gpr[ins.field_ra() as usize],
                            None,
                        );
                    }
                }
            }
            // subf rD, rA, rB
            // subfc rD, rA, rB
            Opcode::Subf | Opcode::Subfc => {
                self.gpr[ins.field_rd() as usize].set_direct(
                    match (
                        self.gpr[ins.field_ra() as usize].value,
                        self.gpr[ins.field_rb() as usize].value,
                    ) {
                        (Value::Constant(left), Value::Constant(right)) => {
                            Value::Constant((!left).wrapping_add(right).wrapping_add(1))
                        }
                        _ => Value::Unknown,
                    },
                    None,
                );
            }
            // subfic rD, rA, SIMM
            Opcode::Subfic => {
                self.gpr[ins.field_rd() as usize].set_direct(
                    match self.gpr[ins.field_ra() as usize].value {
                        Value::Constant(value) => Value::Constant(
                            (!value).wrapping_add(ins.field_simm() as u64).wrapping_add(1),
                        ),
                        _ => Value::Unknown,
                    },
                    None,
                );
            }
            // ori rA, rS, UIMM
            Opcode::Ori => {
                // evil hack to get through what are effectively nops (ori rX, rX, 0)
                if ins.field_uimm() == 0 && ins.field_ra() == ins.field_rs() {
                    // don't do anything
                } else if let Some(target) =
                    relocation_target_for(obj, ins_addr, None /* TODO */).ok().flatten()
                {
                    self.gpr[ins.field_ra() as usize].set_lo(
                        Value::Address(target),
                        ins_addr,
                        self.gpr[ins.field_rs() as usize],
                        None,
                    );
                } else {
                    let value = match self.gpr[ins.field_rs() as usize].value {
                        Value::Constant(value) => {
                            Value::Constant(value | ins.field_uimm() as u64)
                        }
                        _ => Value::Unknown,
                    };
                    self.gpr[ins.field_ra() as usize].set_lo(
                        value,
                        ins_addr,
                        self.gpr[ins.field_rs() as usize],
                        None,
                    );
                }
            }
            // or rA, rS, rB
            Opcode::Or => {
                if ins.field_rs() == ins.field_rb() {
                    // Register copy
                    let src_reg = ins.field_rs() as usize;
                    let dst_reg = ins.field_ra() as usize;
                    let src = self.gpr[src_reg];
                    self.gpr[dst_reg] = src;
                    if let Provenance::Stack { offset, .. } = src.provenance {
                        // Preserve stack-slot provenance across register renames.
                        self.gpr[dst_reg].provenance = Provenance::Stack {
                            offset,
                            revision: self.gpr[dst_reg].revision,
                        };
                        self.gpr[dst_reg].revision += 1;
                    } else {
                        self.gpr[dst_reg].set_source(Some(ins.field_rs()));
                    }
                } else {
                    let left = self.gpr[ins.field_rs() as usize].value;
                    let right = self.gpr[ins.field_rb() as usize].value;
                    let value = match (left, right) {
                        (Value::Constant(left), Value::Constant(right)) => {
                            Value::Constant(left | right)
                        }
                        _ => Value::Unknown,
                    };
                    self.gpr[ins.field_ra() as usize].set_direct(value, None);
                }
            }
            // cmp [crfD], [L], rA, rB
            // cmpi [crfD], [L], rA, SIMM
            // cmpl [crfD], [L], rA, rB
            // cmpli [crfD], [L], rA, UIMM
            Opcode::Cmp | Opcode::Cmpi | Opcode::Cmpl | Opcode::Cmpli => {
                if ins.field_l() == 0 {
                    let left_reg = ins.field_ra() as usize;
                    let left = self.gpr[left_reg].value;
                    let (right, signed) = match ins.op {
                        Opcode::Cmp => (self.gpr[ins.field_rb() as usize].value, true),
                        Opcode::Cmpl => (self.gpr[ins.field_rb() as usize].value, false),
                        Opcode::Cmpi => (Value::Constant(ins.field_simm() as u64), true),
                        Opcode::Cmpli => (Value::Constant(ins.field_uimm() as u64), false),
                        _ => unreachable!(),
                    };
                    let crf = ins.field_crfd();
                    self.cr[crf as usize] = Cr { signed, left, right };
                    self.gpr[left_reg].value = Value::ComparisonResult(crf);
                    self.last_modified_cr = crf;
                }
            }
            // rlwinm rA, rS, SH, MB, ME
            // rlwnm rA, rS, rB, MB, ME
            Opcode::Rlwinm | Opcode::Rlwnm => {
                let value = if let Some(shift) = match ins.op {
                    Opcode::Rlwinm => Some(ins.field_sh() as u32),
                    Opcode::Rlwnm => match self.gpr[ins.field_rb() as usize].value {
                        Value::Constant(value) => Some(value as u32),
                        _ => None,
                    },
                    _ => unreachable!(),
                } {
                    let mask = mask_value(ins.field_mb() as u32, ins.field_me() as u32);

                    // for jump table detection - check to see if rS has a source reg we can pull data from
                    if self.gpr[ins.field_rs() as usize].value == Value::Unknown {
                        // try to find source reg
                        let prov = self.gpr[ins.field_rs() as usize].provenance;
                        match prov {
                            Provenance::Register { reg, revision } => {
                                // check the src reg and the current revision
                                // it MUST match src reg's current revision in order to pull data from it
                                if self.gpr[reg as usize].revision == revision {
                                    if self.gpr[reg as usize].value != Value::Unknown {
                                        self.gpr[ins.field_rs() as usize].value = self.gpr[reg as usize].value;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }

                    match self.gpr[ins.field_rs() as usize].value {
                        // set everything as u32s before rotating
                        // because although regs are 64 bits on Xbox, 32-bit instructions run in 32-bit mode
                        Value::Constant(value) => {
                            Value::Constant(((value as u32).rotate_left(shift) & mask) as u64)
                        }
                        Value::Range { min, max, step } => Value::Range {
                            min: ((min as u32).rotate_left(shift) & mask) as u64,
                            max: ((max as u32).rotate_left(shift) & mask) as u64,
                            step: ((step as u32).rotate_left(shift)) as u64,
                        },
                        // if we've come across a rlwinm as a LoadIndexed...
                        Value::LoadIndexed {
                            jump_table_type: jt,
                            jump_table_address: ja,
                            max_offset: m,
                        } => {
                            let ret = match jt {
                                JumpTableType::Absolute => Value::LoadIndexed {
                                    jump_table_type: jt,
                                    jump_table_address: ja,
                                    max_offset: m,
                                },
                                // if the table type is currently relative, it means we need to multiply offsets by 4
                                JumpTableType::RelativeBytes(addr) => Value::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeBytesTimes4(addr),
                                    jump_table_address: ja,
                                    max_offset: m,
                                },
                                JumpTableType::RelativeBytesTimes4(addr) => {
                                    log::warn!("Reached rlwinm with a JumpTableType of RelativeTimes4. Can we even reach this point? {}", ins_addr);
                                    Value::LoadIndexed {
                                        jump_table_type: JumpTableType::RelativeBytesTimes4(addr),
                                        jump_table_address: ja,
                                        max_offset: m,
                                    }
                                }
                                JumpTableType::RelativeShorts(addr) => Value::LoadIndexed {
                                    jump_table_type: JumpTableType::RelativeShortsTimes2(addr),
                                    jump_table_address: ja,
                                    max_offset: m,
                                },
                                JumpTableType::RelativeShortsTimes2(addr) => {
                                    log::warn!("Reached rlwinm with a JumpTableType of RelativeTimes2. Can we even reach this point? {}", ins_addr);
                                    Value::LoadIndexed {
                                        jump_table_type: JumpTableType::RelativeShortsTimes2(addr),
                                        jump_table_address: ja,
                                        max_offset: m,
                                    }
                                }
                            };
                            ret
                        }
                        _ => Value::Range {
                            min: 0,
                            max: mask as u64,
                            step: 1u64.rotate_left(shift),
                        },
                    }
                } else {
                    Value::Unknown
                };
                self.gpr[ins.field_ra() as usize].set_direct(value, None);
            }
            // b[l][a] target_addr
            // b[c][l][a] BO, BI, target_addr
            // b[c]ctr[l] BO, BI
            // b[c]lr[l] BO, BI
            Opcode::B | Opcode::Bc | Opcode::Bcctr | Opcode::Bclr => {
                // HACK for `bla 0x60` in __OSDBJump
                if ins.op == Opcode::B && ins.field_lk() && ins.field_aa() {
                    return StepResult::Jump(BranchTarget::Unknown);
                }

                let branch_target = match ins.op {
                    Opcode::Bcctr => {
                        match self.ctr.value {
                            Value::Constant(value) => {
                                // TODO only check valid target?
                                if let Some(target) = section_address_for(obj, ins_addr, value as u32) {
                                    BranchTarget::Address(target)
                                } else {
                                    BranchTarget::Unknown
                                }
                            },
                            Value::Address(target) => BranchTarget::Address(target),
                            Value::LoadIndexed { jump_table_type: jtype, jump_table_address: address, max_offset }
                            // FIXME: avoids treating bctrl indirect calls as jump tables
                            if !ins.field_lk() => {
                                let add_increment = match jtype {
                                    JumpTableType::Absolute => 4,
                                    JumpTableType::RelativeBytes(_) | JumpTableType::RelativeBytesTimes4(_) => 1,
                                    JumpTableType::RelativeShorts(_) | JumpTableType::RelativeShortsTimes2(_) => 2,
                                };
                                BranchTarget::JumpTable { jump_table_type: jtype, jump_table_address: address,
                                    size: max_offset.and_then(|n| n.checked_add( add_increment)) }
                            },
                            _ => BranchTarget::Unknown,
                        }
                    }
                    Opcode::Bclr => BranchTarget::Return,
                    _ => {
                        let value = ins.branch_dest(ins_addr.address).unwrap();
                        if let Some(target) = section_address_for(obj, ins_addr, value) {
                            BranchTarget::Address(target)
                        } else {
                            BranchTarget::Unknown
                        }
                    }
                };

                // If branching with link, use function call semantics
                if ins.field_lk() {
                    return StepResult::Branch(vec![
                        Branch {
                            target: BranchTarget::Address(RelocationTarget::Address(ins_addr + 4)),
                            link: false,
                            vm: self.clone_for_return(),
                        },
                        Branch { target: branch_target, link: true, vm: self.clone_for_link() },
                    ]);
                }

                // Branch always
                if ins.op == Opcode::B || ins.field_bo() & 0b10100 == 0b10100 {
                    return StepResult::Jump(branch_target);
                }

                // Branch conditionally
                let mut branches = vec![
                    // Branch not taken
                    Branch {
                        target: BranchTarget::Address(RelocationTarget::Address(ins_addr + 4)),
                        link: false,
                        vm: self.clone_all(),
                    },
                    // Branch taken
                    Branch { target: branch_target, link: ins.field_lk(), vm: self.clone_all() },
                ];

                // Use tracked CR to calculate new register values for branches
                let crf = (ins.field_bi() >> 2) as usize;
                let crb = ins.field_bi() & 3;
                let (f_val, t_val) =
                    split_values_by_crb(crb, self.cr[crf].left, self.cr[crf].right);
                if ins.field_bo() & 0b11110 == 0b00100 {
                    // Branch if false
                    branches[0].vm.set_comparison_result(t_val, crf);
                    branches[1].vm.set_comparison_result(f_val, crf);
                } else if ins.field_bo() & 0b11110 == 0b01100 {
                    // Branch if true
                    branches[0].vm.set_comparison_result(f_val, crf);
                    branches[1].vm.set_comparison_result(t_val, crf);
                }

                return StepResult::Branch(branches);
            }
            // lwzx rD, rA, rB
            Opcode::Lwzx => {
                let left = self.gpr[ins.field_ra() as usize].address(obj, ins_addr);
                let right = self.gpr[ins.field_rb() as usize].value;
                let value = match (left, right) {
                    (Some(address), Value::Range { min: _, max, .. })
                        if /*min == 0 &&*/ max < u64::MAX - 4 && max & 3 == 0 =>
                    {
                        // If the jump_table_address is within .text (supposed to be right after the bctr), this is a jump table
                        // else, this is a data table (i.e. an array of strings)
                        // but! since no bctr's come after data tables, these don't get treated like jump tables, soooooo I think this is fine?
                        Value::LoadIndexed { jump_table_type: JumpTableType::Absolute, jump_table_address: address, max_offset: NonZeroU32::new(max as u32) }
                    }
                    (Some(address), _) => {
                        Value::LoadIndexed { jump_table_type: JumpTableType::Absolute, jump_table_address: address, max_offset: None }
                    }
                    _ => Value::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // lbzx rD, rA, rB
            Opcode::Lbzx => {
                let left = self.gpr[ins.field_ra() as usize].address(obj, ins_addr);
                let right = self.gpr[ins.field_rb() as usize].value;
                let value = match (left, right) {
                    (Some(address), Value::Range { min: _, max, .. })
                        if /*min == 0 &&*/ max < u64::MAX - 4 =>
                    {
                        // if we never encountered a bgt before this, we don't know the bounds for sure
                        let bounds_known: bool = match self.cr[self.last_modified_cr as usize].right {
                            Value::Constant(c) => { max == c },
                            _ => false,
                        };
                        Value::LoadIndexed {
                            jump_table_type: JumpTableType::RelativeBytes(None),
                            jump_table_address: address,
                            max_offset: if bounds_known { NonZeroU32::new(max as u32) } else { None } }
                    }
                    (Some(address), _) => {
                        Value::LoadIndexed { jump_table_type: JumpTableType::RelativeBytes(None), jump_table_address: address, max_offset: None }
                    }
                    _ => Value::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // lhzx rD, rA, rB
            Opcode::Lhzx => {
                let left = self.gpr[ins.field_ra() as usize].address(obj, ins_addr);
                let right = self.gpr[ins.field_rb() as usize].value;
                let value = match (left, right) {
                    (Some(address), Value::Range { min: _, max, .. })
                    if /*min == 0 &&*/ max < u64::MAX - 4 && max & 1 == 0 =>
                        {
                            Value::LoadIndexed { jump_table_type: JumpTableType::RelativeShorts(None), jump_table_address: address, max_offset: NonZeroU32::new(max as u32) }
                        }
                    (Some(address), _) => {
                        Value::LoadIndexed { jump_table_type: JumpTableType::RelativeShorts(None), jump_table_address: address, max_offset: None }
                    }
                    _ => Value::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // mtspr SPR, rS
            Opcode::Mtspr => match ins.field_spr() {
                8 => self.lr.value = self.gpr[ins.field_rs() as usize].value,
                9 => self.ctr.value = self.gpr[ins.field_rs() as usize].value,
                _ => {}
            },
            // mfspr rD, SPR
            Opcode::Mfspr => {
                let value = match ins.field_spr() {
                    8 => self.lr.value,
                    9 => self.ctr.value,
                    _ => Value::Unknown,
                };
                self.gpr[ins.field_rd() as usize].set_direct(value, None);
            }
            // rfi
            Opcode::Rfi | Opcode::Rfid => {
                return StepResult::Jump(BranchTarget::Unknown);
            }
            op if is_load_store_op(op) => {
                let source = ins.field_ra() as usize;
                let mut result = StepResult::Continue;
                if let Value::Address(target) = self.gpr[source].value {
                    if is_update_op(op) {
                        self.gpr[source].set_lo(
                            Value::Address(target),
                            ins_addr,
                            self.gpr[source],
                            None,
                        );
                    }
                    result = StepResult::LoadStore {
                        address: target,
                        source: self.gpr[source],
                        source_reg: source as u8,
                    };
                } else if let Value::Constant(base) = self.gpr[source].value {
                    let address = base.wrapping_add(ins.field_simm() as u64) as u32;
                    if let Some(target) = section_address_for(obj, ins_addr, address) {
                        if is_update_op(op) {
                            self.gpr[source].set_lo(
                                Value::Address(target),
                                ins_addr,
                                self.gpr[source],
                                None,
                            );
                        }
                        result = StepResult::LoadStore {
                            address: target,
                            source: self.gpr[source],
                            source_reg: source as u8,
                        };
                    }
                } else if is_update_op(op) {
                    self.gpr[source].set_direct(Value::Unknown, None);
                }
                // Track stack stores: stw rS, offset(r1)
                if op == Opcode::Stw && ins.field_ra() == 1 {
                    let offset = ins.field_offset() as i16;
                    let rs = ins.field_rs() as usize;
                    self.stack_slots.insert(offset, self.gpr[rs]);
                }
                if op == Opcode::Lwz {
                    // Check stack slot tracking first: lwz rD, offset(r1)
                    if ins.field_ra() == 1 {
                        let offset = ins.field_offset() as i16;
                        if let Some(stored_gpr) = self.stack_slots.get(&offset).cloned() {
                            let mut gpr = stored_gpr;
                            gpr.provenance = Provenance::Stack {
                                offset: offset as usize,
                                revision: gpr.revision,
                            };
                            self.gpr[ins.field_rd() as usize] = gpr;
                            return result;
                        }
                    }
                    // the following sequence checkers are terrible hacks
                    // the "proper" way to do it would be to track values of stack offsets/memory offsets as they're written to/read from,
                    // but for the life me i can't figure out how to do that
                    // so until that system gets implemented, these hacks will have to do
                    let section = obj.sections.at_address(ins_addr.address).expect("no section").1;
                    // check for the evil microsoft jump table bound sequence: lwz, cmplwi, bgt, lwz
                    // we're gonna check for the sequence from the second lwz
                    if ins_addr.address - section.address as u32 >= 12 {
                        if let (Some(first_lwz), Some(cmp), Some(bgt)) = (
                            disassemble(section, ins_addr.address.wrapping_sub(12)),
                            disassemble(section, ins_addr.address.wrapping_sub(8)),
                            disassemble(section, ins_addr.address.wrapping_sub(4)),
                        ) {
                            let is_lwz = first_lwz.op == Opcode::Lwz
                                && first_lwz.field_ra() == ins.field_ra()
                                && first_lwz.field_offset() == ins.field_offset();
                            let is_cmplwi = cmp.op == Opcode::Cmpli && cmp.field_l() == 0;
                            let is_bgt = bgt.op == Opcode::Bc
                                && (bgt.field_bo() & 30) == 12
                                && (bgt.field_bi() & 3) == 1;

                            // if we've found the sequence, retrieve the data
                            if is_lwz && is_cmplwi && is_bgt {
                                // println!("found sequence at {}!", ins_addr);
                                self.gpr[ins.field_rd() as usize].set_direct(
                                    self.gpr[first_lwz.field_rd() as usize].value,
                                    None,
                                );
                                return result;
                            }
                        }
                    }
                    // check for the evil microsoft jump table bound sequence: lwz, cmplwi, ble, b, lwz
                    if ins_addr.address - section.address as u32 >= 16 {
                        if let (Some(first_lwz), Some(cmp), Some(ble), Some(branch)) = (
                            disassemble(section, ins_addr.address.wrapping_sub(16)),
                            disassemble(section, ins_addr.address.wrapping_sub(12)),
                            disassemble(section, ins_addr.address.wrapping_sub(8)),
                            disassemble(section, ins_addr.address.wrapping_sub(4)),
                        ) {
                            let is_lwz = first_lwz.op == Opcode::Lwz
                                && first_lwz.field_ra() == ins.field_ra()
                                && first_lwz.field_offset() == ins.field_offset();
                            let is_cmplwi = cmp.op == Opcode::Cmpli && cmp.field_l() == 0;
                            let is_ble = ble.op == Opcode::Bc
                                && (ble.field_bo() & 30) == 4
                                && (ble.field_bi() & 3) == 1;
                            let is_branch =
                                branch.op == Opcode::B && !branch.field_aa() && !branch.field_lk();

                            // if we've found the sequence, retrieve the data
                            if is_lwz && is_cmplwi && is_ble && is_branch {
                                // println!("found sequence at {}!", ins_addr);
                                self.gpr[ins.field_rd() as usize].set_direct(
                                    self.gpr[first_lwz.field_rd() as usize].value,
                                    None,
                                );
                                return result;
                            }
                        }
                    }
                }
                if is_load_op(op) {
                    self.gpr[ins.field_rd() as usize].set_direct(Value::Unknown, None);
                }
                return result;
            }
            _ => {
                for argument in ins.defs() {
                    if let Argument::GPR(GPR(reg)) = argument {
                        self.gpr[reg as usize].set_direct(Value::Unknown, None);
                    }
                }
            }
        }
        StepResult::Continue
    }

    #[inline]
    fn set_comparison_result(&mut self, value: Value, crf: usize) {
        for gpr in &mut self.gpr {
            if gpr.value == Value::ComparisonResult(crf as u8) {
                gpr.value = value;
                // Propagate narrowed value back to the stack slot this register was loaded from
                if let Provenance::Stack { offset, .. } = gpr.provenance {
                    if let Some(slot) = self.stack_slots.get_mut(&(offset as i16)) {
                        slot.value = value;
                    }
                }
            }
        }
    }
}

/// Given a condition register bit, calculate new register
/// values for each branch. (false / true)
fn split_values_by_crb(crb: u8, left: Value, right: Value) -> (Value, Value) {
    match crb {
        // lt
        0 => match (left, right) {
            (Value::Range { min, max, step }, Value::Constant(value)) => (
                // left >= right
                Value::Range {
                    min: std::cmp::max(min, value),
                    max: std::cmp::max(max, value),
                    step,
                },
                // left < right
                Value::Range {
                    min: std::cmp::min(min, value.wrapping_sub(1)),
                    max: std::cmp::min(max, value.wrapping_sub(1)),
                    step,
                },
            ),
            (_, Value::Constant(value)) => (
                // left >= right
                Value::Range { min: value, max: u64::MAX, step: 1 },
                // left < right
                Value::Range { min: 0, max: value.wrapping_sub(1), step: 1 },
            ),
            _ => (left, left),
        },
        // gt
        1 => match (left, right) {
            (Value::Range { min, max, step }, Value::Constant(value)) => (
                // left <= right
                Value::Range {
                    min: std::cmp::min(min, value),
                    max: std::cmp::min(max, value),
                    step,
                },
                // left > right
                Value::Range {
                    min: std::cmp::max(min, value.wrapping_add(1)),
                    max: std::cmp::max(max, value.wrapping_add(1)),
                    step,
                },
            ),
            (_, Value::Constant(value)) => (
                // left <= right
                Value::Range { min: 0, max: value, step: 1 },
                // left > right
                Value::Range { min: value.wrapping_add(1), max: u64::MAX, step: 1 },
            ),
            _ => (left, left),
        },
        // eq
        2 => match (left, right) {
            (Value::Constant(l), Value::Constant(r)) => (
                // left != right
                if l == r { Value::Unknown } else { left },
                // left == right
                Value::Constant(r),
            ),
            (_, Value::Constant(value)) => (
                // left != right
                left,
                // left == right
                Value::Constant(value),
            ),
            _ => (left, left),
        },
        // so
        3 => (left, left),
        _ => unreachable!(),
    }
}

#[inline]
fn mask_value(begin: u32, end: u32) -> u32 {
    if begin <= end {
        let mut mask = 0u32;
        for bit in begin..=end {
            mask |= 1 << (31 - bit);
        }
        mask
    } else if begin == end + 1 {
        u32::MAX
    } else {
        let mut mask = u32::MAX;
        for bit in end + 1..begin {
            mask &= !(1 << (31 - bit));
        }
        mask
    }
}

#[inline]
pub fn is_load_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Lbz
            | Opcode::Lbzu
            | Opcode::Lha
            | Opcode::Lhau
            | Opcode::Lhz
            | Opcode::Lhzu
            | Opcode::Lmw
            | Opcode::Lwa
            | Opcode::Lwz
            | Opcode::Lwzu
            | Opcode::Ld
            | Opcode::Ldu
    )
}

#[inline]
pub fn is_loadf_op(op: Opcode) -> bool {
    matches!(op, Opcode::Lfd | Opcode::Lfdu | Opcode::Lfs | Opcode::Lfsu)
}

#[inline]
pub fn is_store_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Stb
            | Opcode::Stbu
            | Opcode::Sth
            | Opcode::Sthu
            | Opcode::Stmw
            | Opcode::Stw
            | Opcode::Stwu
            | Opcode::Std
            | Opcode::Stdu
    )
}

#[inline]
pub fn is_storef_op(op: Opcode) -> bool {
    matches!(op, Opcode::Stfd | Opcode::Stfdu | Opcode::Stfs | Opcode::Stfsu)
}

#[inline]
pub fn is_load_store_op(op: Opcode) -> bool {
    is_load_op(op) || is_loadf_op(op) || is_store_op(op) || is_storef_op(op)
}

#[inline]
pub fn is_update_op(op: Opcode) -> bool {
    matches!(
        op,
        Opcode::Lbzu
            | Opcode::Lbzux
            | Opcode::Ldu
            | Opcode::Ldux
            | Opcode::Lfdu
            | Opcode::Lfdux
            | Opcode::Lfsu
            | Opcode::Lfsux
            | Opcode::Lhau
            | Opcode::Lhaux
            | Opcode::Lhzu
            | Opcode::Lhzux
            | Opcode::Lwaux
            | Opcode::Lwzu
            | Opcode::Lwzux
            | Opcode::Stbu
            | Opcode::Stbux
            | Opcode::Stdu
            | Opcode::Stdux
            | Opcode::Stfdu
            | Opcode::Stfdux
            | Opcode::Stfsu
            | Opcode::Stfsux
            | Opcode::Sthu
            | Opcode::Sthux
            | Opcode::Stwu
            | Opcode::Stwux
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind};
    use powerpc::Extensions;

    fn make_obj(base: u32, instructions: &[u32]) -> ObjInfo {
        let data: Vec<u8> = instructions.iter().flat_map(|ins| ins.to_be_bytes()).collect();
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
            "vm-test".into(),
            vec![],
            vec![section],
        )
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
            "vm-test-sized".into(),
            vec![],
            vec![section],
        )
    }

    fn step(vm: &mut VM, obj: &ObjInfo, addr: u32, code: u32) -> StepResult {
        vm.step(obj, SectionAddress::new(0, addr), Ins::new(code, Extensions::xenon()))
    }

    #[test]
    fn stack_slot_provenance_survives_instruction_gaps() {
        let obj = make_obj(0x1000, &[0u32; 8]);
        let mut vm = VM::new_from_obj(&obj);
        vm.gpr[5].value = Value::Range { min: 0, max: u64::MAX, step: 1 };

        let _ = step(&mut vm, &obj, 0x1000, 0x90A1_0050); // stw r5, 80(r1)
        let _ = step(&mut vm, &obj, 0x1004, 0x8081_0050); // lwz r4, 80(r1)
        let _ = step(&mut vm, &obj, 0x1008, 0x2B04_0010); // cmplwi cr6, r4, 0x10
        let StepResult::Branch(mut branches) = step(&mut vm, &obj, 0x100C, 0x4199_0008) else {
            panic!("expected conditional branch");
        };

        let mut fallthrough_vm = branches.remove(0).vm;
        let _ = step(&mut fallthrough_vm, &obj, 0x1010, 0x6042_0001); // ori r2, r2, 1
        let _ = step(&mut fallthrough_vm, &obj, 0x1014, 0x3863_0001); // addi r3, r3, 1
        let _ = step(&mut fallthrough_vm, &obj, 0x1018, 0x8121_0050); // lwz r9, 80(r1)

        assert_eq!(fallthrough_vm.gpr[9].value, Value::Range { min: 0, max: 0x10, step: 1 });
    }

    #[test]
    fn stack_slot_provenance_survives_register_rename_before_compare() {
        let obj = make_obj(0x2000, &[0u32; 8]);
        let mut vm = VM::new_from_obj(&obj);
        vm.gpr[5].value = Value::Range { min: 0, max: u64::MAX, step: 1 };

        let _ = step(&mut vm, &obj, 0x2000, 0x90A1_0050); // stw r5, 80(r1)
        let _ = step(&mut vm, &obj, 0x2004, 0x8081_0050); // lwz r4, 80(r1)
        let _ = step(&mut vm, &obj, 0x2008, 0x7C89_2378); // or r9, r4, r4
        let _ = step(&mut vm, &obj, 0x200C, 0x2B09_0020); // cmplwi cr6, r9, 0x20
        let StepResult::Branch(mut branches) = step(&mut vm, &obj, 0x2010, 0x4199_0008) else {
            panic!("expected conditional branch");
        };

        let mut fallthrough_vm = branches.remove(0).vm;
        let _ = step(&mut fallthrough_vm, &obj, 0x2014, 0x80E1_0050); // lwz r7, 80(r1)
        assert_eq!(fallthrough_vm.gpr[7].value, Value::Range { min: 0, max: 0x20, step: 1 });
    }

    #[test]
    fn relative_byte_jump_table_base_propagates_to_bctr() {
        let obj = make_obj_with_size(0x0, 0x400);
        let mut vm = VM::new_from_obj(&obj);
        vm.gpr[11].value = Value::Range { min: 0, max: 0x10, step: 1 };
        vm.last_modified_cr = 0;
        vm.cr[0].right = Value::Constant(0x10);

        let _ = step(&mut vm, &obj, 0x0000, 0x3D80_0000); // lis r12, 0
        let _ = step(&mut vm, &obj, 0x0004, 0x398C_0100); // addi r12, r12, 0x100 (table)
        let _ = step(&mut vm, &obj, 0x0008, 0x7C0C_58AE); // lbzx r0, r12, r11
        let _ = step(&mut vm, &obj, 0x000C, 0x5400_103A); // slwi r0, r0, 2
        let _ = step(&mut vm, &obj, 0x0010, 0x3D80_0000); // lis r12, 0
        let _ = step(&mut vm, &obj, 0x0014, 0x398C_0200); // addi r12, r12, 0x200 (base)
        let _ = step(&mut vm, &obj, 0x0018, 0x7D8C_0214); // add r12, r12, r0
        let _ = step(&mut vm, &obj, 0x001C, 0x7D89_03A6); // mtctr r12
        let StepResult::Jump(BranchTarget::JumpTable {
            jump_table_type,
            jump_table_address,
            size,
        }) = step(&mut vm, &obj, 0x0020, 0x4E80_0420) // bctr
        else {
            panic!("expected bctr jump-table target");
        };

        assert_eq!(
            jump_table_address,
            RelocationTarget::Address(SectionAddress::new(0, 0x100))
        );
        assert_eq!(
            jump_table_type,
            JumpTableType::RelativeBytesTimes4(Some(RelocationTarget::Address(
                SectionAddress::new(0, 0x200),
            )))
        );
        assert_eq!(size, NonZeroU32::new(0x11));
    }
}
