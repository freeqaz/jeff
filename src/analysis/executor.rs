use anyhow::Result;
use fixedbitset::FixedBitSet;
use powerpc::Ins;

use crate::{
    analysis::{
        cfa::SectionAddress,
        disassemble,
        vm::{StepResult, VM},
    },
    obj::{ObjInfo, ObjSection, ObjSectionKind},
};

/// Space-efficient implementation for tracking visited code addresses
struct VisitedAddresses {
    inner: Vec<FixedBitSet>,
}

impl VisitedAddresses {
    pub fn new(obj: &ObjInfo) -> Self {
        let mut inner = Vec::with_capacity(obj.sections.len() as usize);
        for (_, section) in obj.sections.iter() {
            if section.kind == ObjSectionKind::Code {
                let size = (section.size / 4) as usize;
                inner.push(FixedBitSet::with_capacity(size));
            } else {
                // Empty
                inner.push(FixedBitSet::new())
            }
        }
        Self { inner }
    }

    pub fn contains(&self, section_address: u32, address: SectionAddress) -> bool {
        Self::bit_for(section_address, address.address).is_some_and(|bit| {
            self.inner[address.section as usize].contains(bit)
        })
    }

    pub fn insert(&mut self, section_address: u32, address: SectionAddress) {
        if let Some(bit) = Self::bit_for(section_address, address.address) {
            self.inner[address.section as usize].insert(bit);
        }
    }

    #[inline]
    fn bit_for(section_address: u32, address: u32) -> Option<usize> {
        address.checked_sub(section_address).map(|delta| (delta / 4) as usize)
    }
}

pub struct VMState {
    pub vm: Box<VM>,
    pub address: SectionAddress,
}

/// Helper for branched VM execution, only visiting addresses once.
pub struct Executor {
    vm_stack: Vec<VMState>,
    visited: VisitedAddresses,
}

pub struct ExecCbData<'a> {
    pub executor: &'a mut Executor,
    pub vm: &'a mut VM,
    pub result: StepResult,
    pub ins_addr: SectionAddress,
    pub section: &'a ObjSection,
    pub ins: Ins,
    pub block_start: SectionAddress,
}

pub enum ExecCbResult<T = ()> {
    Continue,
    Jump(SectionAddress),
    EndBlock,
    End(T),
}

impl Executor {
    pub fn new(obj: &ObjInfo) -> Self {
        Self { vm_stack: vec![], visited: VisitedAddresses::new(obj) }
    }

    pub fn run<Cb, R>(&mut self, obj: &ObjInfo, mut cb: Cb) -> Result<Option<R>>
    where Cb: FnMut(ExecCbData) -> Result<ExecCbResult<R>> {
        while let Some(mut state) = self.vm_stack.pop() {
            let section = &obj.sections[state.address.section];
            if !section.contains(state.address.address) {
                log::warn!(
                    "Skipping out-of-bounds code candidate {:#010X} in section {} ({:#010X}-{:#010X})",
                    state.address.address,
                    section.name,
                    section.address,
                    section.address + section.size
                );
                continue;
            }
            if section.kind != ObjSectionKind::Code {
                log::warn!("Attempted to visit non-code address {:#010X}", state.address);
                continue;
            }

            // Already visited block
            let section_address = section.address as u32;
            if self.visited.contains(section_address, state.address) {
                continue;
            }

            let mut block_start = state.address;
            loop {
                if !section.contains(state.address.address) {
                    log::warn!(
                        "Stopping block walk on out-of-bounds address {:#010X} in section {} ({:#010X}-{:#010X})",
                        state.address.address,
                        section.name,
                        section.address,
                        section.address + section.size
                    );
                    break;
                }
                self.visited.insert(section_address, state.address);

                let ins = match disassemble(section, state.address.address) {
                    Some(ins) => ins,
                    None => return Ok(None),
                };
                let result = state.vm.step(obj, state.address, ins);
                match cb(ExecCbData {
                    executor: self,
                    vm: &mut state.vm,
                    result,
                    ins_addr: state.address,
                    section,
                    ins,
                    block_start,
                })? {
                    ExecCbResult::Continue => {
                        state.address += 4;
                    }
                    ExecCbResult::Jump(addr) => {
                        if addr.section != state.address.section || !section.contains(addr.address) {
                            log::warn!(
                                "Ignoring out-of-bounds/direct cross-section jump target {:#010X} from {:#010X}",
                                addr,
                                state.address
                            );
                            break;
                        }
                        if self.visited.contains(section_address, addr) {
                            break;
                        }
                        block_start = addr;
                        state.address = addr;
                    }
                    ExecCbResult::EndBlock => break,
                    ExecCbResult::End(result) => return Ok(Some(result)),
                }
            }
        }
        Ok(None)
    }

    pub fn push(&mut self, address: SectionAddress, vm: Box<VM>, sort: bool) {
        self.vm_stack.push(VMState { address, vm });
        if sort {
            // Sort lowest to highest, so we always go highest address first
            self.vm_stack.sort_by_key(|state| state.address);
        }
    }

    pub fn visited(&self, section_address: u32, address: SectionAddress) -> bool {
        if address.address < section_address {
            return false;
        }
        self.visited.contains(section_address, address)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::{ExecCbResult, Executor};
    use crate::{
        analysis::{cfa::SectionAddress, vm::StepResult},
        obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind},
    };

    fn make_code_section(base_addr: u32, instructions: &[u32]) -> ObjSection {
        let data: Vec<u8> = instructions.iter().flat_map(|w| w.to_be_bytes()).collect();
        ObjSection {
            name: ".text".into(),
            kind: ObjSectionKind::Code,
            address: base_addr as u64,
            size: data.len() as u64,
            data,
            align: 4,
            ..Default::default()
        }
    }

    fn make_obj(base_addr: u32, instructions: &[u32]) -> ObjInfo {
        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "executor-test".into(),
            vec![],
            vec![make_code_section(base_addr, instructions)],
        )
    }

    #[test]
    fn run_ignores_out_of_bounds_direct_jump_target() -> Result<()> {
        const NOP: u32 = 0x60000000;
        let obj = make_obj(0x1000, &[NOP]);
        let mut executor = Executor::new(&obj);
        executor.push(SectionAddress::new(0, 0x1000), crate::analysis::vm::VM::new_from_obj(&obj), false);

        let result = executor.run(&obj, |data| {
            match data.result {
                StepResult::Continue => {
                    Ok(ExecCbResult::<()>::Jump(SectionAddress::new(0, 0x0FFC)))
                }
                _ => Ok(ExecCbResult::EndBlock),
            }
        })?;

        assert!(result.is_none());
        Ok(())
    }
}
