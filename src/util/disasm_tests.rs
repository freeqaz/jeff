use std::collections::BTreeSet;
use std::io::Write;

use anyhow::{Context, Result};
use powerpc::{Argument, Extensions, Ins, InsIter, Opcode};
use serde::{Deserialize, Serialize};

/// CFA test case from YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfaTest {
    pub test_id: u32,
    pub function_start: String,
    pub function_bytes: String,
    pub jump_table_start: String,
    pub jump_table_bytes: String,
}

/// Generate Ghidra-style disassembly for test function bytes
pub fn disasm_test<W>(w: &mut W, test: &CfaTest) -> Result<()>
where
    W: Write + ?Sized,
{
    let function_start = u32::from_str_radix(&test.function_start, 16)
        .with_context(|| format!("Invalid hex: {}", test.function_start))?;

    let function_bytes = hex::decode(&test.function_bytes)
        .with_context(|| format!("Invalid hex bytes: {}", test.function_bytes))?;

    writeln!(w, "Test {}: {}", test.test_id, test.function_start)?;
    writeln!(w, "{}", "=".repeat(80))?;
    writeln!(w, "{:<10} {:<16} {}", "Address", "Bytes", "Instruction")?;
    writeln!(w, "{}", "-".repeat(80))?;

    for (addr, ins) in InsIter::new(&function_bytes, function_start, Extensions::xenon()) {
        let code = ins.code;
        let bytes_str = format!("{:08X}", code);
        let simplified = ins.simplified();
        let mnemonic = simplified.mnemonic;
        let args = simplified
            .args_iter()
            .map(|arg| format!("{}", arg))
            .collect::<Vec<_>>()
            .join(", ");

        let instr = if args.is_empty() {
            mnemonic.to_string()
        } else {
            format!("{} {}", mnemonic, args)
        };

        writeln!(w, "{:08X}   {}   {}", addr, bytes_str, instr)?;
    }

    // Jump table if present
    if test.jump_table_bytes != "00000000" {
        let jt_start = u32::from_str_radix(&test.jump_table_start, 16)
            .with_context(|| format!("Invalid hex: {}", test.jump_table_start))?;

        let jt_bytes = hex::decode(&test.jump_table_bytes)
            .with_context(|| format!("Invalid hex bytes: {}", test.jump_table_bytes))?;

        writeln!(w)?;
        writeln!(w, "Jump Table @ {}: {}", test.jump_table_start, test.jump_table_start)?;
        writeln!(w, "{}", "=".repeat(80))?;
        writeln!(w, "{:<10} {:<16} {}", "Address", "Bytes", "Entry (4-byte LE)")?;
        writeln!(w, "{}", "-".repeat(80))?;

        for (i, chunk) in jt_bytes.chunks(4).enumerate() {
            let addr = jt_start + (i as u32 * 4);
            if chunk.len() == 4 {
                let entry = u32::from_be_bytes(chunk.try_into().unwrap());
                let bytes_str =
                    chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
                writeln!(w, "{:08X}   {}   {:#010X}", addr, bytes_str, entry)?;
            } else {
                let bytes_str =
                    chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
                writeln!(w, "{:08X}   {}   (incomplete)", addr, bytes_str)?;
            }
        }
    }

    writeln!(w)?;
    Ok(())
}

/// Write a single instruction in m2c-compatible GNU `as` format.
/// Handles Offset(reg) pairing and proper hex byte comments.
fn write_m2c_ins<W>(
    w: &mut W,
    addr: u32,
    base_addr: u32,
    ins: Ins,
    branch_target: Option<u32>,
    internal_targets: &BTreeSet<u32>,
) -> Result<()>
where
    W: Write + ?Sized,
{
    let offset = addr - base_addr;
    let code = ins.code;
    write!(
        w,
        "/* {:08X} {:08X}  {:02X} {:02X} {:02X} {:02X} */\t",
        offset,
        offset,
        (code >> 24) & 0xFF,
        (code >> 16) & 0xFF,
        (code >> 8) & 0xFF,
        code & 0xFF
    )?;

    if ins.op == Opcode::Illegal {
        write!(w, ".4byte {:#010X}", ins.code)?;
    } else {
        let simplified = ins.simplified();
        write!(w, "{}", simplified.mnemonic)?;

        let mut writing_offset = false;
        for (i, arg) in simplified.args_iter().enumerate() {
            if !writing_offset {
                if i == 0 {
                    write!(w, " ")?;
                } else {
                    write!(w, ", ")?;
                }
            }
            match arg {
                Argument::Offset(_) => {
                    write!(w, "{arg}")?;
                    write!(w, "(")?;
                    writing_offset = true;
                    continue;
                }
                Argument::BranchDest(_) => {
                    if let Some(target) = branch_target {
                        if internal_targets.contains(&target) {
                            write!(w, ".L{:08X}", target)?;
                        } else {
                            write!(w, "func_{:08X}", target)?;
                        }
                    } else {
                        write!(w, "{arg}")?;
                    }
                }
                _ => {
                    write!(w, "{arg}")?;
                }
            }
            if writing_offset {
                write!(w, ")")?;
                writing_offset = false;
            }
        }
    }
    writeln!(w)?;
    Ok(())
}

/// Collect branch targets, split into internal (within function) and external
fn collect_branch_info(bytes: &[u8], start: u32) -> (BTreeSet<u32>, BTreeSet<u32>) {
    let mut internal = BTreeSet::new();
    let mut external = BTreeSet::new();
    let func_end = start + bytes.len() as u32;
    for (addr, ins) in InsIter::new(bytes, start, Extensions::xenon()) {
        if let Some(dest) = ins.branch_dest(addr) {
            if dest >= start && dest < func_end {
                internal.insert(dest);
            } else {
                external.insert(dest);
            }
        }
    }
    (internal, external)
}

/// Generate m2c-compatible GNU `as` format assembly for a test
pub fn disasm_test_m2c<W>(w: &mut W, test: &CfaTest) -> Result<()>
where
    W: Write + ?Sized,
{
    let function_start = u32::from_str_radix(&test.function_start, 16)
        .with_context(|| format!("Invalid hex: {}", test.function_start))?;

    let function_bytes = hex::decode(&test.function_bytes)
        .with_context(|| format!("Invalid hex bytes: {}", test.function_bytes))?;

    let func_size = function_bytes.len() as u32;

    // Collect branch targets
    let (internal_targets, external_targets) =
        collect_branch_info(&function_bytes, function_start);

    // Write header
    writeln!(w, ".include \"macros.inc\"")?;
    writeln!(w)?;

    // Declare external symbols so m2c can parse branch targets
    for &addr in &external_targets {
        writeln!(w, ".extern func_{:08X}", addr)?;
    }
    if !external_targets.is_empty() {
        writeln!(w)?;
    }

    writeln!(w, ".section .text  # 0x0 - {:#X}", func_size)?;
    writeln!(w)?;
    writeln!(w, ".global test_{}", test.test_id)?;
    writeln!(w, "test_{}:", test.test_id)?;

    // Write instructions
    for (addr, ins) in InsIter::new(&function_bytes, function_start, Extensions::xenon()) {
        // Emit label if this address is an internal branch target
        if internal_targets.contains(&addr) && addr != function_start {
            writeln!(w, ".L{:08X}:", addr)?;
        }
        // Resolve branch: internal → .LXXXXXXXX, external → func_XXXXXXXX
        let resolved_target = ins.branch_dest(addr);
        write_m2c_ins(w, addr, function_start, ins, resolved_target, &internal_targets)?;
    }

    // Write jump table data section if present
    if test.jump_table_bytes != "00000000" {
        let jt_bytes = hex::decode(&test.jump_table_bytes)
            .with_context(|| format!("Invalid hex bytes: {}", test.jump_table_bytes))?;

        writeln!(w)?;
        writeln!(w, ".section .rodata  # {:#X} - {:#X}", func_size, func_size + jt_bytes.len() as u32)?;
        writeln!(w)?;
        writeln!(w, ".global jtbl_{}", test.test_id)?;
        writeln!(w, "jtbl_{}:", test.test_id)?;

        for chunk in jt_bytes.chunks(4) {
            if chunk.len() == 4 {
                let val = u32::from_be_bytes(chunk.try_into().unwrap());
                writeln!(w, "\t.4byte {:#010X}", val)?;
            } else {
                for b in chunk {
                    writeln!(w, "\t.byte {:#04X}", b)?;
                }
            }
        }
    }

    writeln!(w)?;
    Ok(())
}

/// Generate m2c-compatible assembly for all tests in a YAML file
pub fn disasm_tests_file_m2c<W>(w: &mut W, yaml_content: &str) -> Result<()>
where
    W: Write + ?Sized,
{
    let tests: Vec<CfaTest> =
        serde_yaml::from_str(yaml_content).context("Failed to parse YAML test file")?;

    for test in tests {
        disasm_test_m2c(w, &test)?;
    }

    Ok(())
}

/// Generate disassembly for all tests in a YAML file
pub fn disasm_tests_file<W>(w: &mut W, yaml_content: &str) -> Result<()>
where
    W: Write + ?Sized,
{
    let tests: Vec<CfaTest> =
        serde_yaml::from_str(yaml_content).context("Failed to parse YAML test file")?;

    for test in tests {
        disasm_test(w, &test)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disasm_basic() -> Result<()> {
        let test = CfaTest {
            test_id: 0,
            function_start: "82000000".to_string(),
            function_bytes: "386000004e800020".to_string(),
            jump_table_start: "00000000".to_string(),
            jump_table_bytes: "00000000".to_string(),
        };

        let mut output = Vec::new();
        disasm_test(&mut output, &test)?;
        let output_str = String::from_utf8(output)?;
        assert!(output_str.contains("82000000"));
        assert!(output_str.contains("addi"));
        assert!(output_str.contains("blr"));
        Ok(())
    }

    #[test]
    fn test_m2c_format() -> Result<()> {
        let test = CfaTest {
            test_id: 0,
            function_start: "82000000".to_string(),
            function_bytes: "386000004e800020".to_string(),
            jump_table_start: "00000000".to_string(),
            jump_table_bytes: "00000000".to_string(),
        };

        let mut output = Vec::new();
        disasm_test_m2c(&mut output, &test)?;
        let output_str = String::from_utf8(output)?;
        assert!(output_str.contains(".include \"macros.inc\""));
        assert!(output_str.contains(".section .text"));
        assert!(output_str.contains("test_0:"));
        assert!(output_str.contains("blr"));
        Ok(())
    }
}
