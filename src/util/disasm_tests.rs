use std::io::Write;

use anyhow::{Context, Result};
use powerpc::{Extensions, InsIter};
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
                let bytes_str = chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
                writeln!(w, "{:08X}   {}   {:#010X}", addr, bytes_str, entry)?;
            } else {
                // Partial entry (shouldn't happen, but handle gracefully)
                let bytes_str = chunk.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
                writeln!(w, "{:08X}   {}   (incomplete)", addr, bytes_str)?;
            }
        }
    }

    writeln!(w)?;
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
            function_bytes: "386000004e800020".to_string(), // addi r3, r0, 0; blr
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
}
