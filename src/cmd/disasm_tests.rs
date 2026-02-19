use std::{fs, io::stdout};

use anyhow::Result;
use argp::FromArgs;

use crate::util::disasm_tests;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Disassemble CFA test YAML files to Ghidra-style or m2c-compatible output.
#[argp(subcommand, name = "disasm-tests")]
pub struct Args {
    #[argp(positional)]
    /// path to YAML test file
    yaml_file: String,

    #[argp(switch)]
    /// output in m2c-compatible GNU as format (per-test .s files to stdout)
    m2c: bool,
}

pub fn run(args: Args) -> Result<()> {
    let content = fs::read_to_string(&args.yaml_file)?;
    let mut stdout = stdout().lock();
    if args.m2c {
        disasm_tests::disasm_tests_file_m2c(&mut stdout, &content)?;
    } else {
        disasm_tests::disasm_tests_file(&mut stdout, &content)?;
    }
    Ok(())
}
