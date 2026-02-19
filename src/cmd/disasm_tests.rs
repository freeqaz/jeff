use std::{fs, io::stdout};

use anyhow::Result;
use argp::FromArgs;

use crate::util::disasm_tests;

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Disassemble CFA test YAML files to Ghidra-style output.
#[argp(subcommand, name = "disasm-tests")]
pub struct Args {
    #[argp(positional)]
    /// path to YAML test file
    yaml_file: String,
}

pub fn run(args: Args) -> Result<()> {
    let content = fs::read_to_string(&args.yaml_file)?;
    let mut stdout = stdout().lock();
    disasm_tests::disasm_tests_file(&mut stdout, &content)?;
    Ok(())
}
