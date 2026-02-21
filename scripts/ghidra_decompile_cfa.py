#!/usr/bin/env python3
"""Ghidra headless decompilation of CFA tests via pyghidra.

Uses pyghidra to start Ghidra, import each test's binary at the correct
base address with PowerPC:BE:64:Xenon, create jump table memory blocks
where needed, and decompile all 20 tests.

Usage:
    python3 scripts/ghidra_decompile_cfa.py [output_file]

Requires:
    - pyghidra (pip install pyghidra)
    - Ghidra 12.1 DEV with GhidraXenon extension
    - GHIDRA_INSTALL_DIR env var or default path below
"""

import json
import os
import sys
import traceback

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
BIN_DIR = "/tmp/cfa_test_bins"
MANIFEST_PATH = os.path.join(BIN_DIR, "manifest.json")
DEFAULT_OUTPUT = os.path.join(PROJECT_DIR, "docs", "cfa_tests_ghidra_decomp.c")
DEFAULT_GHIDRA = os.path.expanduser(
    "~/code/milohax/vmx128-research/ghidra-test/ghidra_12.1_DEV"
)


def ensure_bins():
    """Run yaml_to_bins.py if manifest doesn't exist."""
    if not os.path.exists(MANIFEST_PATH):
        import subprocess
        subprocess.check_call([
            sys.executable,
            os.path.join(SCRIPT_DIR, "yaml_to_bins.py"),
        ])


def decompile_test(entry, lang, comp_spec):
    """Decompile a single test entry, returns (test_id, c_code_or_error)."""
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.database import ProgramDB
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import ByteArrayInputStream

    monitor = ConsoleTaskMonitor()
    tid = entry["test_id"]
    func_start_hex = entry["function_start"]
    func_start = int(func_start_hex, 16)

    with open(entry["func_bin"], "rb") as f:
        func_bytes = f.read()

    program = ProgramDB("test_{}".format(tid), lang, comp_spec, monitor)

    try:
        # Set up memory blocks
        txn = program.startTransaction("setup")
        try:
            memory = program.getMemory()
            space = program.getAddressFactory().getDefaultAddressSpace()
            func_addr = space.getAddress(func_start)

            stream = ByteArrayInputStream(func_bytes)
            block = memory.createInitializedBlock(
                ".text", func_addr, stream, len(func_bytes), monitor, False
            )
            block.setRead(True)
            block.setWrite(False)
            block.setExecute(True)

            if "jt_start" in entry:
                with open(entry["jt_bin"], "rb") as f:
                    jt_bytes = f.read()
                jt_addr = space.getAddress(int(entry["jt_start"], 16))
                jt_stream = ByteArrayInputStream(jt_bytes)
                jt_block = memory.createInitializedBlock(
                    ".rdata_jt", jt_addr, jt_stream, len(jt_bytes), monitor, False
                )
                jt_block.setRead(True)
                jt_block.setWrite(False)
                jt_block.setExecute(False)
        finally:
            program.endTransaction(txn, True)

        # Disassemble
        txn = program.startTransaction("disassemble")
        try:
            cmd = DisassembleCommand(func_addr, None, True)
            cmd.applyTo(program)
        finally:
            program.endTransaction(txn, True)

        # Create function with full body
        fm = program.getFunctionManager()
        txn = program.startTransaction("create_func")
        try:
            end_addr = func_addr.add(len(func_bytes) - 1)
            body = AddressSet(func_addr, end_addr)
            func = fm.createFunction(
                "test_{}".format(tid), func_addr, body, SourceType.USER_DEFINED
            )
        finally:
            program.endTransaction(txn, True)

        if func is None:
            return (tid, "// ERROR: Could not create function at 0x{}".format(func_start_hex))

        # Decompile
        decomp = DecompInterface()
        decomp.openProgram(program)
        result = decomp.decompileFunction(func, 120, monitor)

        if result.decompileCompleted():
            c_code = result.getDecompiledFunction().getC()
        else:
            c_code = "// Decompilation failed: {}".format(result.getErrorMessage())

        decomp.dispose()
    finally:
        program.release(monitor)

    return (tid, c_code)


def main():
    output_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_OUTPUT

    ensure_bins()

    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    ghidra_home = os.environ.get("GHIDRA_INSTALL_DIR", DEFAULT_GHIDRA)
    os.environ["GHIDRA_INSTALL_DIR"] = ghidra_home

    print("Starting Ghidra from {}".format(ghidra_home))
    import pyghidra
    pyghidra.start(install_dir=ghidra_home)

    from ghidra.program.util import DefaultLanguageService
    from ghidra.program.model.lang import LanguageID

    lang_service = DefaultLanguageService.getLanguageService()
    lang = lang_service.getLanguage(LanguageID("PowerPC:BE:64:Xenon"))
    comp_spec = lang.getDefaultCompilerSpec()
    print("Language: {} / {}".format(lang, comp_spec))

    # Write header
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write(
            "// ============================================================================\n"
            "// Ghidra Headless Decompilation of CFA Tests\n"
            "// Processor: PowerPC:BE:64:Xenon (Xbox 360)\n"
            "// Generated by: scripts/ghidra_decompile_cfa.py\n"
            "// ============================================================================\n\n"
        )

    ok_count = 0
    err_count = 0

    for entry in manifest:
        tid = entry["test_id"]
        func_start = entry["function_start"]
        jt_info = ""
        if "jt_start" in entry:
            jt_info = " (jt @ 0x{})".format(entry["jt_start"])
        print("\nTest {:2d}: func @ 0x{}{}".format(tid, func_start, jt_info))

        try:
            test_id, c_code = decompile_test(entry, lang, comp_spec)
            status = "OK ({} chars)".format(len(c_code))
            ok_count += 1
        except Exception as e:
            test_id = tid
            c_code = "// ERROR: {}\n// {}".format(e, traceback.format_exc())
            status = "FAILED: {}".format(e)
            err_count += 1
            traceback.print_exc()

        print("  -> {}".format(status))

        with open(output_file, "a") as f:
            f.write(
                "// ============================================================================\n"
                "// Test {}: func @ 0x{}\n"
                "// ============================================================================\n\n"
                .format(test_id, func_start)
            )
            f.write(c_code)
            f.write("\n\n")

    print("\n=== Summary: {} OK, {} failed ===".format(ok_count, err_count))
    print("Output: {}".format(output_file))


if __name__ == "__main__":
    main()
