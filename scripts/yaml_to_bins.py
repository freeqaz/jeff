#!/usr/bin/env python3
"""Convert cfa_tests.yml to per-test .bin files for Ghidra headless import.

Reads the simple YAML format manually (no pyyaml dependency).
Outputs per-test .bin files to /tmp/cfa_test_bins/ and a manifest.json.
"""

import json
import os
import sys


def parse_cfa_tests_yaml(content):
    """Parse the simple cfa_tests.yml format into a list of test dicts."""
    tests = []
    current = {}
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("- test_id:"):
            if current:
                tests.append(current)
            current = {"test_id": int(line.split(":")[1].strip())}
        elif line.startswith("function_start:"):
            current["function_start"] = line.split(":")[1].strip()
        elif line.startswith("function_bytes:"):
            current["function_bytes"] = line.split(":")[1].strip()
        elif line.startswith("jump_table_start:"):
            current["jump_table_start"] = line.split(":")[1].strip()
        elif line.startswith("jump_table_bytes:"):
            current["jump_table_bytes"] = line.split(":")[1].strip()
    if current:
        tests.append(current)
    return tests


def main():
    if len(sys.argv) < 2:
        yaml_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "assets", "tests", "cfa_tests.yml",
        )
    else:
        yaml_path = sys.argv[1]

    out_dir = "/tmp/cfa_test_bins"
    os.makedirs(out_dir, exist_ok=True)

    with open(yaml_path) as f:
        content = f.read()

    tests = parse_cfa_tests_yaml(content)
    manifest = []

    for t in tests:
        tid = t["test_id"]
        func_start = t["function_start"]
        func_hex = t["function_bytes"]
        jt_start = t.get("jump_table_start", "00000000")
        jt_hex = t.get("jump_table_bytes", "00000000")

        # Write function bytes
        func_bin_path = os.path.join(out_dir, "test_{:02d}_func.bin".format(tid))
        with open(func_bin_path, "wb") as f:
            f.write(bytes.fromhex(func_hex))

        entry = {
            "test_id": tid,
            "function_start": func_start,
            "func_bin": func_bin_path,
        }

        # Write jump table bytes if present (non-zero start)
        if jt_start != "00000000" and jt_hex != "00000000":
            jt_bin_path = os.path.join(out_dir, "test_{:02d}_jt.bin".format(tid))
            with open(jt_bin_path, "wb") as f:
                f.write(bytes.fromhex(jt_hex))
            entry["jt_start"] = jt_start
            entry["jt_bin"] = jt_bin_path

        manifest.append(entry)
        func_size = len(func_hex) // 2
        print("Test {:2d}: func @ 0x{} ({} bytes){}".format(
            tid, func_start, func_size,
            "  jt @ 0x{} ({} bytes)".format(jt_start, len(jt_hex) // 2)
            if "jt_start" in entry else "",
        ))

    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print("\nWrote {} test bins and manifest to {}".format(len(manifest), out_dir))


if __name__ == "__main__":
    main()
