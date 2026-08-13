#!/usr/bin/env python3
"""Dump the instruction-mismatch rows a given symbol is charged, under two binaries.

Purpose: turn "this symbol moved between commit X and X^" (a temporal fact) into
"the rows that disappeared have shape S" (a causal one). Used to verify that the
per-commit attribution in report_delta.py names the right mechanism.
"""

import json
import re
import subprocess
import sys

DEPLOYED = "/home/free/.local/bin/objdiff-cli"
HEAD = (
    "/home/free/code/milohax/decomp-bench/archive/runs/"
    "2026-08-12-objdiff-ruler-parity/bin/objdiff-cli-9138611"
)

ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*`([^`]*)`\s*\|\s*`([^`]*)`\s*\|\s*(\S+)\s*\|")


def rows(binary, project, unit, symbol):
    p = subprocess.run(
        [binary, "diff", "-p", project, "-u", unit, symbol, "--include-instructions"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    out = []
    score = None
    for line in p.stdout.splitlines():
        if line.startswith("- **Diff Score**"):
            score = line.split(":", 1)[1].strip()
        m = ROW.match(line)
        if m:
            out.append(
                {"index": int(m.group(1)), "target": m.group(2), "base": m.group(3), "kind": m.group(4)}
            )
    return score, out, p.returncode


def main():
    spec = json.load(open(sys.argv[1]))
    results = []
    for case in spec:
        proj, unit, sym = case["project"], case["unit"], case["symbol"]
        sb, rb, rcb = rows(DEPLOYED, proj, unit, sym)
        sa, ra, rca = rows(HEAD, proj, unit, sym)
        key = lambda r: (r["index"], r["target"], r["base"], r["kind"])
        before, after = {key(r): r for r in rb}, {key(r): r for r in ra}
        removed = [before[k] for k in before if k not in after]
        added = [after[k] for k in after if k not in before]
        rec = dict(case)
        rec.update(
            {
                "score_deployed": sb,
                "score_head": sa,
                "rows_deployed": len(rb),
                "rows_head": len(ra),
                "removed": removed,
                "added": added,
                "rc": [rcb, rca],
            }
        )
        results.append(rec)
        print(f"### [{case['class']}] {case['game']} {unit} {sym}")
        print(f"  Diff Score  {sb}  ->  {sa}   (rows {len(rb)} -> {len(ra)})")
        for r in removed:
            print(f"  - REMOVED  idx {r['index']:5d}  {r['kind']:12s} target=`{r['target']}`  base=`{r['base']}`")
        for r in added:
            print(f"  + ADDED    idx {r['index']:5d}  {r['kind']:12s} target=`{r['target']}`  base=`{r['base']}`")
        if added:
            print("  !! ROWS ADDED — a charge appeared that did not exist before")
        print()
    json.dump(results, open(sys.argv[2], "w"), indent=1)


if __name__ == "__main__":
    main()
