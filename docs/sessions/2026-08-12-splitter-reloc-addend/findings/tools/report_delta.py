#!/usr/bin/env python3
"""Per-symbol delta between two objdiff `report generate` JSON reports.

Both reports must have been generated over the SAME object trees; the only
intended variable is the objdiff-cli binary. Keyed on (unit, function name,
address) so that duplicate names inside a unit do not collide.

Emits:
  * a project-level measure delta,
  * every symbol whose fuzzy_match_percent or match_percent_normalized moved,
  * symbols present in one report and not the other (a schema/skew alarm),
  * a machine-readable JSON of the moved set for downstream classification.

Usage: report_delta.py BEFORE.json AFTER.json [--json OUT.json] [--label L]
"""

import argparse
import json
import sys

MEASURES = (
    "fuzzy_match_percent",
    "matched_code_percent",
    "matched_functions_percent",
    "complete_code_percent",
    "matched_functions",
    "complete_units",
    "masked_equal_functions",
)


def load(path):
    with open(path) as fh:
        return json.load(fh)


def index(report):
    """(unit, name, address) -> function record."""
    out = {}
    for unit in report["units"]:
        uname = unit["name"]
        for fn in unit.get("functions") or []:
            key = (uname, fn["name"], fn.get("address"))
            if key in out:
                # Same unit+name+address twice: keep both under a disambiguated
                # key rather than silently dropping one.
                n = 2
                while (key[0], key[1], f"{key[2]}#{n}") in out:
                    n += 1
                key = (key[0], key[1], f"{key[2]}#{n}")
            out[key] = fn
    return out


def unit_measures(report):
    return {u["name"]: u.get("measures", {}) for u in report["units"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--label", default="")
    args = ap.parse_args()

    b, a = load(args.before), load(args.after)
    print(f"# report delta {args.label}".rstrip())
    print(f"before: {args.before}")
    print(f"after : {args.after}")

    print("\n## project measures")
    for m in MEASURES:
        bv, av = b["measures"].get(m), a["measures"].get(m)
        if bv is None and av is None:
            continue
        try:
            d = float(av) - float(bv)
        except (TypeError, ValueError):
            d = "n/a"
        flag = "" if (isinstance(d, float) and abs(d) < 1e-9) else "   <== MOVED"
        dtxt = f"{d:+.6f}" if isinstance(d, float) else str(d)
        print(f"  {m:32s} {bv} -> {av}   ({dtxt}){flag}")

    bi, ai = index(b), index(a)
    only_b = sorted(set(bi) - set(ai))
    only_a = sorted(set(ai) - set(bi))
    print("\n## symbol-set skew (must be empty: same object trees)")
    print(f"  only in before: {len(only_b)}")
    print(f"  only in after : {len(only_a)}")
    for k in only_b[:20]:
        print(f"    -B {k}")
    for k in only_a[:20]:
        print(f"    +A {k}")

    moved = []
    for key in sorted(set(bi) & set(ai)):
        fb, fa = bi[key], ai[key]
        dz = float(fa.get("fuzzy_match_percent") or 0) - float(
            fb.get("fuzzy_match_percent") or 0
        )
        dn = float(fa.get("match_percent_normalized") or 0) - float(
            fb.get("match_percent_normalized") or 0
        )
        if abs(dz) > 1e-6 or abs(dn) > 1e-6:
            moved.append(
                {
                    "unit": key[0],
                    "name": key[1],
                    "address": key[2],
                    "size": fb.get("size"),
                    "fuzzy_before": fb.get("fuzzy_match_percent"),
                    "fuzzy_after": fa.get("fuzzy_match_percent"),
                    "fuzzy_delta": dz,
                    "norm_before": fb.get("match_percent_normalized"),
                    "norm_after": fa.get("match_percent_normalized"),
                    "norm_delta": dn,
                }
            )

    down = [m for m in moved if m["fuzzy_delta"] < -1e-6 or m["norm_delta"] < -1e-6]
    up = [m for m in moved if m not in down]

    print(f"\n## moved symbols: {len(moved)}  (up {len(up)}, DOWN {len(down)})")
    print(
        f"{'unit':52s} {'symbol':70s} {'fuzzy':>22s} {'norm':>22s}"
    )
    for m in sorted(moved, key=lambda x: (x["fuzzy_delta"], x["unit"])):
        print(
            f"{m['unit'][:52]:52s} {m['name'][:70]:70s} "
            f"{m['fuzzy_before']:8.4f}->{m['fuzzy_after']:8.4f} "
            f"{m['norm_before']:8.4f}->{m['norm_after']:8.4f}"
        )

    if down:
        print("\n!! DOWNWARD MOVEMENT — this is a STOP condition")
        for m in down:
            print(f"   {m['unit']} {m['name']} {m['fuzzy_delta']:+.4f}")

    # unit-level measures that moved but whose functions did not (data-side moves)
    bu, au = unit_measures(b), unit_measures(a)
    unit_moved = []
    for name in sorted(set(bu) & set(au)):
        for m in ("fuzzy_match_percent", "matched_data_percent", "complete_code_percent"):
            x, y = bu[name].get(m), au[name].get(m)
            if x is None or y is None:
                continue
            if abs(float(y) - float(x)) > 1e-6:
                unit_moved.append((name, m, float(x), float(y)))
    print(f"\n## unit measures moved: {len(unit_moved)}")
    for name, m, x, y in unit_moved:
        print(f"  {name:52s} {m:24s} {x:10.5f} -> {y:10.5f} ({y - x:+.5f})")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(
                {
                    "label": args.label,
                    "before": args.before,
                    "after": args.after,
                    "project_measures_before": b["measures"],
                    "project_measures_after": a["measures"],
                    "only_in_before": [list(k) for k in only_b],
                    "only_in_after": [list(k) for k in only_a],
                    "moved": moved,
                    "downward": down,
                    "unit_measures_moved": unit_moved,
                },
                fh,
                indent=1,
            )
        print(f"\nwrote {args.json_out}")

    return 2 if down or only_b or only_a else 0


if __name__ == "__main__":
    sys.exit(main())
