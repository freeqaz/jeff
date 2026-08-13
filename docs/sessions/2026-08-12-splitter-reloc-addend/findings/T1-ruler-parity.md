# T1 — parity evidence for the objdiff-cli rebuild

**Verdict: PASS.** Zero unexplained movements, zero downward movements, on every
project measured. The deployed `objdiff-cli` may be replaced by a build of
objdiff `9138611`.

Written 2026-08-12 by the T1 agent. Every number below is first-hand from this
session. Run artifacts (12 + 5 full reports, per-symbol deltas, per-row dumps,
the five binaries):
`decomp-bench/archive/runs/2026-08-12-objdiff-ruler-parity/`.

Nothing in jeff was built or deployed. `/home/free/code/milohax/jeff/target/release/dtk`
was not touched, and neither was the objdiff deploy path
`objdiff/target/release/objdiff-cli` (still the 05:56 binary, mtime unchanged) —
all builds went to private `CARGO_TARGET_DIR`s under
`jeff/.worktrees/t1/`.

---

## 1. Three corrections to the brief, up front

The task brief said to budget for **two** explanation classes and expect
"Shape-1 artifact rows move toward agreement and nothing else moves". All three
parts of that are wrong, in ways that matter:

1. **There are three functional commits between the deployed binary and HEAD, not
   two.** `fb80730` "Port preferredStringEncoding from upstream" (15 files,
   +329/-90, touching `arch/mod.rs`, `diff/code.rs`, `diff/display.rs`) sits
   between them. Named below as class **E3**. Measured inert on all four
   projects — but it had to be measured, not assumed, and it is the single
   largest diff of the three.
2. **The Shape-1 class is a minority of the movement.** By symbol count it is
   37/173 on dc3 and 21/164 on rb3-xenon; the second class (`f2424d6`) accounts
   for the rest. "Shape-1 rows move and nothing else moves" would have been a
   failing prediction. What is true is the stronger claim the license actually
   needs: *every* moved symbol is assigned to one of the three commits, and
   nothing moves down.
3. **rb3 (Wii / mwcceppc / ELF) is also moved by this deploy**, by 232 symbols.
   The session `README.md` §1.3 correction and NOTES FINDING 4 correctly say the
   *splitter addend* defect cannot touch rb3 — that is about class E1, and it
   holds (rb3's E1 delta is byte-identically zero). But `~/.local/bin/objdiff-cli`
   is a single global symlink, so replacing it moves rb3's ruler too, via class
   E2. rb3 was outside the brief's scope; it is inside the deploy's scope.

---

## 2. What was compared, and why it is a single-variable A/B

Both arms read the **same object trees**. Nothing was rebuilt, re-split or
re-configured in any game repo; `dc3-decomp/build/373307D9` and
`rb3-xenon/build/45410914` were read-only inputs. The only variable is the
`objdiff-cli` binary. That is why hazard 5 ("`report.json` is not a trustworthy
baseline") does not bite: the before arm is not a remembered `report.json`, it is
a report **generated in this session** by the currently deployed binary, and it
is not the repo's `report.json` — every arm went to its own `-o` path under the
run dir.

**Cache hygiene.** `report generate` writes a `<output-stem>.cache` sidecar next
to `-o`, and the objdiff binary is not part of the cache key. Every arm therefore
got its own `-o` path. All 17 report runs logged `Report cache: 0 hits, N misses`
(`logs/`), which is the positive proof that no arm read another arm's cache.

### 2.1 The five binaries

| arm | objdiff commit | provenance |
|---|---|---|
| `A_deployed` | (unknown a priori) | `~/.local/bin/objdiff-cli` -> `objdiff/target/release/objdiff-cli`, built 2026-08-12 05:56 |
| `B_cb238c8` | `cb238c8` 03:23:04Z | scratch build — last commit before 05:56 |
| `C_745b7e3` | `745b7e3` 06:00:47Z | + `fb80730` preferredStringEncoding port (**E3**) |
| `D_4c38c31` | `4c38c31` 06:03:38Z | + `interior_self_reference` (**E1**) |
| `E_9138611` | `9138611` 06:17:37Z | + `f2424d6` unrelocated target operand (**E2**) = HEAD |

Built with
`CARGO_TARGET_DIR=/home/free/code/milohax/jeff/.worktrees/t1/objdiff-target-attr cargo build --release -p objdiff-cli`
from a detached objdiff worktree at `jeff/.worktrees/t1/objdiff-wt`, so the
shared `objdiff` checkout was never moved off HEAD. A sixth binary
(`Escratch_9138611`) was built independently from the shared checkout into
`jeff/.worktrees/t1/objdiff-target-scratch` — exactly the command the brief
prescribes — and produced **byte-identical reports to `E_9138611`** on both
games, so the worktree build and the in-place build are interchangeable.

### 2.2 The deployed binary's identity is now measured, not inferred

The session NOTES identified the deployed binary as "built seven minutes before
the fix" from its mtime. That is an inference. It is now a measurement:

**`A_deployed` and `B_cb238c8` produce byte-identical reports (sha256) on all
three of dc3, rb3-xenon and rb3.** The deployed binary behaves exactly as a
build of `cb238c8` on 7,185 units. See `logs/report-sha256.txt`.

This matters because the whole per-commit attribution below rests on the before
arm being a known commit rather than an unlabelled binary.

---

## 3. The three explanation classes

### E1 — `4c38c31` "NameCheck: the switch-dispatch base is the same address; dtk lost the addend"

`objdiff-core/src/diff/code.rs:1210 interior_self_reference()`. NameCheck-gated.
Forgives exactly the dtk addend-loss signature: ours a `$`-local label with zero
addend, in the same section as and inside the extent of the function being
diffed; theirs a zero-addend relocation naming that very function, in that
function's own section. This is Shape 1 of the session doc.

### E2 — `f2424d6` "NameCheck: an unrelocated target operand has no name to check"

Same file, `arg_eq`'s `Value`/`Reloc` arm, widened from `None` to
`None | NameCheck`. Where dtk failed to attribute an address it leaves the
computed constant in the operand (`lis r11, 0x8311`), the arch types it as a
`Value`, control never reaches `reloc_eq`, and NameCheck was charging a site
where the target object states no name at all. Unrelated to the addend; it is a
dtk *coverage* hole, not a dtk *addend* hole.

### E3 — `fb80730` "Port preferredStringEncoding from upstream"

The largest diff of the three (ports upstream `13f1267` string-literal detection
+ `8b1b4a9` the config option). Default `auto` = pre-existing behaviour. The
commit's own claim is that it is inert for any repo that does not set the
property. **Confirmed, and stronger than claimed:** `C_745b7e3` reports are
sha256-identical to `B_cb238c8` on dc3, rb3-xenon and rb3 — 7,185 units, zero
symbols moved. None of these projects sets `preferredStringEncoding`; a project
that does (zeldaret/tww) would move, and this parity account says nothing about
that case.

---

## 4. Per-symbol delta: complete assignment, no residue

Method: `work/report_delta.py`, keyed on `(unit, function name, address)`,
comparing `fuzzy_match_percent` and `match_percent_normalized`. Assignment is
mechanical — a symbol that moves across the `C→D` boundary is E1, across `D→E`
is E2, across `B→C` is E3.

| project | ruler | symbols moved A→E | E1 | E2 | both | E3 | **unexplained** | **downward** | set skew |
|---|---|---|---|---|---|---|---|---|---|
| dc3-decomp | `name_check` | 173 | 36 | 136 | 1 | 0 | **0** | **0** | 0 |
| rb3-xenon | `name_check` | 164 | 20 | 143 | 1 | 0 | **0** | **0** | 0 |
| rb3 (Wii/mwcc) | `name_check` | 232 | **0** | 232 | 0 | 0 | **0** | **0** | 0 |
| cea-decomp | `name_only` | **0** | 0 | 0 | 0 | 0 | **0** | **0** | 0 |

`union(E1, E2, E3) == headline moved set` exactly, on every project. Symbol-set
skew (a symbol present in one report and absent from the other) is zero
everywhere, which is the check that the two arms really did read the same trees.

Full table: `moved_symbols.csv` in the run dir (569 rows: game, class, unit,
symbol, address, size, fuzzy before/after/delta, normalized before/after/delta).

**No delta anywhere in that file is negative** — 569 rows, `fuzzy_delta` and
`norm_delta` both `>= 0`. Unit-level measures likewise: 194 unit measures moved
across dc3+rb3-xenon, none downward. Project measures:

| project | `matched_code_percent` A→E | E1 share | E2 share | functions reaching `fuzzy=100` |
|---|---|---|---|---|
| dc3 | 42.702670 → 43.098682 (+0.396012) | +0.347478 | +0.048534 | 28 (23 E1, 5 E2) |
| rb3-xenon | 32.506813 → 32.613857 (+0.107044) | +0.093717 | +0.013327 | 10 (9 E1, 1 E2) |
| rb3 | 63.091927 → 63.141228 (+0.049301) | 0 | +0.049301 | 1 (E2) |

These reproduce the objdiff commit messages' own claims **to six decimal places
on the deltas** (`4c38c31`: dc3 +0.347 pp / +23 fns, xenon +0.094 / +9, rb3 0;
`f2424d6`: dc3 +0.049 / +5, xenon +0.013 / +1, rb3 +0.049 / +1), from a
different absolute baseline — the author measured dc3 at 41.731250 → 42.127262,
we measure 42.702670 → 43.098682, because the dc3 object tree has moved since.
Identical deltas from different baselines is the expected signature of a change
that touches only a fixed set of sites.

The 23 dc3 and 9 rb3-xenon functions cleared by E1 are listed in §8.

---

## 5. Causal confirmation: the removed rows have the predicted shape

Attribution by commit boundary is a temporal fact. To make it causal, every one
of the 337 moved dc3+rb3-xenon symbols was re-diffed under both the deployed and
the HEAD binary with
`diff -p . -u <unit> <symbol> --include-instructions`, and the charged rows
present in one output and absent from the other were enumerated
(`work/sample_rows.py`, `work/sample_rows_result.json`, 674 invocations).

- **178 charged rows removed. 0 charged rows added.** Not one symbol acquires a
  charge it did not have.
- **E1 (124 removed rows, incl. the 4 from the E1+E2 symbols): 100% are
  `lis`/`addi`, perfectly paired 62/62**, target operand the literal `0x0` in
  124/124 cases, base operand a nonzero interior offset in 124/124:

  ```
  target=`lis r12, 0x0`         base=`lis r12, 0x4c`
  target=`addi r12, r12, 0x0`   base=`addi r12, r12, 0x4c`
  ```

  That is the switch-dispatch base signature of README §1.1 Shape 1, and nothing
  else appears in the class.
- **E2 (54 removed rows): 0/54 have the `0x0` shape.** Every one is a target-side
  bare computed constant against a base-side named symbol, across 8 opcodes
  (`lwz` 19, `lis` 17, `stw` 6, `addi` 5, `lfs` 3, `lbz` 2, `lwa` 1, `stb` 1):

  ```
  target=`lwz r3, 0x1d80, r10`  base=`lwz r3, ?kAssertStr@@3PBDB, r10`
  target=`lis r11, 0x8311`      base=`lis r11, ?TheAccomplishmentMgr@@3PAVAccomplishmentManager@@A`
  ```

  Exactly the "dtk left the constant in the operand" shape `f2424d6` describes.

The two classes are disjoint in shape as well as in commit — the assignment is
not an artifact of bisection ordering.

Direction, second instrument: the CLI's own `Diff Score` across those 337
symbols **improved on 293, worsened on 0**, unchanged on 44.

### 5.1 The brief's spot-check reproduces

```
cd /home/free/code/milohax/dc3-decomp
objdiff-cli diff -p . -u default/lazer/meta_ham/SaveLoadManager \
  '?HandleEventResponse@SaveLoadManager@@QAAXPAVHamProfile@@H@Z' --include-instructions
```

| binary | charged rows | Diff Score |
|---|---|---|
| deployed (05:56) | 2 — `lis r12, 0x0` vs `lis r12, 0x164`, `addi r12, r12, 0x0` vs `addi r12, r12, 0x164` | 10 / 21100 |
| scratch build of HEAD | **0** | **0 / 21100** |

### 5.2 Why 254 of the 337 show no *row* disappearing

The markdown table lists rows that are still mismatches. Most of the E2 movement
forgives one operand of a row that remains mismatched on another operand, so the
row stays in the table and only its penalty drops (e.g.
`?ConfigureCampaignData@Campaign` 957/64300 → 955/64300). Two `keygen_xbox`
symbols move in the report but show an unchanged integer `Diff Score` — a
rounding-scale effect on an 8-instruction function (report `fuzzy` 71.00 →
71.25), not a disagreement about direction.

---

## 6. What downstream will see change, beyond the numbers

16 functions cross `match_percent_normalized` from just-under to exactly 100.0 —
6 on dc3, 3 on rb3-xenon, 7 on rb3. This is the most consequential visible
effect of the deploy, because `normalized == 100` is the selection predicate for
the gap-bug-hunt lane (task #156) and appears in several worklists.

dc3: `AccomplishmentConditional::UpdateConditionOptionalData`,
`MainMenuPanel::UpdateArtLoaders`, `MetaPerformer::HandleGameplayEnded`,
`MetaPerformer::SaveDanceBattleScores`, `HollaBackMinigame::Poll`,
`VirtualKeyboard::ShowKeyboardUI`.
rb3-xenon: `DateTime::Format`, `DateTime::ToMiniDateString`, `KeysFx::Poll`.
rb3: `CustomizePanel::RotatePatch`, `TourDesc::Configure`,
`BandConfiguration::SyncPlayMode`, `BandDirector::OnFirstShotOK`,
`ChannelData::SetSlipTrackSpeed`, `HiResScreen::InvScreenRect`, `inflate`.

Two cautions on that list:

- **`normalized == 100` is not byte-exactness** and never was (decomp-synth task
  #150). These are presentation-metric flips, not new cracks. Only the 39
  functions reaching `fuzzy_match_percent == 100` (28 dc3, 10 xenon, 1 rb3) are
  the ruler saying "no residual left at this ruler", and even that is
  `name_check`, not `coff raw_eq AND reloc_eq`.
- rb3 `TourDesc::Configure` appears in the list, and `f2424d6`'s commit message
  explicitly says its residual is a *genuine* mwcc string-pool counter rotation
  that stays charged. Both are true: its `fuzzy` goes 99.91084 → 99.93976, still
  short of 100, so the ruler does still charge it; only the normalized
  presentation metric rounds to 100.

**Consequence for the deploy step:** every `report.json` consumer
(`real_corpus_census.py`, `score_probe_bytes.py`, `worklist.py`,
`eval_freshness.py`) is reading a number produced by the old ruler. The reports
must be regenerated as part of the deploy, and any eval or census that straddles
the deploy is comparing two rulers. This is a ruler move; it is not comparable
across the boundary.

---

## 7. cea-decomp — the negative control passes byte-identically

`cea-decomp` (Halo CEA, X360 MSVC PPC) is a fourth consumer of the same global
symlink and it ships `functionRelocDiffs: "name_only"`. Both E1 and E2 are
NameCheck-gated, so the prediction was *zero* movement — a prereg'd negative
control on a different ruler.

**Confirmed: the two 3,675-unit reports are sha256-identical**
(`57a06b494407c99b2dcc47bd34d702eeb3553b851eba9532dc96c84890a53e0f`, 21,062,347
bytes each, ~454 s per arm). Zero symbols moved, zero set skew, every project
measure unchanged to full precision.

This is the strongest single piece of evidence that neither tolerance leaked
outside its gate: an identical binary change, on a same-family target
(X360 MSVC PPC, dtk-split objects, same defect shapes present), produces exactly
nothing at a ruler that is not NameCheck.

---

## 8. The 32 functions cleared by class E1

dc3 (23) — `SaveLoadManager::GetDialogMsg`, `SaveLoadManager::HandleEventResponse`,
`SaveLoadManager::OnMsg(SigninChangedMsg)`, `CameraTilt::Poll`,
`SpeechMgr::GetSpeechLanguageDir`, `ftp_statemach_act`, `Curl_ftp_parselist`,
`Curl_httpchunk_read`, `multi_getsock`, `multi_runsingle`, `Curl_raw_toupper`,
`rtsp_do`, `smtp_statemach_act`, `curl_easy_strerror`, `Curl_setopt`,
`DataNode::DataTypeString`, `DataNode::Load`, `DataNode::Print`,
`DataNode::Save`, `Holmes::ProtocolDebugString`, `GetSystemLocale`,
`SongInfoAudioTypeToSym`, `inflate`.

rb3-xenon (9) — `GetSymbolFromAssetType`, `DataNode::Load`, `DataNode::Print`,
`DataNode::Save`, `GemPlayer::PlayMissSound`, `MusicLibrary::DifficultySortPart`,
`TypeToString`, `AssetMgr::EquipAsset`, `inflate`.

A further 14 dc3 and 12 rb3-xenon E1 symbols move up without reaching 100
(residual elsewhere in the function). All in `moved_symbols.csv`.

Note `SongInfoAudioTypeToSym` (README G33) and `SaveLoadManager::HandleEventResponse`
(G24) are in the cleared set, and `GetDialogMsg` — the function `4c38c31` was
settled on — is too.

---

## 9. Side finding, outside T1's scope but load-bearing for anyone scoring

**`objdiff-cli diff --format proto` silently ignores the project-level
`functionRelocDiffs`.** `objdiff-cli/src/cmd/diff.rs:849` calls
`build_config_from_args(args, None, unit_options, project_dir)` — `project_config`
is passed as `None` on the `run_oneshot` (proto) path only; `run_json`
(markdown/json, line 934) and `run_interactive` (line 3057) both pass it. The
base config is `FunctionRelocDiffs::DataValue` (line 879), so proto output on
dc3 runs at `DataValue` while `report generate` runs at the shipped
`name_check`.

Measured, not read: same binary, same symbol, proto output with and without an
explicit `-c functionRelocDiffs=name_check` differ (1,920,687 vs 1,904,440
bytes; `work/protocheck/`). Any consumer scoring through `--format proto` is on
a different ruler than `report.json`. Not caused by this deploy — it is true of
the deployed binary too — but it will corrupt any parity comparison that mixes
the two output formats.

---

## 10. Reproduction

```bash
RUN=/home/free/code/milohax/decomp-bench/archive/runs/2026-08-12-objdiff-ruler-parity

# per-symbol delta for any arm pair
python3 $RUN/work/report_delta.py $RUN/reports/dc3-A_deployed.json \
        $RUN/reports/dc3-E_9138611.json --label headline --json /dev/null

# regenerate any arm (each arm MUST get its own -o path: the .cache sidecar
# ignores which binary produced it)
cd /home/free/code/milohax/dc3-decomp && \
  $RUN/bin/objdiff-cli-cb238c8 report generate -p . -o $RUN/reports/dc3-B_cb238c8.json

sha256sum $RUN/reports/*.json          # arm identity at a glance
```

The 384 MB of reports, the 45 MB of binaries and the 3.7 MB proto pair are
deliberately not committed (`.gitignore` in the run dir says so and why); the
deltas, the CSV, the logs and both scripts are.

## 11. What this licenses, and what it does not

**Licensed:** replacing `objdiff/target/release/objdiff-cli` with a build of
objdiff `9138611`. Every score that moves has a named cause, all movement is
upward, and the before arm is a measured `cb238c8`.

**Not licensed by this document:**

- Any splitter (`dtk`) change. Nothing here touches jeff. Shape 2 (the
  intra-function REL14, 2 on dc3 and 59 on rb3-xenon) is untouched by all three
  commits and remains the only live splitter defect.
- Treating the 39 `fuzzy=100` arrivals or the 16 `normalized=100` flips as
  cracks. They are ruler movements at `name_check`; a crack needs the byte-exact
  bar.
- Any cross-boundary numeric comparison. Reports generated before and after the
  deploy are on different rulers and must be regenerated, not diffed.
