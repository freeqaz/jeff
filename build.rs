//! Stamps the build's git identity into the binary, for `--version` and for the
//! `tool_commit` field of every `split_manifest.json`.
//!
//! WHY THIS IS NOT JUST `git rev-parse HEAD`. It used to be, and the stamp lied.
//! The `dtk` deployed at `../jeff/target/release/dtk` on 2026-08-18 -- the binary
//! that writes the target side of nearly every diff in dc3-decomp, rb3-xenon and
//! cea -- reported `1.14.0 b4b25bcb4805...`, a commit that does NOT contain the
//! COMDAT dead-space change (614331e) that 2,048 of dc3's 2,223 target objects
//! carry. It was built from a dirty tree a minute before `b4b25bc` landed, so the
//! stamp named a commit whose code the binary did not match. The only check that
//! worked was `strings -a dtk | grep -c __comdat_gap`. A provenance field that
//! cannot report "I do not know" is not provenance; it is a guess wearing a
//! hash's clothes.
//!
//! Two independent defects had to be fixed:
//!
//!   1. DIRTINESS. `git rev-parse HEAD` is the commit that is checked out, not
//!      the code that is compiled. We now suffix `-dirty` when tracked files are
//!      modified, and emit an EMPTY string outside a git checkout rather than
//!      inventing something.
//!
//!   2. STALENESS. The old file emitted `cargo:rustc-rerun-if-changed=.git/HEAD`,
//!      which is not a cargo directive at all -- the real spelling has no
//!      `rustc-` -- so cargo saw a build script that declared NO rerun inputs and
//!      fell back to "re-run if any file in the package changes". And `.git/HEAD`
//!      is a plain path, which does not exist in a linked worktree, where `.git`
//!      is a file.
//!
//! Both halves of (2) matter, and the first attempt at this file got it wrong by
//! fixing only one. Declaring the git refs and nothing else is a REGRESSION for
//! the commonest dirty case: an unstaged edit to a tracked source file moves
//! neither HEAD nor the index, so the build script does not re-run and the
//! `-dirty` marker never appears. Caught by the sabotage below, which is why it
//! exists. Declaring *any* `rerun-if-changed` also switches off cargo's
//! "any file in the package" fallback -- so the fallback has to be re-declared
//! by hand. Hence both sets: the git refs (a commit or checkout that does not
//! touch a file) AND the compiled sources (a file that does not touch a ref).
//!
//! Even with both, the stamp remains ADVISORY, and the module doc on
//! `crate::build_id` says so. Cargo watches these paths by mtime, and mtime is
//! not content; a tracked file outside the declared set (`README.md`,
//! `docs/`) can differ from HEAD without the marker appearing. That case does
//! not change the binary, but it does mean "clean" here means "the code is
//! clean", not "the tree is". The authoritative identity is the xxh3 of the
//! executable itself, computed at runtime -- this stamp exists to make that hash
//! human-readable, not to replace it.
//!
//! `scripts/build_stamp_honesty.sh` is the sabotage: it builds clean, builds
//! dirty, and builds clean again, and requires the stamp to move and come back.
//!
//! Modelled on objdiff's `objdiff-cli/build.rs`, which got here first; that
//! stamp is why `callee_gate` and `pattern_census` can name their instrument.
use std::process::Command;

fn main() {
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    // (a) Re-run when the checked-out commit changes without a file changing --
    // a `git commit` of what is already on disk, a checkout, a branch switch.
    // `--git-path` resolves correctly from a linked worktree, where `.git` is a
    // file rather than a directory.
    for path in ["HEAD", "index"] {
        if let Some(p) = git(&["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(p) = git(&["rev-parse", "--git-path", &head_ref]) {
            println!("cargo:rerun-if-changed={p}");
        }
    }

    // (b) ...and when a file changes without the commit changing -- the unstaged
    // edit, which is how the 2026-08-18 binary came to exist. Declaring (a)
    // switches off cargo's "any file in the package" default, so the part of it
    // that was load-bearing has to be re-declared. These are exactly the inputs
    // that can change the compiled bytes; watching them costs three `git`
    // invocations per source edit.
    for path in ["src", "build.rs", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={path}");
    }

    let commit = match git(&["rev-parse", "HEAD"]) {
        Some(c) if !c.is_empty() => {
            // `--untracked-files=no`: an untracked scratch file does not change
            // what was compiled, and treating it as dirt would make the marker
            // so noisy nobody would read it.
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if dirty {
                format!("{c}-dirty")
            } else {
                c
            }
        }
        // Not a git checkout (a tarball, a vendored build). Empty, never a guess.
        _ => String::new(),
    };
    println!("cargo:rustc-env=GIT_COMMIT_SHA={commit}");
}
