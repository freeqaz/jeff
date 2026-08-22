//! Who did the splitting.
//!
//! `dtk xex split` writes the entire reference side of every diff a decomp
//! project makes -- 2,223 target objects in dc3-decomp alone -- and none of them
//! is a declared build output. So the only way to answer "did these objects come
//! from the dtk I think they did?" is for dtk to say who it was, truthfully.
//!
//! It did not. The binary deployed on 2026-08-18 reported
//! `dtk 1.14.0 b4b25bcb4805...` while containing code from `614331e`, a commit
//! that was not even an ancestor of `main`. It was built from a dirty tree a
//! minute before `b4b25bc` landed. Nothing in the toolchain could tell; the check
//! that actually worked was `strings -a dtk | grep -c __comdat_gap`.
//!
//! Two identities, and they are not equivalent:
//!
//!   * [`binary_hash`] -- xxHash3-64 of the executing binary. AUTHORITATIVE.
//!     Different bytes, different instrument, whatever either build claims.
//!   * [`commit`] -- the git commit `build.rs` stamped in at build time,
//!     `-dirty`-suffixed if the tree had modified tracked files then, and empty
//!     outside a git checkout. Human-readable and ADVISORY: cargo re-runs a build
//!     script only when one of its declared `rerun-if-changed` inputs changes,
//!     and "a tracked file was edited but not staged" is not something it can
//!     declare, so the stamp can still lag the binary. Never treat a matching
//!     commit as proof that two binaries are the same.
//!
//! Lifted from objdiff's `objdiff-cli/src/build_id.rs`, which shipped this first.

/// xxHash3-64 (hex) of the running executable, computed once per process.
///
/// `None` if the executable cannot be located or read. A caller that needs an
/// identity must fail closed rather than substitute a weaker one.
///
/// Cost: one read of ~8 MB (page cache after the first) plus the hash, ~2 ms.
pub fn binary_hash() -> Option<&'static str> {
    static HASH: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    HASH.get_or_init(|| {
        let exe = std::env::current_exe().ok()?;
        let data = std::fs::read(exe).ok()?;
        Some(format!("{:016x}", xxhash_rust::xxh3::xxh3_64(&data)))
    })
    .as_deref()
}

/// The git commit this binary's build script last saw.
///
/// `"<sha>"` when the tree was clean, `"<sha>-dirty"` when tracked files were
/// modified, and `""` when the build was not from a git checkout at all. The
/// empty case is deliberate: a provenance field that cannot say "unknown" is
/// worse than one that is absent, because it forces a guess to be recorded as a
/// fact.
pub fn commit() -> &'static str { env!("GIT_COMMIT_SHA") }

/// `dtk 1.14.0 (76b42237ad1e-dirty, xxh3 44cf58d7697c1fe1)` -- the line
/// `--version` prints.
pub fn version_line(command_name: &str) -> String {
    format_version_line(command_name, env!("CARGO_PKG_VERSION"), commit(), binary_hash())
}

/// [`version_line`] with its three inputs handed in, so every state of the two
/// identities can be tested without producing a build in each state.
fn format_version_line(
    command_name: &str,
    package_version: &str,
    commit: &str,
    hash: Option<&str>,
) -> String {
    let mut line = format!("{command_name} {package_version}");
    if commit.is_empty() && hash.is_none() {
        // Nothing truthful to say about this build, and an empty `()` says it
        // worse than saying nothing.
        return line;
    }
    line.push_str(" (");
    if !commit.is_empty() {
        line.push_str(commit);
        // Unconditional: the hash half below always writes something, present or
        // not, so the separator is needed in both cases.
        line.push_str(", ");
    }
    match hash {
        Some(h) => line.push_str(&format!("xxh3 {h}")),
        // Say so out loud. A silent omission reads as "no hash exists".
        None => line.push_str("xxh3 unavailable"),
    }
    line.push(')');
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All four states of the two independent identities. Written before the
    /// formatter was, and each assertion is its own negative control: three of
    /// the four would pass against a naive `format!("{} {} ({}, xxh3 {})")`, and
    /// the ones that would not are exactly the ones that matter.
    #[test]
    fn test_version_line_separates_commit_from_hash_in_every_state() {
        assert_eq!(
            format_version_line("dtk", "1.14.0", "76b42237ad1e", Some("44cf58d7697c1fe1")),
            "dtk 1.14.0 (76b42237ad1e, xxh3 44cf58d7697c1fe1)"
        );
        // A dirty build must be legible as such at a glance; this is the state
        // the deployed 2026-08-18 binary was actually in.
        assert_eq!(
            format_version_line("dtk", "1.14.0", "76b42237ad1e-dirty", Some("44cf58d7697c1fe1")),
            "dtk 1.14.0 (76b42237ad1e-dirty, xxh3 44cf58d7697c1fe1)"
        );
        // No hash: a comma here, not `76b42237ad1exxh3 unavailable`.
        assert_eq!(
            format_version_line("dtk", "1.14.0", "76b42237ad1e", None),
            "dtk 1.14.0 (76b42237ad1e, xxh3 unavailable)"
        );
        // No commit (a tarball, a vendored build): no leading separator either.
        assert_eq!(
            format_version_line("dtk", "1.14.0", "", Some("44cf58d7697c1fe1")),
            "dtk 1.14.0 (xxh3 44cf58d7697c1fe1)"
        );
        // Neither identity: no empty parens.
        assert_eq!(format_version_line("dtk", "1.14.0", "", None), "dtk 1.14.0");
    }

    /// The stamp of THIS build must never be a bare non-empty string that merely
    /// looks like a sha -- it is either empty, a 40-hex sha, or that sha with the
    /// `-dirty` marker. Anything else means `build.rs` invented something.
    #[test]
    fn test_commit_stamp_is_empty_or_a_sha_optionally_marked_dirty() {
        let c = commit();
        if c.is_empty() {
            return; // not a git checkout: the honest answer
        }
        let sha = c.strip_suffix("-dirty").unwrap_or(c);
        assert_eq!(sha.len(), 40, "not a full sha: {c:?}");
        assert!(sha.chars().all(|ch| ch.is_ascii_hexdigit()), "not hex: {c:?}");
    }

    /// The real line still has the shape a `--version` consumer parses.
    #[test]
    fn test_version_line_of_this_build_is_well_formed() {
        let line = version_line("dtk");
        assert!(line.starts_with(&format!("dtk {}", env!("CARGO_PKG_VERSION"))), "{line}");
        // Whatever is in the parens, a hash never abuts the commit.
        assert!(!line.contains("xxh3") || line.contains("(xxh3 ") || line.contains(", xxh3 "));
    }

    /// The authoritative identity must actually be computable for the test
    /// binary, or `binary_hash()` is a function that always returns `None` and
    /// every caller silently degrades to the advisory one.
    #[test]
    fn test_binary_hash_is_available_and_stable_within_a_process() {
        let a = binary_hash().expect("test binary should be readable");
        assert_eq!(a.len(), 16, "xxh3-64 renders as 16 hex chars: {a:?}");
        assert_eq!(a, binary_hash().unwrap(), "memoized value must not drift");
    }
}
