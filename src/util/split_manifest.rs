//! A record of every file a split wrote, and every file it read to decide.
//!
//! # Why this exists
//!
//! `dtk xex split` writes thousands of files — one target `.obj` (and, when
//! `write_asm` is on, one `.s`) per unit, plus `config.json`, `dep`,
//! `proposed_splits.txt`, and the extracted `.exe`. Only **one** of them,
//! `config.json`, is ever named as an output by the build systems that drive
//! it. The rest are undeclared side effects: no ninja edge names them, nothing
//! stats them, and no consumer can tell whether the ones on disk came from the
//! config that is on disk *now*.
//!
//! That is not a hygiene complaint. The target objects are the entire
//! reference side of every `objdiff` comparison a decomp project makes, and
//! their **content depends on `symbols.txt`** — dtk writes each function under
//! the name `symbols.txt` gives its address. So a report taken over objects
//! split from a *different* `symbols.txt` is a different measurement, and it is
//! silent: a function whose target-side name no longer pairs scores `0.0`,
//! which is indistinguishable from a function that was never written.
//!
//! Measured in `dc3-decomp` (Xbox 360 MSVC, title `373307D9`) on 2026-08-21 —
//! one worktree, one `objdiff-cli` (4.2.7 / `76c8da87e040`), report cache cold
//! on both runs, identical `symbols.txt` on disk the whole time:
//!
//! ```text
//! report started 2 s into `dtk xex split`  ->  29,497 matched functions
//! the same command after the split finished ->  29,838
//! ```
//!
//! A 341-function gap discriminated only by *when* it ran. Neither run failed
//! and neither warned. There is a second, deterministic form: restore
//! `symbols.txt` with an *older* mtime than `config.json` (`cp -a`, `tar -x`, a
//! reflinked worktree) and ninja does not plan `SPLIT` at all — so the report
//! measures objects that disagree with the config indefinitely.
//!
//! Consumers had been papering over this from the outside, by bracketing the
//! split with their own stamp files. That is a seatbelt bolted to the wrong
//! car: the splitter is the only party that actually knows what it wrote.
//!
//! # What this is not
//!
//! It is deliberately **not** a depfile. ninja's depfile grammar carries
//! exactly one output, and rejects a depfile naming more than one — so a
//! depfile cannot declare 2,223 objects no matter how it is written. A
//! manifest can, and it can additionally be *content*-keyed, which is the only
//! thing that catches the mtime-invisible form above.
//!
//! # The fixed-point rule
//!
//! `dtk xex split` must be a fixed point of its own input: re-running it on an
//! unchanged tree must produce an unchanged tree, or every depfile/manifest
//! edge that consumes it self-refires on every build. So this manifest records
//! **only content-derived facts** — no timestamps, no pids, no host paths, no
//! iteration order (`BTreeMap` throughout) — and is written through
//! [`write_if_changed`], exactly like the objects are. Re-running a split with
//! unchanged inputs leaves the manifest byte-identical *and* leaves its mtime
//! alone.

use std::{
    collections::BTreeMap,
    fs,
    io::Write,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

/// Bump when the document's *shape* changes in a way a reader must notice.
/// Readers should refuse a version they do not know rather than guess.
pub const MANIFEST_VERSION: u32 = 1;

/// Written next to `config.json`, i.e. `<out_dir>/split_manifest.json`.
pub const MANIFEST_FILE_NAME: &str = "split_manifest.json";

/// One file, identified by content rather than by mtime.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRecord {
    pub size: u64,
    /// Lowercase hex SHA-1 of the file's bytes.
    pub sha1: String,
}

impl FileRecord {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha1::new();
        hasher.update(bytes);
        Self { size: bytes.len() as u64, sha1: hex::encode(hasher.finalize()) }
    }

    pub fn of_file(path: &Utf8NativePath) -> Result<Self> {
        let bytes = fs::read(path.as_str())
            .with_context(|| format!("Failed to read '{path}' for the split manifest"))?;
        Ok(Self::of_bytes(&bytes))
    }
}

/// The document `dtk` writes to declare what a split produced and consumed.
///
/// Field order here is the serialized order, and it is chosen so a human
/// opening the file sees the identity of the run before the 2,223-line
/// inventory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SplitManifest {
    pub manifest_version: u32,
    /// `CARGO_PKG_VERSION` of the dtk that wrote this.
    pub tool_version: String,
    /// `GIT_COMMIT_SHA` of the dtk that wrote this. Two dtk builds with the
    /// same outputs is the common case, but when outputs *do* move this is the
    /// field that says why, and it is the one thing a consumer cannot recover
    /// by hashing files on disk.
    pub tool_commit: String,
    /// e.g. `"xex split"`. Present so a future `dol split` manifest is
    /// distinguishable without inspecting the payload.
    pub command: String,
    /// The config file passed on the command line, as given (unix-encoded).
    pub config: String,
    /// The output directory passed on the command line, as given (unix-encoded).
    pub out_dir: String,
    /// Everything the split READ to decide what to write: the xex, the map,
    /// `symbols.txt`, `splits.txt`, the config itself. This is the same set the
    /// `dep` file names, but hashed — so a consumer can answer "were these
    /// objects produced by the config that is on disk right now?" without
    /// believing an mtime.
    pub inputs: BTreeMap<String, FileRecord>,
    /// Everything the split WROTE. Keys are paths as the split addressed them
    /// (unix-encoded, relative to the caller's cwd when the arguments were).
    pub outputs: BTreeMap<String, FileRecord>,
}

/// Accumulates the manifest while a split runs.
///
/// The recording calls are cheap and infallible-by-content: every writer in the
/// split already has the bytes in hand, so nothing here re-reads a file it just
/// wrote (which would both cost 71 MB of I/O and, worse, be able to disagree
/// with what was written).
pub struct SplitManifestBuilder {
    command: String,
    config: String,
    out_dir: String,
    inputs: BTreeMap<String, FileRecord>,
    outputs: BTreeMap<String, FileRecord>,
}

impl SplitManifestBuilder {
    pub fn new(command: &str, config: &Utf8NativePath, out_dir: &Utf8NativePath) -> Self {
        Self {
            command: command.to_string(),
            config: config.with_unix_encoding().to_string(),
            out_dir: out_dir.with_unix_encoding().to_string(),
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
        }
    }

    /// Record a file the split WROTE, from the bytes it wrote.
    pub fn record_output(&mut self, path: &Utf8NativePath, contents: &[u8]) {
        self.outputs.insert(normalize_key(path), FileRecord::of_bytes(contents));
    }

    /// Record a file the split WROTE, by reading it back.
    ///
    /// For the handful of writers that own their own formatting and do not hand
    /// the bytes back. Reading it back is not merely convenient: it means the
    /// manifest describes what is ON DISK, which is the only thing a consumer
    /// can check.
    pub fn record_output_from_disk(&mut self, path: &Utf8NativePath) -> Result<()> {
        let record = FileRecord::of_file(path)?;
        self.outputs.insert(normalize_key(path), record);
        Ok(())
    }

    /// Record a file the split READ, hashing it from disk.
    ///
    /// Missing inputs are recorded as absent rather than erroring: `map` is
    /// optional, and a split that got far enough to write a manifest has
    /// already proven it could read everything it needed.
    pub fn record_input(&mut self, path: &Utf8NativePath) {
        if let Ok(record) = FileRecord::of_file(path) {
            self.inputs.insert(normalize_key(path), record);
        }
    }

    pub fn record_inputs<'a, I>(&mut self, paths: I)
    where I: IntoIterator<Item = &'a Utf8NativePathBuf> {
        for path in paths {
            self.record_input(path.as_path());
        }
    }

    pub fn output_count(&self) -> usize { self.outputs.len() }

    pub fn finish(self) -> SplitManifest {
        SplitManifest {
            manifest_version: MANIFEST_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            tool_commit: env!("GIT_COMMIT_SHA").trim().to_string(),
            command: self.command,
            config: self.config,
            out_dir: self.out_dir,
            inputs: self.inputs,
            outputs: self.outputs,
        }
    }
}

/// Render the manifest exactly as it is written to disk.
///
/// Split out from [`write_manifest`] so the determinism test can assert on the
/// bytes without touching a filesystem.
pub fn render(manifest: &SplitManifest) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Write `contents` to `path` only if it differs from what is already there.
///
/// This is the fixed-point half of the contract. An unconditional write would
/// bump the mtime on every split, and any ninja edge declaring the manifest as
/// an output (with `restat`) would then re-fire its whole downstream on a tree
/// where nothing moved.
///
/// Returns `true` when the file was actually rewritten.
pub fn write_if_changed(path: &Utf8NativePath, contents: &[u8]) -> Result<bool> {
    if let Ok(existing) = fs::read(path.as_str()) {
        if existing == contents {
            return Ok(false);
        }
    }
    let mut file = fs::File::create(path.as_str())
        .with_context(|| format!("Failed to create '{path}'"))?;
    file.write_all(contents).with_context(|| format!("Failed to write '{path}'"))?;
    file.flush()?;
    Ok(true)
}

/// Write the manifest into `out_dir`. Returns the path written.
pub fn write_manifest(
    out_dir: &Utf8NativePath,
    manifest: &SplitManifest,
) -> Result<Utf8NativePathBuf> {
    let path = out_dir.join(MANIFEST_FILE_NAME);
    let bytes = render(manifest)?;
    write_if_changed(path.as_path(), &bytes)?;
    Ok(path)
}

/// Path keys are unix-encoded and `.`/`..` are collapsed, so the same file
/// named two ways from the same cwd lands on one key. A split addresses some
/// files by joining onto `out_dir` and others by joining onto a config-relative
/// parent, so this is not hypothetical tidiness.
fn normalize_key(path: &Utf8NativePath) -> String {
    path.normalize().with_unix_encoding().to_string()
}

#[cfg(test)]
mod tests {
    use typed_path::Utf8NativePathBuf;

    use super::*;

    fn builder() -> SplitManifestBuilder {
        SplitManifestBuilder::new(
            "xex split",
            Utf8NativePathBuf::from("config/373307D9/config.yml").as_path(),
            Utf8NativePathBuf::from("build/373307D9").as_path(),
        )
    }

    /// THE fixed-point property: the same split, recorded twice, renders to the
    /// same bytes. If this ever fails, every ninja edge consuming the manifest
    /// re-fires on every build.
    ///
    /// The negative control is inside the test: the *same* assertion is run
    /// against a run whose object content differs by one byte, and it must
    /// FAIL to be equal. Without it, `render` returning a constant would pass.
    #[test]
    fn render_is_a_fixed_point_of_content_but_not_blind_to_it() {
        let mut a = builder();
        let mut b = builder();
        // Deliberately record in OPPOSITE orders: a manifest that leaked
        // iteration order would differ here even with identical content.
        for (name, bytes) in [("obj/Zoo.obj", &b"zoo"[..]), ("obj/Ant.obj", &b"ant"[..])] {
            a.record_output(Utf8NativePathBuf::from(name).as_path(), bytes);
        }
        for (name, bytes) in [("obj/Ant.obj", &b"ant"[..]), ("obj/Zoo.obj", &b"zoo"[..])] {
            b.record_output(Utf8NativePathBuf::from(name).as_path(), bytes);
        }
        let rendered_a = render(&a.finish()).unwrap();
        let rendered_b = render(&b.finish()).unwrap();
        assert_eq!(rendered_a, rendered_b, "identical content must render identically");

        // NEGATIVE CONTROL: one byte of one object changes, and the manifest
        // must notice. This is what makes the equality above mean something.
        let mut c = builder();
        c.record_output(Utf8NativePathBuf::from("obj/Ant.obj").as_path(), b"ant");
        c.record_output(Utf8NativePathBuf::from("obj/Zoo.obj").as_path(), b"zoO");
        let rendered_c = render(&c.finish()).unwrap();
        assert_ne!(
            rendered_a, rendered_c,
            "a one-byte object change MUST move the manifest; a manifest that \
             cannot go red is not a manifest"
        );
    }

    /// The manifest must not smuggle in anything that changes on its own.
    /// Timestamps and pids are the classic offenders, and they are exactly what
    /// the stamp files this replaces were made of.
    #[test]
    fn render_contains_no_wall_clock_or_process_state() {
        let mut b = builder();
        b.record_output(Utf8NativePathBuf::from("obj/One.obj").as_path(), b"x");
        let text = String::from_utf8(render(&b.finish()).unwrap()).unwrap();
        for banned in ["unix_time", "timestamp", "mtime", "pid", "generated"] {
            assert!(
                !text.contains(banned),
                "manifest contains non-content field `{banned}`: {text}"
            );
        }
    }

    #[test]
    fn write_if_changed_leaves_an_identical_file_alone() {
        let dir = std::env::temp_dir().join(format!("dtk-manifest-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = Utf8NativePathBuf::from(dir.join("m.json").to_str().unwrap().to_string());

        assert!(write_if_changed(path.as_path(), b"first").unwrap(), "first write must happen");
        assert!(
            !write_if_changed(path.as_path(), b"first").unwrap(),
            "an unchanged rewrite must be skipped -- this is the fixed-point rule"
        );
        // NEGATIVE CONTROL: it must still write when the content really moves.
        assert!(
            write_if_changed(path.as_path(), b"second").unwrap(),
            "a changed rewrite must happen -- a writer that never writes is not a writer"
        );
        assert_eq!(fs::read(path.as_str()).unwrap(), b"second");
        fs::remove_dir_all(&dir).ok();
    }

    /// Path keys must be stable across the ways the same file can be spelled,
    /// or two runs that differ only in spelling produce different manifests.
    #[test]
    fn keys_are_normalized() {
        let mut b = builder();
        b.record_output(Utf8NativePathBuf::from("build/./x/../obj/A.obj").as_path(), b"a");
        let manifest = b.finish();
        assert!(
            manifest.outputs.contains_key("build/obj/A.obj"),
            "expected a normalized key, got {:?}",
            manifest.outputs.keys().collect::<Vec<_>>()
        );
    }
}
