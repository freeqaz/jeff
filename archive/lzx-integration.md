# LZX Decompression Integration Design

## Background

Xbox 360 executables (XEX files) can use LZX compression on the embedded PE image.
LZX is Microsoft's general-purpose compression algorithm, also used in CAB archives.
When a XEX uses `XexCompression::Compressed`, the PE data (after AES-128-CBC decryption)
is stored as a chain of LZX-compressed blocks that must be decompressed before the PE
image can be reconstructed.

jeff currently bails on LZX-compressed XEX files (`src/util/xex.rs:649-656`).

### POC Results

A proof-of-concept (`cargo test test_lzx_poc`) confirmed that the `lzxd` crate (v0.2,
standard LZX — same format as CAB) correctly decompresses XEX LZX data:

- **GH2 TU1** — decompressed successfully, MZ header valid, size matched `image_size`
- **RB2 TU0** — decompressed successfully, MZ header valid, size matched `image_size`

The POC test code lives in the `#[cfg(test)]` module at the bottom of `src/util/xex.rs`.

## Integration Point

The entire change is localized to **one match arm** in `try_get_exe()`. Replace the
`bail!()` at line 649-656 with decompression logic. The surrounding code already handles
everything else:

| Step | Location | Status |
|------|----------|--------|
| AES decryption | `try_get_exe` lines 619-626 | Existing — populates `compressed` |
| **LZX decompression** | **lines 649-656** | **Replace `bail!()` with new code** |
| MZ validation | line 659 | Existing |
| PE section adjustment | lines 661-691 | Existing |
| Dual-key fallback | `from_file` lines 568-598 | Existing — retries with devkit key on `Err` |

The new code in the `XexCompression::Compressed` arm will:

1. Extract `NormalCompression` metadata (`window_size`, `block_size`) from `bff.normal`
2. Walk the decrypted block chain via `collect_lzx_chunks()`
3. Feed each chunk to `lzxd::Lzxd::decompress_next()`
4. Write the result into `pe_image`

## XEX Block Chain Format

Binary layout of the decrypted data when compression is LZX (derived from
Xenia/idaxex, validated by the POC):

```
Block (repeating):
  ┌─────────────────────────────────────┐
  │ next_block_size : u32 (big-endian)  │  0 = last block
  │ sha1_hash       : [u8; 20]         │  hash of next block's raw bytes
  ├─────────────────────────────────────┤
  │ Chunk 0:                            │
  │   compressed_size : u16 (BE)        │  0 = end of block's chunks
  │   lzx_data        : [u8; N]        │
  │ Chunk 1:                            │
  │   compressed_size : u16 (BE)        │
  │   lzx_data        : [u8; N]        │
  │ ...                                 │
  └─────────────────────────────────────┘
```

- The first block's size comes from `NormalCompression::block_size`
- Each subsequent block's size comes from the previous block's `next_block_size` field
- Each chunk is one LZX frame producing up to 32 KB of decompressed output
  (the last chunk may produce less to fill the remaining `image_size`)

## Code Structure

Promote two helpers from the test module to private free functions in `src/util/xex.rs`,
placed near `try_get_exe`:

### `map_window_size(raw: u32) -> Result<lzxd::WindowSize>`

Converts from `NormalCompression::window_size` (byte count like 32768, 65536, etc.)
to the `lzxd::WindowSize` enum.

Production change from POC: return `Result` with `bail!` on unknown sizes instead of
`panic!`.

```rust
fn map_window_size(raw: u32) -> Result<lzxd::WindowSize> {
    match raw {
        32768 => Ok(lzxd::WindowSize::KB32),
        65536 => Ok(lzxd::WindowSize::KB64),
        131072 => Ok(lzxd::WindowSize::KB128),
        262144 => Ok(lzxd::WindowSize::KB256),
        524288 => Ok(lzxd::WindowSize::KB512),
        1048576 => Ok(lzxd::WindowSize::MB1),
        2097152 => Ok(lzxd::WindowSize::MB2),
        4194304 => Ok(lzxd::WindowSize::MB4),
        8388608 => Ok(lzxd::WindowSize::MB8),
        16777216 => Ok(lzxd::WindowSize::MB16),
        33554432 => Ok(lzxd::WindowSize::MB32),
        _ => bail!("Unknown LZX window size: {}", raw),
    }
}
```

### `collect_lzx_chunks(decrypted: &[u8], first_block_size: u32) -> Result<Vec<Vec<u8>>>`

Walks the block chain and extracts raw LZX chunks.

Production changes from POC:
- Takes `&[u8]` instead of `&Vec<u8>`
- Returns `Result` with `ensure!()` for bounds checks instead of `assert!`

```rust
fn collect_lzx_chunks(decrypted: &[u8], first_block_size: u32) -> Result<Vec<Vec<u8>>> {
    let mut chunks: Vec<Vec<u8>> = vec![];
    let mut pos: usize = 0;
    let mut current_block_size = first_block_size as usize;

    loop {
        let block_start = pos;

        let next_block_size = read_word(decrypted, pos) as usize;
        pos += 4;
        pos += 20; // skip SHA1

        let block_end = block_start + current_block_size;
        while pos + 2 <= block_end && pos + 2 <= decrypted.len() {
            let chunk_size = read_halfword(decrypted, pos) as usize;
            pos += 2;
            if chunk_size == 0 {
                break;
            }
            ensure!(
                pos + chunk_size <= decrypted.len(),
                "LZX chunk extends beyond data: pos={}, chunk_size={}, data_len={}",
                pos, chunk_size, decrypted.len()
            );
            chunks.push(decrypted[pos..pos + chunk_size].to_vec());
            pos += chunk_size;
        }

        if next_block_size == 0 {
            break;
        }

        pos = block_end;
        current_block_size = next_block_size;
    }

    Ok(chunks)
}
```

### Match arm replacement (lines 649-656)

```rust
XexCompression::Compressed => {
    let normal = bff.normal.as_ref()
        .context("Missing NormalCompression metadata for LZX-compressed XEX")?;
    let window_size = map_window_size(normal.window_size)?;
    let chunks = collect_lzx_chunks(&compressed, normal.block_size)?;

    let mut lzxd = lzxd::Lzxd::new(window_size);
    let mut decompressed: Vec<u8> = Vec::new();

    for (i, chunk) in chunks.iter().enumerate() {
        let remaining = img_size as usize - decompressed.len();
        let output_len = remaining.min(lzxd::MAX_CHUNK_SIZE);

        let result = lzxd.decompress_next(chunk, output_len).map_err(|e| {
            anyhow!(
                "LZX decompression failed at chunk {} ({} bytes, output_len={}, \
                 total={}/{}): {}",
                i, chunk.len(), output_len, decompressed.len(), img_size, e,
            )
        })?;
        decompressed.extend_from_slice(result);
    }

    pe_image = decompressed;
}
```

## Dependency Change

Move `lzxd` from dev-dependencies to dependencies in `Cargo.toml`:

```toml
# Remove from [dev-dependencies]:
# lzxd = "0.2"

# Add to [dependencies]:
lzxd = "0.2"
```

## Error Handling

Errors must propagate cleanly so the **dual-key fallback** in `from_file()` works.
The fallback logic (lines 568-598) calls `try_get_exe` with the retail key first,
and on any `Err`, retries with the devkit key. This means:

- **Wrong key** → garbled decrypted data → block parsing or decompression fails → `Err`
  → fallback tries the other key automatically
- `map_window_size`: returns `Result`, bails on unknown window size
- `collect_lzx_chunks`: returns `Result`, uses `ensure!()` for bounds checks
- `decompress_next`: `DecompressError` is mapped to `anyhow::Error` with chunk index
  and size context for debugging

No panics in the production path — all errors are `Result`-based.

## Testing Strategy

### Constraint

The `lzxd` crate is decompression-only — no LZX encoder exists in the Rust ecosystem.
We cannot generate valid compressed LZX streams synthetically. This shapes the strategy
into two tiers: unit tests for the helpers (no LZX data needed) and integration tests
against real XEX files (existing POC tests).

### Tier 1: Unit tests (hermetic, run in CI)

These use hand-crafted `&[u8]` byte arrays — no fixtures, no external files.

**`map_window_size`** — exhaustive mapping coverage:
- All 11 valid sizes (32KB through 32MB) return the correct `WindowSize` variant
- An invalid size (e.g. `999`) returns `Err`
- Boundary values: `0`, `u32::MAX`

**`collect_lzx_chunks`** — the block chain parser is pure binary parsing and doesn't
touch LZX decompression, so chunk payloads can be arbitrary bytes:

| Case | Hand-crafted input | Validates |
|------|--------------------|-----------|
| Single block, one chunk | `[next=0 (4B BE)] [sha1 (20B zeros)] [chunk_size=3 (2B BE)] [0xAA 0xBB 0xCC]` | Basic extraction: returns 1 chunk of `[AA BB CC]` |
| Single block, two chunks | Same header, two chunk entries back-to-back, then `chunk_size=0` sentinel | Multiple chunks within one block |
| Two-block chain | First block's `next_block_size` points to second block; second block has `next=0` | Chain traversal, `current_block_size` updates correctly |
| Chunk at block boundary | Chunks exactly fill the block (no zero sentinel needed) | Parser stops at `block_end` without overread |
| Truncated chunk | `chunk_size` larger than remaining data | Returns `Err` (the `ensure!()` fires) |
| Empty data | Zero-length slice | Returns `Err` or empty vec (bounds check) |

Example of building a single-block fixture inline:

```rust
#[test]
fn test_collect_single_block_one_chunk() {
    // Block: next_size=0 (last), sha1=zeros, one 3-byte chunk
    let mut data: Vec<u8> = vec![];
    data.extend(&0u32.to_be_bytes());       // next_block_size = 0
    data.extend(&[0u8; 20]);                // sha1 placeholder
    data.extend(&3u16.to_be_bytes());       // chunk compressed_size = 3
    data.extend(&[0xAA, 0xBB, 0xCC]);      // chunk payload

    let block_size = data.len() as u32;
    let chunks = collect_lzx_chunks(&data, block_size).unwrap();

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0], vec![0xAA, 0xBB, 0xCC]);
}
```

### Tier 2: Integration tests (require external XEX files, skip otherwise)

The existing POC tests cover the full pipeline — decryption, block chain parsing, LZX
decompression, MZ validation, and size checks — against real game XEX files:

- `test_lzx_poc_gh2` — Guitar Hero 2 TU1
- `test_lzx_poc_rb2` — Rock Band 2 TU0

These gracefully skip when the files aren't present (`if !Path::new(path).exists()`),
so they won't break CI. They remain as regression tests after integration, validating
that the production helpers produce identical results to the POC.

### Why not commit a test fixture?

A minimal valid LZX-compressed XEX would need: a valid XEX header, loader info,
`NormalCompression` metadata, encrypted block chain with valid LZX frames, and correct
SHA1 hashes. This is effectively a real game executable — generating one from scratch
is infeasible without an LZX encoder, and committing copyrighted game data is not
appropriate. The two-tier approach gives us deterministic CI coverage on the code we
own (the parser) and real-world validation on the code we don't (the `lzxd` crate).

## Cleanup

- Remove the `bail!()` and reference comments at lines 649-656 (replaced by new code)
- Remove `README.md` line 52 (`Xexes that were LZX compressed are not currently supported.`)
- POC tests (`test_lzx_poc_gh2`, `test_lzx_poc_rb2`) stay as regression tests — they
  validate the full decompression pipeline independently of the production code path

## Verification

After implementation, verify with:

1. `cargo test test_lzx_poc` — existing POC tests (GH2 + RB2) continue passing
2. `cargo run -- xex extract <lzx-compressed.xex>` — produces valid EXE with MZ header
3. `cargo run -- xex info <lzx-compressed.xex>` — displays info without error
4. `cargo run -- xex split <config.yml>` — full split workflow completes on LZX XEX

## Files to Modify

| File | Change |
|------|--------|
| `src/util/xex.rs:649-656` | Replace `bail!` with LZX decompression logic |
| `src/util/xex.rs` (new fns) | Add `map_window_size`, `collect_lzx_chunks` near `try_get_exe` |
| `Cargo.toml` | Move `lzxd` from `[dev-dependencies]` to `[dependencies]` |
| `README.md:52` | Remove LZX known issue line |
