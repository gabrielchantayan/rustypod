# Porting guide

How a function travels from the iPod's stock firmware into this crate.

## The pipeline

```
osos.dec (decrypted ARM binary) ──Ghidra──> decomp/ reference C/asm
        │
        ▼  port by hand
rustypod/src/<module>.rs  ──cargo test──>  behavioral parity proven
        │
        ▼  cargo build -Z build-std=core --release
librustypod.a ──ipod-decomp/tools/build.py──> osos.patched
        │
        ▼  hooks.yaml (branch from stock code to Rust symbol)
runs on the iPod (tethered boot via wInd3x)
```

## Rules of the road

1. **Names say what things do.** `memmove`, `dst`, `src`, `len` — never
   `FUN_080000d4`, `param_1`, `uVar5`, `DAT_3c700000`. This is the point of
   the project.
2. **Cite the original.** Every ported function's doc header carries its
   load address, size and a one-paragraph algorithm summary, plus any
   deliberate deviations.
3. **Prove behavior with host tests.** `cargo test --target <host-triple>`
   (`aarch64-apple-darwin` on the Mac, `x86_64-unknown-linux-gnu` on sizipos)
   compares against a reference implementation on edge cases (alignments
   0..3, lengths 0..64, overlap, NUL placement...). Note the funnel-shift
   paths may read up to a word past the range — pad test buffers
   (see `libc.rs`'s `PAD`).
4. **Review codegen with match.py** (in ipod-decomp):
   `python3 tools/match.py 0x080000d4 memmove [--size N]`
   gives a mnemonic diff vs the original. Exact matches are NOT expected
   (ARM ADS 1.0.1 vs modern LLVM); use it to confirm the structure is the
   same (loops, block sizes, tail handling).
5. **Record everything in names.yaml**: address, signature, variable
   renames, notes, status (`identified` → `ported`).

## Picking the next function

- Browse `decomp/functions.csv` (32K functions) and `decomp/c/*/`. Good
  candidates are small, leaf, and well-understood: more runtime helpers,
  CRC/hash functions, format parsers.
- Hardware drivers need the register map (see freemyipod.org S5L8702 wiki
  and Rockbox's `firmware/target/arm/s5l8702/`); name registers as
  constants (`TIMER_A_CONTROL`, not `DAT_3c700000`).
- Call-site counts from the disassembly tell you what's worth doing:
  `grep -c "bl 0x080xxxxx" decomp/osos.asm`.

## Building into the firmware

From ipod-decomp: `make build` compiles this crate (nightly,
`-Z build-std=core`, target `armv5te-none-eabi`) and links `librustypod.a`
into the osos patch payload. `src/hooks.yaml` there plants branches from
stock addresses to `#[no_mangle]` Rust symbols. The demo hook routes the
stock `memmove` through our Rust port.

## Gotchas

- Use the rustup proxies (`~/.cargo/bin` first in PATH) for ARM builds;
  the Homebrew cargo ignores `rust-toolchain.toml`. Plain `cargo test`
  works for host tests.
- LLVM's loop-idiom recognition rewrites simple byte loops into calls to
  libc symbols that don't exist here (`strlen`, `memcpy`). If the ARM link
  fails with an undefined libc symbol, use `read_volatile`/`write_volatile`
  in the loop (see `strcat.rs`, `strlen_safe.rs`).
- Don't export symbols named exactly like compiler intrinsics unless you
  mean it — the crate's exported `memmove`/`memcpy`/`memset`/`memcmp`
  shadows are intentional (that's how hooks reach them).
- Exports are always `#[cfg_attr(target_os = "none", no_mangle)]`, never
  bare `#[no_mangle]`: in host test builds a bare export shadows the libc/
  libm symbol of the same name, and the soft-float bit-pattern signatures
  (`u64` for `double`) are ABI-compatible only on 32-bit ARM. On x86-64
  LLVM lowers `f64::ceil` & co. to libcalls, which then hit the shadow
  with garbage arguments.
