//! memzero / memzero_aligned / memset — originals: `FUN_080002d4` @
//! 0x080002d4 (68 bytes), `FUN_0800027c` @ 0x0800027c (88 bytes),
//! `FUN_08030fe4` @ 0x08030fe4 (20 bytes).
//!
//! All three share one word-block fill body at 0x08000280: 32-byte blocks
//! (two 16-byte `stmia`s writing four copies of the fill word each), then a
//! tail that picks off bits 4..0 of the remainder with 16/8/4/2/1-byte
//! stores. `memzero_aligned` enters that body directly (entry expects an
//! already word-aligned `dst`); `memzero` adds a prologue: for `len < 4` it
//! byte-stores the whole range, otherwise it byte-stores up to word
//! alignment and subtracts the head from `len`. `memset` broadcasts the byte
//! value into a full word and tail-branches (through an iRAM veneer) into
//! the memzero body just past its `mov r2, #0` — mirrored here by both
//! calling the same private `fill`.
//!
//! Deviations from the originals:
//! - The original memset is ARM ADS `__rt_memset(dst, len, value)` — length
//!   in r1, byte value in r2. The port uses the classic C signature
//!   `memset(dst, value, len)`.
//! - The originals advance r0 through the fill and effectively return the
//!   end pointer; the ports return the original `dst` (classic memset
//!   semantics).
//!
//! Behavioral verification: host-side `cargo test` compares against simple
//! reference implementations across lengths, alignments and fill values;
//! `tools/match.py` (ipod-decomp) reports the mnemonic-level diff against
//! the original machine code.

#[inline(always)]
unsafe fn write_word(aligned: *mut u8, value: u32) {
    (aligned as *mut u32).write(value);
}

/// Shared fill body (original @ 0x08000280). `dst` must be word-aligned.
/// 32-byte blocks, then 16/8/4/2/1-byte tail picked off by remainder bits.
unsafe fn fill_blocks(mut dst: *mut u8, word: u32, mut len: usize) {
    while len >= 32 {
        // Two 16-byte stmia of {word, word, word, word} per iteration.
        write_word(dst, word);
        write_word(dst.add(4), word);
        write_word(dst.add(8), word);
        write_word(dst.add(12), word);
        write_word(dst.add(16), word);
        write_word(dst.add(20), word);
        write_word(dst.add(24), word);
        write_word(dst.add(28), word);
        dst = dst.add(32);
        len -= 32;
    }
    // Tail: the original tests bits 4..0 of the remainder via flag pickoff
    // after `lsls r1, r1, #28`.
    if len & 16 != 0 {
        write_word(dst, word);
        write_word(dst.add(4), word);
        write_word(dst.add(8), word);
        write_word(dst.add(12), word);
        dst = dst.add(16);
    }
    if len & 8 != 0 {
        write_word(dst, word);
        write_word(dst.add(4), word);
        dst = dst.add(8);
    }
    if len & 4 != 0 {
        write_word(dst, word);
        dst = dst.add(4);
    }
    let byte = word as u8;
    if len & 2 != 0 {
        *dst = byte;
        *dst.add(1) = byte;
        dst = dst.add(2);
    }
    if len & 1 != 0 {
        *dst = byte;
    }
}

/// memzero prologue + fill (original `FUN_080002d4` body): byte-store
/// everything when `len < 4`, else byte-store up to word alignment and
/// finish with the shared block fill.
unsafe fn fill(mut dst: *mut u8, mut len: usize, word: u32) {
    let byte = word as u8;
    if len < 4 {
        // Small path: the original stores len&2 ? two bytes, len&1 ? one.
        while len > 0 {
            *dst = byte;
            dst = dst.add(1);
            len -= 1;
        }
        return;
    }
    let misalign = dst as usize & 3;
    if misalign != 0 {
        let head = 4 - misalign;
        for _ in 0..head {
            *dst = byte;
            dst = dst.add(1);
        }
        len -= head;
    }
    fill_blocks(dst, word, len);
}

/// Zero-fill `len` bytes at `dst`; `dst` may be misaligned. Returns `dst`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memzero(dst: *mut u8, len: usize) -> *mut u8 {
    fill(dst, len, 0);
    dst
}

/// Zero-fill `len` bytes at `dst`; `dst` must be word-aligned (the original
/// enters the shared block-fill body directly). Returns `dst`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memzero_aligned(dst: *mut u8, len: usize) -> *mut u8 {
    fill_blocks(dst, 0, len);
    dst
}

/// Fill `len` bytes at `dst` with `value as u8`. Returns `dst`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, value: i32, len: usize) -> *mut u8 {
    // Broadcast the byte to a word, then run the memzero body (the original
    // tail-branches into memzero just past its `mov r2, #0`).
    let b = value as u8 as u32;
    fill(dst, len, b | (b << 8) | (b << 16) | (b << 24));
    dst
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Simple reference implementations.
    fn ref_memzero(dst: &mut [u8], len: usize) {
        for b in dst[..len].iter_mut() {
            *b = 0;
        }
    }

    fn ref_memset(dst: &mut [u8], value: i32, len: usize) {
        for b in dst[..len].iter_mut() {
            *b = value as u8;
        }
    }

    const PAD: usize = 8;

    fn pattern(size: usize) -> Vec<u8> {
        (0..size + PAD).map(|i| (0xA5u8 ^ (i as u32 * 37) as u8)).collect()
    }

    #[test]
    fn memzero_matches_reference() {
        for size in [4usize, 16, 64] {
            for off in 0..4usize {
                for len in 0..=size - off {
                    let mut orig = pattern(size);
                    let mut reference = orig.clone();
                    let dst = unsafe { orig.as_mut_ptr().add(off) };
                    let ret = unsafe { memzero(dst, len) };
                    ref_memzero(&mut reference[off..], len);
                    assert_eq!(orig, reference, "mismatch: off={off} len={len}");
                    assert_eq!(ret, dst, "return value: off={off} len={len}");
                }
            }
        }
    }

    #[test]
    fn memzero_aligned_matches_reference() {
        #[repr(align(4))]
        struct Aligned([u8; 80]);
        for len in 0..=64usize {
            let mut orig = Aligned([0x5Au8; 80]);
            let mut reference = pattern(72);
            for (i, b) in reference.iter_mut().enumerate() {
                orig.0[i] = *b;
            }
            let dst = orig.0.as_mut_ptr();
            assert_eq!(dst as usize & 3, 0);
            let ret = unsafe { memzero_aligned(dst, len) };
            ref_memzero(&mut reference[..], len);
            assert_eq!(
                &orig.0[..],
                &reference[..orig.0.len()],
                "mismatch: len={len}"
            );
            assert_eq!(ret, dst, "return value: len={len}");
        }
    }

    #[test]
    fn memset_matches_reference() {
        for value in [0i32, 1, 0x7f, 0x80, 0xff, -1, 0x1234, 0x100, -0x55] {
            for off in 0..4usize {
                for len in 0..=64usize {
                    let mut orig = pattern(off + len.max(64));
                    let mut reference = orig.clone();
                    let dst = unsafe { orig.as_mut_ptr().add(off) };
                    let ret = unsafe { memset(dst, value, len) };
                    ref_memset(&mut reference[off..], value, len);
                    assert_eq!(
                        orig, reference,
                        "mismatch: value={value:#x} off={off} len={len}"
                    );
                    assert_eq!(ret, dst, "return value: value={value:#x} off={off} len={len}");
                }
            }
        }
    }
}
