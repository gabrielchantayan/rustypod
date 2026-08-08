//! IRAM veneers for the two hottest ADS block-memory routines — originals:
//! `thunk_EXT_FUN_22000188` @ 0x08037df8 and `thunk_EXT_FUN_220002d4` @
//! 0x08037dc8 (Ghidra reports 4 bytes each; the real stub is 8 — the
//! `ldr pc, [pc, #-4]` word 0xe51ff004 plus the absolute target word that
//! follows it).
//!
//! # Verified call-site counts (decoded from osos.dec, all B/BL encodings,
//! every condition code, not a Ghidra xref count)
//!
//! | veneer      | target       | `bl` | tail `b` |
//! |-------------|--------------|-----:|---------:|
//! | 0x08037df8  | 0x22000188   |  477 |       11 |
//! | 0x08037dc8  | 0x220002d4   |  106 |        7 |
//!
//! Of the 477 `bl`s to 0x08037df8, 465 are unconditional and 12 predicated.
//! 0x08037df8 is the most-called single address in the image reachable only
//! through a veneer.
//!
//! # The targets are recoverable: 0x2200XXXX mirrors osos 0x0800XXXX
//!
//! 0x22000000 is S5L8702 internal SRAM, so the bodies are not in osos.dec at
//! their own addresses. They are in osos.dec at the *mirror* offsets, and
//! three independent binary facts pin the mirror and its exact extent:
//!
//! 1. **An osos relocator populates IRAM from the image.** The routine @
//!    0x080046e0 calls memmove with dst = 0x22000000 and length 0xaed8, then
//!    zero-fills 0x2200aed8 for 0x589c bytes (the IRAM BSS), then jumps to
//!    0x22000000. So the IRAM code region is exactly 0xaed8 bytes long and is
//!    a copy of an image-resident blob — it is *not* mask ROM, which is where
//!    `kernel/thunks.rs` places it. (Mask ROM on this SoC is at 0x20000000;
//!    0x22000000 is IRAM.) The RTXC targets higher in the thunk table live in
//!    the same relocated region.
//! 2. **The image's low 0xaed8 bytes are a closed call island.** Decoding
//!    every B/BL word in osos.dec gives 1467 branches wholly inside
//!    0x08000000..0x0800aed8 and 188560 wholly above it — and 7 crossings
//!    total, all of them literal-pool words that merely happen to decode as
//!    branches. Nothing above 0x0800aed8 ever branches directly into that
//!    block; it reaches it only through the veneer table. That is precisely
//!    the shape of a region whose runtime home is elsewhere.
//! 3. **The offsets line up on real entry points.** 0x22000188 and
//!    0x220002d4 land exactly on `memcpy_forward_words` @ 0x08000188 and
//!    `memzero` @ 0x080002d4 — two independently identified ADS runtime
//!    entries (see names.yaml), not arbitrary mid-function addresses.
//!
//! Bucketing the call sites confirms the split with no exceptions: all 24
//! direct B/BL references to the in-image bodies (0x08000020, 0x080000d4,
//! 0x08000188, 0x080002d4) originate below 0x0800aed8, and all 601
//! references to these two veneers originate above it.
//!
//! # What the veneers do
//!
//! Nothing but transfer control: r0-r3 are untouched, no stack is used, `lr`
//! still points at the caller. So each veneer is exactly a tail call to the
//! already-ported body, and that is what these ports are — the seam a
//! `hooks.yaml` entry can plant a branch on to route all 477 (resp. 106)
//! call sites through the Rust implementation with a single 4-byte patch.
//!
//! # ABI details
//!
//! - `memcpy_forward_words` @ 0x08000188 advances r0 and returns
//!   `dst + len`; it also advances caller-saved r1. The veneer is a tail
//!   transfer, so it preserves that result exactly.
//! - `memcpy_forward_words` requires both pointers word-aligned (it is the
//!   aligned fast path of `__rt_memcpy`, broken out as its own entry). The
//!   veneer inherits that precondition unchanged.
//! - Each port loads its callee through `read_volatile` before calling it.
//!   Written as a plain call, LLVM recognises a memcpy-shaped body as the C
//!   library routine and re-lowers the veneer to `bl __aeabi_memcpy`, and
//!   inlines `memzero` outright — either way the veneer stops reaching the
//!   ported body, which is its entire purpose. The volatile load also happens
//!   to be the closer analogue of the original: `ldr pc, [pc, #-4]` is itself
//!   an indirect jump through a literal, not a direct branch. Both ports
//!   compile to `ldr rN, [pc, #8]; ldr rN, [rN]; bx rN` — the original's
//!   shape plus one indirection and a `push {fp, lr}` / `pop {fp, lr}` frame,
//!   with r0-r2 passed through untouched.

use crate::libc::memcpy::memcpy_forward_words;
use crate::libc::memzero::memzero;

/// Veneer @ 0x08037df8 -> IRAM 0x22000188 = `memcpy_forward_words`
/// (477 `bl`, 11 `b`).
///
/// # Safety
/// `dst` and `src` must both be word-aligned and valid for `len` bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iram_memcpy_veneer(
    dst: *mut u8,
    src: *const u8,
    len: usize,
) -> *mut u8 {
    let body = core::ptr::read_volatile(
        &(memcpy_forward_words as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8),
    );
    body(dst, src, len)
}

/// Veneer @ 0x08037dc8 -> IRAM 0x220002d4 = `memzero` (106 `bl`, 7 `b`).
///
/// # Safety
/// `dst` must be valid for `len` bytes. Any alignment is accepted; the body
/// carries its own byte prologue.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn iram_memzero_veneer(dst: *mut u8, len: usize) -> *mut u8 {
    let body =
        core::ptr::read_volatile(&(memzero as unsafe extern "C" fn(*mut u8, usize) -> *mut u8));
    body(dst, len)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| ((i as u16 * seed as u16 + 7) % 251) as u8).collect()
    }

    /// The veneer must be behaviorally transparent: same bytes written, same
    /// return value as calling the body directly. Word-aligned offsets only
    /// (the 0x22000188 body's precondition), lengths across the 32-byte block
    /// loop and every 16/8/4/tail leftover combination.
    #[test]
    fn memcpy_veneer_matches_body() {
        const SIZE: usize = 96;
        for dst_off in (0..16).step_by(4) {
            for src_off in (0..16).step_by(4) {
                for len in 0..=64usize {
                    let src = pattern(SIZE, 37);
                    let mut through_veneer = vec![0xAAu8; SIZE];
                    let mut direct = through_veneer.clone();
                    unsafe {
                        let v = iram_memcpy_veneer(
                            through_veneer.as_mut_ptr().add(dst_off),
                            src.as_ptr().add(src_off),
                            len,
                        );
                        let d = memcpy_forward_words(
                            direct.as_mut_ptr().add(dst_off),
                            src.as_ptr().add(src_off),
                            len,
                        );
                        assert_eq!(v, through_veneer.as_mut_ptr().add(dst_off + len));
                        assert_eq!(d, direct.as_mut_ptr().add(dst_off + len));
                    }
                    assert_eq!(
                        through_veneer, direct,
                        "dst_off={dst_off} src_off={src_off} len={len}"
                    );
                }
            }
        }
    }

    /// Zero-fill through the veneer, across all four `dst` alignments and
    /// lengths spanning the `len < 4` prologue, the alignment prologue and
    /// the 32-byte block loop.
    #[test]
    fn memzero_veneer_matches_body() {
        const SIZE: usize = 96;
        for dst_off in 0..8usize {
            for len in 0..=64usize {
                let mut through_veneer = pattern(SIZE, 13);
                let mut direct = through_veneer.clone();
                unsafe {
                    let v = iram_memzero_veneer(through_veneer.as_mut_ptr().add(dst_off), len);
                    let d = memzero(direct.as_mut_ptr().add(dst_off), len);
                    assert_eq!(v, through_veneer.as_mut_ptr().add(dst_off));
                    assert_eq!(d, direct.as_mut_ptr().add(dst_off));
                }
                assert_eq!(through_veneer, direct, "dst_off={dst_off} len={len}");
                assert!(
                    through_veneer[dst_off..dst_off + len].iter().all(|&b| b == 0),
                    "range not cleared: dst_off={dst_off} len={len}"
                );
            }
        }
    }

    /// Bytes outside the requested range stay untouched through either veneer.
    #[test]
    fn veneers_leave_surrounding_bytes_intact() {
        const SIZE: usize = 64;
        for len in [0usize, 1, 3, 4, 5, 16, 31, 32, 33] {
            let src = pattern(SIZE, 91);
            let mut buf = pattern(SIZE, 13);
            let before = buf.clone();
            unsafe {
                iram_memcpy_veneer(buf.as_mut_ptr().add(8), src.as_ptr().add(4), len);
            }
            assert_eq!(&buf[..8], &before[..8], "memcpy head, len={len}");
            assert_eq!(&buf[8 + len..], &before[8 + len..], "memcpy tail, len={len}");

            let mut buf = pattern(SIZE, 13);
            let before = buf.clone();
            unsafe {
                iram_memzero_veneer(buf.as_mut_ptr().add(5), len);
            }
            assert_eq!(&buf[..5], &before[..5], "memzero head, len={len}");
            assert_eq!(&buf[5 + len..], &before[5 + len..], "memzero tail, len={len}");
        }
    }

    /// The veneers must survive as distinct, callable symbols — the whole
    /// point is that a hook can branch to them from 0x08037df8 / 0x08037dc8.
    #[test]
    fn veneers_are_distinct_call_targets() {
        let (copy, clear) = unsafe {
            (
                core::ptr::read_volatile(&(iram_memcpy_veneer
                    as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8)),
                core::ptr::read_volatile(
                    &(iram_memzero_veneer as unsafe extern "C" fn(*mut u8, usize) -> *mut u8),
                ),
            )
        };
        assert_ne!(copy as usize, 0);
        assert_ne!(clear as usize, 0);
        assert_ne!(copy as usize, clear as usize);
    }
}
