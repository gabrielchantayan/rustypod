//! Unaligned big-endian u32 load @ 0x080743b8.
//!
//! The big-endian counterpart of the `le_read` family: rather than
//! gathering four bytes directly, the original delegates to
//! [`read_u32_le`] @ 0x080ed748 (the ADS `__packed` u32 reader) with a
//! real `bl` and then byte-reverses the result in registers —
//! `lsl r1, r0, #24`, `orr` of `r0 & 0xff00` shifted left 8, `orr` of
//! `r0 & 0xff0000` shifted right 8, `orr` of `r0 >> 24`.
//!
//! Behaviorally identical to `load_be32` @ 0x081f3b30/0x0837a158 and
//! `unpack_be32` @ 0x08261770 (both in `util/beload.rs`), but a distinct
//! firmware function from a different object file, so it keeps its own
//! address, symbol, and text section.
//!
//! Extent and call sites decoded from the raw words in osos.dec, not from
//! Ghidra: the function is 24 bytes (`push {lr}` … `pop {pc}` at
//! 0x080743d8), not the 36 Ghidra reports — the extra 12 bytes are the
//! separately-linked sibling @ 0x080743dc (`bl read_u64_le` + tail
//! branch, the 64-bit twin). 41 `bl` call sites, all unpredicated; the
//! recovered ones (0x0813xxxx, 0x08155xxx, 0x081c5xxx, 0x08202xxx) walk
//! packed big-endian record arrays with strides of 4, 8 and 0xc, one
//! field per call.
//!
//! [`read_u32_le`]: crate::util::le_read::read_u32_le

use crate::util::le_read::read_u32_le;

/// read_u32_be — original: `FUN_080743b8` @ 0x080743b8 (24 bytes;
/// 41 `bl` call sites, all unpredicated, counted by decoding every B/BL
/// word in osos.dec).
///
/// Unaligned big-endian u32 load: returns `p[0] << 24 | p[1] << 16 |
/// p[2] << 8 | p[3]`, needing no alignment.
///
/// The port keeps the original's two-step shape — call [`read_u32_le`],
/// then reverse in registers — because that is literally what the
/// firmware does. LLVM inlines the tiny callee anyway
/// (`codegen-units = 1`), so the shipped body is the four-byte gather
/// followed by the mask/shift reverse; the observable result is
/// unchanged. The dedicated text section stops LLVM from folding this
/// onto the equal-bodied [`load_be32`]/[`unpack_be32`] in `beload`.
///
/// [`read_u32_le`]: crate::util::le_read::read_u32_le
/// [`load_be32`]: crate::util::beload::load_be32
/// [`unpack_be32`]: crate::util::beload::unpack_be32
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.read_u32_be")]
#[inline(never)]
pub unsafe extern "C" fn read_u32_be(p: *const u8) -> u32 {
    read_u32_le(p).swap_bytes()
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

    /// Every offset in a patterned buffer, against `u32::from_be_bytes`.
    #[test]
    fn read_u32_be_matches_reference() {
        let buf = pattern(64, 53);
        for off in 0..=buf.len() - 4 {
            let want = u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
            assert_eq!(unsafe { read_u32_be(buf.as_ptr().add(off)) }, want, "off={off}");
        }
    }

    /// Extremes and single-lane values, placed at every alignment.
    #[test]
    fn interesting_values_at_every_alignment() {
        for value in [
            0x0000_0000u32,
            0xffff_ffff,
            0x0000_0001,
            0x8000_0000,
            0x0102_0304,
            0xdead_beef,
            0x00ff_00ff,
            0xff00_ff00,
        ] {
            for off in 0..4usize {
                let mut padded = vec![0xa5u8; 8];
                padded[off..off + 4].copy_from_slice(&value.to_be_bytes());
                assert_eq!(
                    unsafe { read_u32_be(padded.as_ptr().add(off)) },
                    value,
                    "{value:#010x} off={off}"
                );
            }
        }
    }

    /// The reader must not touch a byte outside its width — a violation
    /// would show up as a mismatch when the neighbours differ.
    #[test]
    fn reader_stays_within_its_width() {
        let mut buf = [0xffu8; 12];
        buf[4] = 0x44;
        buf[5] = 0x33;
        buf[6] = 0x22;
        buf[7] = 0x11;
        let p = unsafe { buf.as_ptr().add(4) };
        assert_eq!(unsafe { read_u32_be(p) }, 0x4433_2211);
    }
}
