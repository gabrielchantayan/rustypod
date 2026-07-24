//! Port of the retailOS fixed-size block byteswap, original:
//! `FUN_0802e94c` @ 0x0802e94c (844 bytes).
//!
//! The original is a fully unrolled, straight-line routine (no loop, no
//! length register): it converts exactly 256 bytes (64 words) from `src`
//! (r0) to `dst` (r1), in eight passes of eight words each — one `ldm` of
//! 8 words, the classic ARM byte-reverse idiom per word
//! (`eor t, w, w ror #16; and t, ~0xff00, t lsr #8; eor w, t, w ror #8`),
//! then one `stm` of 8 words. Each 32-bit word has its four bytes reversed
//! (identical to `u32::swap_bytes`); word order within the block is kept.
//! Used by the caller @ 0x080896b4 to endian-convert 256-byte resource
//! blocks (fonts/images) between distinct src/dst buffers.
//!
//! Simplifications / deviations from the original:
//! - There is no length parameter and no tail handling: the original always
//!   processes 256 bytes, so the Rust signature drops the suggested `len`.
//! - Both pointers must be word-aligned, exactly as the original's
//!   `ldm`/`stm` require (misaligned use is undefined on ARMv5 hardware).
//! - The per-pass load-8-then-store-8 structure is preserved, so in-place
//!   conversion (`src == dst`) behaves like the original; LLVM may schedule
//!   or vectorize the idiom differently than ADS 1.0.1 — that is expected.

/// Number of bytes converted by one call — fixed by the original.
pub const BLOCK_BYTESWAP_LEN: usize = 256;

const WORDS_PER_PASS: usize = 8;
const PASSES: usize = BLOCK_BYTESWAP_LEN / 4 / WORDS_PER_PASS;

/// block_byteswap — original: `FUN_0802e94c` @ 0x0802e94c (844 bytes).
///
/// Byte-reverses each of the 64 words of the 256-byte block at `src` into
/// `dst`. Register order matches the original: `src` in r0, `dst` in r1.
#[no_mangle]
pub unsafe extern "C" fn block_byteswap(src: *const u8, dst: *mut u8) {
    let mut s = src as *const u32;
    let mut d = dst as *mut u32;
    for _ in 0..PASSES {
        // One pass = one ldm of 8 words, byte-reverse each, one stm.
        let w0 = s.read();
        let w1 = s.add(1).read();
        let w2 = s.add(2).read();
        let w3 = s.add(3).read();
        let w4 = s.add(4).read();
        let w5 = s.add(5).read();
        let w6 = s.add(6).read();
        let w7 = s.add(7).read();
        d.write(w0.swap_bytes());
        d.add(1).write(w1.swap_bytes());
        d.add(2).write(w2.swap_bytes());
        d.add(3).write(w3.swap_bytes());
        d.add(4).write(w4.swap_bytes());
        d.add(5).write(w5.swap_bytes());
        d.add(6).write(w6.swap_bytes());
        d.add(7).write(w7.swap_bytes());
        s = s.add(WORDS_PER_PASS);
        d = d.add(WORDS_PER_PASS);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Reference derived directly from the original's idiom:
    /// `t = w ^ (w ror 16); t = ~0xff00 & (t >> 8); out = t ^ (w ror 8)`.
    fn idiom_word(w: u32) -> u32 {
        let t = w ^ w.rotate_right(16);
        let t = 0xffff_00ff & (t >> 8);
        t ^ w.rotate_right(8)
    }

    fn reference_block(src: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; src.len()];
        for (s, d) in src.chunks_exact(4).zip(dst.chunks_exact_mut(4)) {
            let w = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
            d.copy_from_slice(&idiom_word(w).to_le_bytes());
        }
        dst
    }

    fn pattern(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| ((i as u16 * seed as u16 + 0x5a) % 251) as u8).collect()
    }

    /// The idiom is exactly a per-word byte reversal.
    #[test]
    fn idiom_matches_swap_bytes() {
        let mut w: u32 = 0x0000_0001;
        for _ in 0..100_000 {
            assert_eq!(idiom_word(w), w.swap_bytes(), "w={w:#010x}");
            w = w.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        }
        for w in [0, 1, 0xff, 0xff00, 0xffff_00ff, 0xdead_beef, 0xffff_ffff, 0x0102_0304] {
            assert_eq!(idiom_word(w), w.swap_bytes(), "w={w:#010x}");
        }
    }

    /// Full 256-byte block, distinct buffers, word order preserved.
    #[test]
    fn transforms_fixed_256_byte_block() {
        let src = pattern(BLOCK_BYTESWAP_LEN, 37);
        let mut dst = vec![0xaau8; BLOCK_BYTESWAP_LEN + 8];
        unsafe { block_byteswap(src.as_ptr(), dst.as_mut_ptr()) };
        assert_eq!(&dst[..BLOCK_BYTESWAP_LEN], &reference_block(&src)[..]);
        // Nothing past the 256-byte block is touched.
        assert_eq!(&dst[BLOCK_BYTESWAP_LEN..], &[0xaa; 8]);
        // Spot-check: byte order reversed within each word, words in place.
        assert_eq!(&dst[0..4], &[src[3], src[2], src[1], src[0]]);
        assert_eq!(&dst[252..256], &[src[255], src[254], src[253], src[252]]);
    }

    /// dst and src at different (word-aligned) offsets in their buffers.
    #[test]
    fn independent_word_aligned_offsets() {
        for src_off in [0usize, 4, 8, 12] {
            for dst_off in [0usize, 4, 8, 12] {
                let src = pattern(BLOCK_BYTESWAP_LEN + 16, 91);
                let mut dst = pattern(BLOCK_BYTESWAP_LEN + 16, 13);
                let before = dst.clone();
                unsafe {
                    block_byteswap(src.as_ptr().add(src_off), dst.as_mut_ptr().add(dst_off))
                };
                let expected = reference_block(&src[src_off..src_off + BLOCK_BYTESWAP_LEN]);
                assert_eq!(
                    &dst[dst_off..dst_off + BLOCK_BYTESWAP_LEN],
                    &expected[..],
                    "src_off={src_off} dst_off={dst_off}"
                );
                // Surroundings untouched.
                assert_eq!(&dst[..dst_off], &before[..dst_off]);
                assert_eq!(
                    &dst[dst_off + BLOCK_BYTESWAP_LEN..],
                    &before[dst_off + BLOCK_BYTESWAP_LEN..]
                );
            }
        }
    }

    /// In-place conversion (src == dst): loads precede stores per 32-byte
    /// pass, exactly like the original's ldm/stm pairing.
    #[test]
    fn in_place() {
        let orig = pattern(BLOCK_BYTESWAP_LEN, 53);
        let mut buf = orig.clone();
        unsafe { block_byteswap(buf.as_ptr(), buf.as_mut_ptr()) };
        assert_eq!(buf, reference_block(&orig));
    }

    /// Byte reversal is an involution: converting twice restores the input.
    #[test]
    fn involution() {
        let orig = pattern(BLOCK_BYTESWAP_LEN, 77);
        let mut tmp = vec![0u8; BLOCK_BYTESWAP_LEN];
        let mut back = vec![0u8; BLOCK_BYTESWAP_LEN];
        unsafe {
            block_byteswap(orig.as_ptr(), tmp.as_mut_ptr());
            block_byteswap(tmp.as_ptr(), back.as_mut_ptr());
        }
        assert_eq!(back, orig);
    }
}
