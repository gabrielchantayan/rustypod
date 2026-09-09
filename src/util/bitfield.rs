//! Packed-word bitfield extractor — `FUN_082728a8` @ 0x082728a8 (36
//! bytes; 32 `bl` call sites, binary-scanned: all unconditional, all from
//! the packed-config decoder `FUN_08188b8c` @ 0x08188b8c, which pulls 32
//! two-bit fields out of the words at 0x38400044 / 0x38400048 into a
//! byte struct).
//!
//! The argument convention matches the berec family: callers pass a
//! *handle* — `&local` where `local` holds the word's address — so the
//! word is reached by two loads (`ldr r0, [r0]` twice). The field is
//! `(word >> lo) & ((1 << (hi - lo + 1)) - 1)`:
//!
//! ```text
//! sub r1, r1, r2          @ width-1 = hi - lo
//! ldr r0, [r0]            @ handle -> word address
//! add r1, r1, #1
//! mov r3, #1
//! ldr r0, [r0]            @ the word itself
//! lsl r1, r3, r1          @ 1 << width   (ARM register shift)
//! sub r1, r1, #1          @ mask
//! and r0, r1, r0, lsr r2  @ (word >> lo) & mask
//! bx  lr
//! ```
//!
//! Both shifts are by register, so ARM register-shift rules apply (only
//! the bottom 8 bits of the amount count; 32..=255 yields 0), replicated
//! via `berec::arm_lsl`/`arm_lsr`. Consequences: `hi - lo + 1 == 32`
//! makes the mask all-ones (`0 - 1` wraps), and `lo >= 32` always
//! returns 0. The width byte is `(hi - lo + 1) & 0xff`, so `hi < lo`
//! yields width 0 mod 256 only when `hi == lo - 1` (mask 0).
//!
//! Sibling `bitfield_test` (`FUN_0827288c` @ 0x0827288c, 28 bytes;
//! 17 `bl` call sites, binary-scanned: all unconditional, all from the
//! same packed-config decoder) reduces the same handle convention to a
//! single-bit test (`ands` + `movne`), ported below. Its shift is by
//! register too, so bit indices 32..=255 return 0 and 256 wraps to
//! bit 0.

use super::berec::{arm_lsl, arm_lsr};

/// bitfield_extract — original: `FUN_082728a8` @ 0x082728a8 (36 bytes).
///
/// Returns the `hi..=lo` bit field of the word behind `word_handle`:
/// `(**word_handle >> lo) & ((1 << (hi - lo + 1)) - 1)`, with ARM
/// register-shift semantics on both shift amounts.
///
/// # Safety
///
/// `word_handle` must point to a readable word pointer, which in turn
/// must point to a readable word. The original performs both loads
/// unchecked; this port adds no NULL or validity guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bitfield_extract(
    word_handle: *const *const u32,
    hi: u32,
    lo: u32,
) -> u32 {
    let word = **word_handle;
    arm_lsr(word, lo) & arm_lsl(1, hi.wrapping_sub(lo).wrapping_add(1)).wrapping_sub(1)
}

/// bitfield_test — original: `FUN_0827288c` @ 0x0827288c (28 bytes; 17
/// `bl` call sites, binary-scanned: all unconditional, all from the
/// packed-config decoder `FUN_08188b8c` @ 0x08188b8c, which stores each
/// result byte into the same struct `bitfield_extract` fills).
///
/// Tests a single bit of the word behind `word_handle`, returning 1 or
/// 0. Original instructions:
///
/// ```text
/// ldr   r0, [r0]          @ handle -> word address
/// mov   r2, #1
/// ldr   r0, [r0]          @ the word itself
/// mov   r1, r2, lsl r1    @ mask = 1 << bit  (ARM register shift)
/// ands  r0, r0, r1        @ word & mask, flags
/// movne r0, #1
/// bx    lr
/// ```
///
/// The shift is by register, so ARM rules apply to the bit index: only
/// the bottom 8 bits count and amounts 32..=255 shift the 1 completely
/// out, yielding mask 0 (returns 0). Replicated via `berec::arm_lsl`.
/// Consequences: `bit >= 256` wraps to `bit & 0xff`, so e.g. bit 256
/// tests bit 0.
///
/// The mask is ANDed into r0 by `ands` and then normalised to 0/1 by
/// the predicated `movne`; returning a C bool is exact.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `word_handle` must point to a readable word pointer, which in turn
/// must point to a readable word. The original performs both loads
/// unchecked; this port adds no NULL or validity guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bitfield_test(word_handle: *const *const u32, bit: u32) -> u32 {
    u32::from(**word_handle & arm_lsl(1, bit) != 0)
}

#[cfg(test)]
mod test_tests {
    use super::*;

    /// Runs the test through a stack handle, exactly like the firmware
    /// callers (`&local`, local holds the address).
    unsafe fn test_bit(word: u32, bit: u32) -> u32 {
        let addr: *const u32 = &word;
        bitfield_test(&addr, bit)
    }

    #[test]
    fn every_bit_of_a_known_pattern() {
        let word = 0b10_01_11_00_10_01_11_00_10_01_11_00_10_01_11_00u32;
        for bit in 0..32 {
            let expect = (word >> bit) & 1;
            assert_eq!(unsafe { test_bit(word, bit) }, expect, "bit {bit}");
        }
    }

    #[test]
    fn returns_exactly_zero_or_one() {
        // The ands/movne pair normalises to 0/1 even when the mask is
        // the sign bit.
        assert_eq!(unsafe { test_bit(0x8000_0000, 31) }, 1);
        assert_eq!(unsafe { test_bit(0x7fff_ffff, 31) }, 0);
        assert_eq!(unsafe { test_bit(1, 0) }, 1);
        assert_eq!(unsafe { test_bit(0xffff_fffe, 0) }, 0);
    }

    #[test]
    fn caller_pattern_single_bits_into_byte_struct() {
        // Real call sites pass a bare bit index (19, 18, 13, 12, 9,
        // 6, 3, 0...) and store the byte result; reproduce a few.
        let word = 0x000c_0249u32;
        for bit in [19u32, 18, 13, 12, 9, 6, 3, 0] {
            let expect = (word >> bit) & 1;
            assert_eq!(unsafe { test_bit(word, bit) }, expect, "bit {bit}");
        }
    }

    #[test]
    fn bit_index_32_to_255_reads_zero() {
        // ARM register shift: amounts 32..=255 push the 1 out -> mask 0.
        for bit in [32u32, 33, 63, 100, 255] {
            assert_eq!(unsafe { test_bit(0xffff_ffff, bit) }, 0, "bit {bit}");
        }
    }

    #[test]
    fn bit_index_wraps_mod_256() {
        // Only the bottom 8 bits of the amount count: bit 256 tests
        // bit 0, bit 257 tests bit 1.
        assert_eq!(unsafe { test_bit(1, 256) }, 1);
        assert_eq!(unsafe { test_bit(0xffff_fffe, 256) }, 0);
        assert_eq!(unsafe { test_bit(2, 257) }, 1);
        assert_eq!(unsafe { test_bit(0x8000_0000, 287) }, 1);
    }

    #[test]
    fn matches_naive_reference_for_sane_bits_on_patterns() {
        let patterns = [0u32, !0u32, 0xaaaa_5555, 0x0123_4567, 0x89ab_cdef];
        for &word in &patterns {
            for bit in 0..32 {
                assert_eq!(unsafe { test_bit(word, bit) }, (word >> bit) & 1, "{word:#x}[{bit}]");
            }
        }
    }
}

#[cfg(test)]
mod extract_tests {
    use super::*;

    /// Runs the extractor against `word` through a stack handle, exactly
    /// like the firmware callers (`&local`, local holds the address).
    unsafe fn extract(word: u32, hi: u32, lo: u32) -> u32 {
        let addr: *const u32 = &word;
        bitfield_extract(&addr, hi, lo)
    }

    #[test]
    fn extracts_two_bit_fields_like_the_config_decoder() {
        // All 32 real call sites pull 2-bit fields; walk every aligned
        // pair of a known pattern.
        let word = 0b10_01_11_00_10_01_11_00_10_01_11_00_10_01_11_00u32;
        for pair in 0..16 {
            let lo = pair * 2;
            let expect = (word >> lo) & 0b11;
            assert_eq!(unsafe { extract(word, lo + 1, lo) }, expect, "pair {pair}");
        }
    }

    #[test]
    fn full_width_field_returns_the_whole_word() {
        // hi=31, lo=0: width 32, ARM lsl yields 0, sub #1 wraps to all-ones.
        assert_eq!(unsafe { extract(0xdead_beef, 31, 0) }, 0xdead_beef);
        assert_eq!(unsafe { extract(0, 31, 0) }, 0);
    }

    #[test]
    fn low_bit_of_a_shifted_field() {
        assert_eq!(unsafe { extract(0x1234_5678, 7, 4) }, 0x7);
        assert_eq!(unsafe { extract(0x1234_5678, 15, 8) }, 0x56);
        assert_eq!(unsafe { extract(0x1234_5678, 31, 28) }, 0x1);
    }

    #[test]
    fn single_bit_fields() {
        assert_eq!(unsafe { extract(0x8000_0001, 0, 0) }, 1);
        assert_eq!(unsafe { extract(0x8000_0001, 31, 31) }, 1);
        assert_eq!(unsafe { extract(0x8000_0001, 30, 30) }, 0);
    }

    #[test]
    fn hi_below_lo_masks_everything_off() {
        // hi = lo - 1 -> width byte 0 -> mask 0.
        assert_eq!(unsafe { extract(0xffff_ffff, 0, 1) }, 0);
        assert_eq!(unsafe { extract(0xffff_ffff, 10, 11) }, 0);
    }

    #[test]
    fn lo_at_or_above_32_reads_zero() {
        // ARM lsr by register: amounts 32..=255 produce 0.
        assert_eq!(unsafe { extract(0xffff_ffff, 31, 32) }, 0);
        assert_eq!(unsafe { extract(0xffff_ffff, 20, 40) }, 0);
    }

    #[test]
    fn width_past_32_via_high_hi_is_all_ones_mask() {
        // hi=33, lo=2 -> width byte 32 -> all-ones mask over (word >> 2).
        assert_eq!(unsafe { extract(0xabcd_1234, 33, 2) }, 0xabcd_1234 >> 2);
    }

    #[test]
    fn matches_naive_reference_for_sane_fields_on_patterns() {
        // Reference with C-like semantics, valid for 0 <= lo <= hi < 32.
        let patterns = [0u32, !0u32, 0xaaaa_5555, 0x0123_4567, 0x89ab_cdef];
        for &word in &patterns {
            for hi in 0..32 {
                for lo in 0..=hi {
                    let width = hi - lo + 1;
                    let expect = if width >= 32 {
                        word >> lo
                    } else {
                        (word >> lo) & ((1u32 << width) - 1)
                    };
                    assert_eq!(unsafe { extract(word, hi, lo) }, expect, "{word:#x}[{hi}:{lo}]");
                }
            }
        }
    }
}
