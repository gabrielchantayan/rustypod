//! Big-endian record field readers — the accessor cluster
//! @ 0x0813b714..0x0813b7b0.
//!
//! All five take a *record handle*: a pointer whose first word is the base
//! address of a raw byte buffer (callers pass `&local` where `local` holds
//! the buffer pointer — see e.g. the parser @ 0x080fbf44, which reads flag
//! bits and enum fields out of a binary record via this family). Each
//! reader dereferences the handle, applies a byte offset, and decodes a
//! big-endian / bit-level field. Pure leaf functions, no globals.
//!
//! Originals (sizes from decomp/functions.csv; call-site counts from
//! scanning osos.dec for `bl` words, not osos.asm, which drops lines):
//!
//! - `berec_test_bit` — `FUN_0813b714` @ 0x0813b714 (24 bytes; 17 call
//!   sites). `ands` of the byte at `offset` against `1 << bit`, normalized
//!   to 0/1 by `movne`.
//! - `berec_extract_bits` — `FUN_0813b72c` @ 0x0813b72c (32 bytes; 8 call
//!   sites). `(byte >> shift) & ((1 << width) - 1)` — a bit-field pulled
//!   out of one byte.
//! - `berec_read_u16` — `FUN_0813b74c` @ 0x0813b74c (24 bytes; 5 call
//!   sites). Big-endian 16-bit load, byte at `offset` is the high byte.
//! - `berec_read_u24` — `FUN_0813b764` @ 0x0813b764 (36 bytes; 3 call
//!   sites). Big-endian 24-bit load.
//! - `berec_read_u32` — `FUN_0813b788` @ 0x0813b788 (44 bytes; 4 call
//!   sites). Big-endian 32-bit load.
//!
//! Shift semantics: the originals shift by a *register* (`lsl r1, r1, r3`
//! / `lsr r0, r0, r2`), so ARM's register-shift rules apply — only the
//! bottom 8 bits of the amount count, and amounts 32..=255 produce 0.
//! Ghidra renders this as `& 0xff` on the amounts. `arm_lsl`/`arm_lsr`
//! below replicate those rules exactly so out-of-range `bit`/`shift`/
//! `width` arguments behave bit-for-bit like the hardware.

/// ARM `lsl` by register: amount is the bottom byte; 32..=255 yields 0.
/// Shared with util/table_find.rs, whose original builds its mask the
/// same way.
#[inline]
pub(crate) fn arm_lsl(value: u32, amount: u32) -> u32 {
    let amount = amount & 0xff;
    if amount >= 32 { 0 } else { value << amount }
}

/// ARM `lsr` by register: amount is the bottom byte; 32..=255 yields 0.
/// Shared with util/bitfield.rs, whose original shifts the word the same way.
#[inline]
pub(crate) fn arm_lsr(value: u32, amount: u32) -> u32 {
    let amount = amount & 0xff;
    if amount >= 32 { 0 } else { value >> amount }
}

/// berec_test_bit — original: `FUN_0813b714` @ 0x0813b714 (24 bytes).
///
/// Returns 1 if bit `bit` of the byte at `offset` in the record's buffer
/// is set, else 0 (`bit` >= 32 always reads as 0 — ARM register-shift).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn berec_test_bit(rec: *const *const u8, offset: isize, bit: u32) -> u32 {
    let byte = (*rec).offset(offset).read() as u32;
    u32::from(byte & arm_lsl(1, bit) != 0)
}

/// berec_extract_bits — original: `FUN_0813b72c` @ 0x0813b72c (32 bytes).
///
/// Returns the `width`-bit field starting at bit `shift` of the byte at
/// `offset`: `(byte >> shift) & ((1 << width) - 1)`. `width` >= 32 makes
/// the mask all-ones (`(0 - 1)` wraps), exactly as the original's
/// `sub r1, r1, #1` does.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn berec_extract_bits(
    rec: *const *const u8,
    offset: isize,
    shift: u32,
    width: u32,
) -> u32 {
    let byte = (*rec).offset(offset).read() as u32;
    arm_lsr(byte, shift) & arm_lsl(1, width).wrapping_sub(1)
}

/// berec_read_u16 — original: `FUN_0813b74c` @ 0x0813b74c (24 bytes).
///
/// Big-endian 16-bit read at `offset` (byte at `offset` is the high byte).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn berec_read_u16(rec: *const *const u8, offset: isize) -> u32 {
    let p = (*rec).offset(offset);
    (p.read() as u32) << 8 | p.add(1).read() as u32
}

/// berec_read_u24 — original: `FUN_0813b764` @ 0x0813b764 (36 bytes).
///
/// Big-endian 24-bit read at `offset`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn berec_read_u24(rec: *const *const u8, offset: isize) -> u32 {
    let p = (*rec).offset(offset);
    (p.read() as u32) << 16 | (p.add(1).read() as u32) << 8 | p.add(2).read() as u32
}

/// berec_read_u32 — original: `FUN_0813b788` @ 0x0813b788 (44 bytes).
///
/// Big-endian 32-bit read at `offset`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn berec_read_u32(rec: *const *const u8, offset: isize) -> u32 {
    let p = (*rec).offset(offset);
    (p.read() as u32) << 24
        | (p.add(1).read() as u32) << 16
        | (p.add(2).read() as u32) << 8
        | p.add(3).read() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record handle over a stack buffer, offset into it.
    fn handle(buf: &[u8]) -> *const u8 {
        buf.as_ptr()
    }

    const BUF: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0b1010_0101, 0xff, 0x00, 0x80];

    #[test]
    fn test_bit_reads_each_bit_of_the_flag_byte() {
        let base = handle(&BUF);
        // Byte at offset 4 is 0b1010_0101.
        for (bit, expect) in [(0, 1), (1, 0), (2, 1), (3, 0), (4, 0), (5, 1), (6, 0), (7, 1)] {
            let got = unsafe { berec_test_bit(&base, 4, bit) };
            assert_eq!(got, expect, "bit {bit}");
        }
    }

    #[test]
    fn test_bit_bits_8_to_31_test_high_zero_bits_of_the_byte() {
        let base = handle(&BUF);
        // The byte is zero-extended to 32 bits, so bits 8..=31 are 0.
        assert_eq!(unsafe { berec_test_bit(&base, 5, 8) }, 0);
        assert_eq!(unsafe { berec_test_bit(&base, 5, 31) }, 0);
    }

    #[test]
    fn test_bit_arm_register_shift_semantics_for_large_bit_numbers() {
        let base = handle(&BUF);
        // Amounts 32..=255: lsl yields 0, so the test always fails.
        assert_eq!(unsafe { berec_test_bit(&base, 5, 32) }, 0);
        assert_eq!(unsafe { berec_test_bit(&base, 5, 255) }, 0);
        // Amount 256 wraps to 0 (bottom byte): tests bit 0. 0xff has it set.
        assert_eq!(unsafe { berec_test_bit(&base, 5, 256) }, 1);
    }

    #[test]
    fn extract_bits_pulls_bit_fields_out_of_one_byte() {
        let base = handle(&BUF);
        // Byte at offset 4 is 0b1010_0101.
        assert_eq!(unsafe { berec_extract_bits(&base, 4, 0, 4) }, 0b0101);
        assert_eq!(unsafe { berec_extract_bits(&base, 4, 4, 4) }, 0b1010);
        assert_eq!(unsafe { berec_extract_bits(&base, 4, 2, 3) }, 0b001);
        assert_eq!(unsafe { berec_extract_bits(&base, 4, 0, 8) }, 0xa5);
    }

    #[test]
    fn extract_bits_width_zero_masks_everything_off() {
        let base = handle(&BUF);
        assert_eq!(unsafe { berec_extract_bits(&base, 5, 0, 0) }, 0);
    }

    #[test]
    fn extract_bits_width_32_and_up_means_all_ones_mask() {
        let base = handle(&BUF);
        // (1 lsl 32) - 1 wraps to 0xffff_ffff — the whole shifted byte.
        assert_eq!(unsafe { berec_extract_bits(&base, 5, 4, 32) }, 0x0f);
        assert_eq!(unsafe { berec_extract_bits(&base, 5, 0, 200) }, 0xff);
    }

    #[test]
    fn read_u16_is_big_endian() {
        let base = handle(&BUF);
        assert_eq!(unsafe { berec_read_u16(&base, 0) }, 0x1234);
        assert_eq!(unsafe { berec_read_u16(&base, 1) }, 0x3456);
        assert_eq!(unsafe { berec_read_u16(&base, 6) }, 0x0080);
    }

    #[test]
    fn read_u24_is_big_endian() {
        let base = handle(&BUF);
        assert_eq!(unsafe { berec_read_u24(&base, 0) }, 0x123456);
        assert_eq!(unsafe { berec_read_u24(&base, 1) }, 0x345678);
        assert_eq!(unsafe { berec_read_u24(&base, 5) }, 0xff0080);
    }

    #[test]
    fn read_u32_is_big_endian() {
        let base = handle(&BUF);
        assert_eq!(unsafe { berec_read_u32(&base, 0) }, 0x12345678);
        assert_eq!(unsafe { berec_read_u32(&base, 3) }, 0x78a5ff00);
        assert_eq!(unsafe { berec_read_u32(&base, 4) }, 0xa5ff0080);
    }

    #[test]
    fn readers_match_reference_on_every_offset_of_a_pattern_buffer() {
        let buf: [u8; 36] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let base = handle(&buf);
        for off in 0..32isize {
            let o = off as usize;
            let be32 = u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
            assert_eq!(unsafe { berec_read_u32(&base, off) }, be32, "u32 off={off}");
            assert_eq!(unsafe { berec_read_u16(&base, off) }, be32 >> 16, "u16 off={off}");
            assert_eq!(unsafe { berec_read_u24(&base, off) }, be32 >> 8, "u24 off={off}");
            for bit in 0..8 {
                assert_eq!(
                    unsafe { berec_test_bit(&base, off, bit) },
                    u32::from(buf[o] >> bit & 1 != 0),
                    "bit off={off} bit={bit}"
                );
            }
        }
    }
}
