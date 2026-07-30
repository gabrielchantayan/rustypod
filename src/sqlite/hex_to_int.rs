//! Converting one ASCII hex digit to its 4-bit value — the per-nibble
//! helper the blob-literal parser runs on each character of an
//! `x'ABCD'` literal.
//!
//! - `hex_to_int` — original: `FUN_082d2ba0` @ 0x082d2ba0 (24 bytes;
//!   called from hexToBlob @ 0x0837b00c twice, once per nibble of each
//!   output byte). SQLite 3.5.x's `sqlite3HexToInt` (util.c), the
//!   `SQLITE_ASCII` build.
//!
//! Algorithm: a branchless ASCII-decode trick. Bit 6 of the character
//! separates the digit band (`'0'..'9'` = 0x30..0x39, bit 6 clear) from
//! the letter bands (`'A'..'F'` = 0x41..0x46 and `'a'..'f'` = 0x61..0x66,
//! bit 6 set). Letters sit 7 past their value with the low nibble 9
//! short, so adding 9 when bit 6 is set lands every band's low nibble on
//! the digit's value; masking with 0xf keeps exactly that nibble:
//!
//! ```text
//! 082d2ba0:  mov r1,r0, lsl #0x19   ; r1 = h << 25  (bit 6 -> bit 31)
//! 082d2ba4:  mov r1,r1, lsr #0x1f   ; r1 = (h >> 6) & 1
//! 082d2ba8:  add r1,r1,r1, lsl #0x3 ; r1 = r1 * 9
//! 082d2bac:  add r0,r1,r0           ; r0 = h + 9*((h >> 6) & 1)
//! 082d2bb0:  and r0,r0,#0xf         ; r0 &= 0xf
//! 082d2bb4:  bx  lr
//! ```
//!
//! i.e. `return (h + 9*(1 & (h>>6))) & 0xf;` — character-for-character
//! the SQLite 3.5.x source `h += 9*(1&(h>>6)); return (u8)(h & 0xf);`
//! (the original returns a full register, so the `(u8)` truncation is
//! just the mask). The caller at 0x0837b00c confirms the reading: it
//! shifts this result by 4 for the high nibble and ORs in the low
//! nibble, packing a hex string into bytes.
//!
//! Register usage: r0 = h (in) / nibble value (out); r1 = scratch.
//!
//! Deviations: none beyond typing — the parameter and result are `u32`
//! (the original's register contract; callers pass a zero-extended
//! `ldrb` byte and use the low nibble of the result).

/// hex_to_int — original: `FUN_082d2ba0` @ 0x082d2ba0 (24 bytes).
///
/// `sqlite3HexToInt`: map one ASCII hex digit to its 4-bit value by
/// adding 9 when bit 6 is set (the letter bands `'A'..'F'`/`'a'..'f'`)
/// and masking to the low nibble. Behavior on non-hex input is whatever
/// the bit formula yields — the original validates nothing, and neither
/// do we.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn hex_to_int(h: u32) -> u32 {
    // Original: h + 9*((h >> 6) & 1), masked to a nibble. The *9 is a
    // shift-add (`add r1,r1,r1, lsl #0x3`) in the original.
    h.wrapping_add(((h >> 6) & 1).wrapping_mul(9)) & 0xf
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// The exact instruction sequence of the original, written as a
    /// literal reference implementation: bit 6 extracted by shifting it
    /// up to bit 31 and back down, scaled by 9 via shift-add, added,
    /// masked.
    fn reference(h: u32) -> u32 {
        let bit6 = (h << 25) >> 31;
        let nine_x = bit6.wrapping_add(bit6 << 3);
        h.wrapping_add(nine_x) & 0xf
    }

    #[test]
    fn decimal_digits_decode_to_their_value() {
        for d in 0u32..10 {
            assert_eq!(hex_to_int(b'0' as u32 + d), d, "'{}'", (b'0' + d as u8) as char);
        }
    }

    #[test]
    fn uppercase_letters_decode_to_ten_through_fifteen() {
        for (i, c) in (b'A'..=b'F').enumerate() {
            assert_eq!(hex_to_int(c as u32), 10 + i as u32, "'{}'", c as char);
        }
    }

    #[test]
    fn lowercase_letters_decode_to_ten_through_fifteen() {
        for (i, c) in (b'a'..=b'f').enumerate() {
            assert_eq!(hex_to_int(c as u32), 10 + i as u32, "'{}'", c as char);
        }
    }

    #[test]
    fn bit6_selects_the_plus_nine_correction() {
        // The whole decode is the bit-6 test: same low nibble, both
        // bands, e.g. 0x37 ('7') vs 0x47 ('G') vs 0x67 ('g').
        assert_eq!(hex_to_int(0x37), 7, "bit 6 clear: no +9");
        assert_eq!(hex_to_int(0x47), (0x47 + 9) & 0xf, "bit 6 set: +9");
        assert_eq!(hex_to_int(0x67), (0x67 + 9) & 0xf, "bit 6 set: +9");
    }

    #[test]
    fn result_is_always_a_single_nibble() {
        // Whatever garbage the caller feeds in (the original validates
        // nothing), the `and r0,r0,#0xf` guarantees a 4-bit result —
        // the caller shifts it by 4 without further masking.
        for h in 0u32..=0xff {
            assert!(hex_to_int(h) <= 0xf, "h = {h:#04x}");
        }
        assert!(hex_to_int(u32::MAX) <= 0xf, "mask survives full-width input");
    }

    #[test]
    fn matches_the_reference_formula_everywhere() {
        // Every caller-visible byte value, plus full-width words around
        // the carry points of the +9 (wrapping) add.
        for h in 0u32..=0xff {
            assert_eq!(hex_to_int(h), reference(h), "h = {h:#04x}");
        }
        for h in [u32::MAX, u32::MAX - 8, 0xffff_ffc0, 0x8000_0041, 0x0000_0046] {
            assert_eq!(hex_to_int(h), reference(h), "h = {h:#010x}");
        }
    }

    #[test]
    fn packs_x_literals_as_hex_to_blob_does() {
        // End-to-end over the caller's pattern (0x0837b00c: high nibble
        // shifted by 4, low nibble OR'd in): "x'1fA0'" -> [0x1f, 0xa0].
        let hex = *b"1fA0";
        let mut blob = [0u8; 2];
        for (i, byte) in blob.iter_mut().enumerate() {
            let hi = hex_to_int(hex[2 * i] as u32);
            let lo = hex_to_int(hex[2 * i + 1] as u32);
            *byte = (lo | (hi << 4)) as u8;
        }
        assert_eq!(blob, [0x1f, 0xa0]);
    }
}
