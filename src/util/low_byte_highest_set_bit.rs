//! Highest set-bit index of the low byte of a word.
//!
//! Original: `FUN_080903ac` at load address 0x080903ac, true size 52 bytes
//! ([0x080903ac, 0x080903e0)). Raw A32 ends with `bx lr` at 0x080903dc;
//! 0x080903e0 is a separate empty return leaf, followed by a zero-return
//! leaf at 0x080903e4. Verified two incoming plain BLs (0x080ce108 and
//! 0x080ce124), zero predicated incoming BLs, and zero outgoing BLs.
//!
//! Scan masks 0x80 down to 1, returning the first matching index 7..0.
//! If no low-byte bit is set, the final decrement wraps the halfword
//! index to 0xffff. Upper input bits are ignored. Both callers pass a
//! halfword and consume the full zero-extended r0, not a signed short.
//! Deliberate deviations: none; preserve the scan and halfword wrapping.

/// Return 0..7 for a nonempty low byte, otherwise the word value 65535.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn low_byte_highest_set_bit(value: u32) -> u32 {
    let mut index = 7u16;
    let mut mask = 0x80u32;
    loop {
        if value & mask != 0 || mask == 0 {
            return u32::from(index);
        }
        index = index.wrapping_sub(1);
        mask >>= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::low_byte_highest_set_bit;

    fn reference(value: u32) -> u32 {
        let byte = value & 0xff;
        if byte == 0 { 65535 } else { 31 - byte.leading_zeros() }
    }

    #[test]
    fn every_halfword_matches_low_byte_reference() {
        for value in 0..=65535 {
            assert_eq!(low_byte_highest_set_bit(value), reference(value), "value={value:#x}");
        }
    }

    #[test]
    fn upper_word_bits_never_affect_the_result() {
        for upper in [0x0001_0000, 0x8000_0000, 0xffff_ff00, 0x5555_5500, 0xaaaa_aa00] {
            for byte in 0..=255 {
                let value = upper | byte;
                assert_eq!(low_byte_highest_set_bit(value), reference(value), "value={value:#x}");
            }
        }
        assert_eq!(low_byte_highest_set_bit(0), 65535);
        assert_eq!(low_byte_highest_set_bit(0x100), 65535);
        assert_eq!(low_byte_highest_set_bit(u32::MAX), 7);
    }
}
