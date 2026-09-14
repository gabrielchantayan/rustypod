//! Big-endian-word bit-index conversion.

/// big_endian_word_bit_index — original: `FUN_0836b698` @ 0x0836b698
/// (**32 bytes exactly**, eight ARM words from `lsl r2,r0,#27` through `bx lr`;
/// the separately linked sibling begins at 0x0836b6b8). Raw decoding finds five
/// inbound direct calls, all unconditional `bl` at 0x080643a0, 0x0836b588,
/// 0x0836b60c, 0x0836b648, and 0x0836b710; no predicated `bl` or direct tail
/// `b` callers exist.
///
/// Converts the low five bits of a logical bit index into the bit position in
/// a big-endian 32-bit word held by this little-endian CPU: it preserves the
/// bit within its byte and reverses the four byte positions. The firmware
/// stores that result through `out_bit_index` and returns zero. Deviations:
/// none.
///
/// # Safety
/// `out_bit_index` must be valid and aligned for one writable `u32`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.big_endian_word_bit_index")]
#[inline(never)]
pub unsafe extern "C" fn big_endian_word_bit_index(
    bit_index: u32,
    out_bit_index: *mut u32,
) -> u32 {
    let byte_index = (bit_index & 0x1f) >> 3;
    let bit_in_byte = bit_index & 7;
    out_bit_index.write(((3 - byte_index) << 3) + bit_in_byte);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::big_endian_word_bit_index;

    #[test]
    fn reverses_byte_positions_without_changing_bits_inside_them() {
        let mut result = u32::MAX;

        for (input, expected) in [
            (0, 24), (7, 31), (8, 16), (15, 23), (16, 8), (23, 15), (24, 0), (31, 7),
        ] {
            let status = unsafe { big_endian_word_bit_index(input, &mut result) };
            assert_eq!(status, 0, "the firmware always returns success");
            assert_eq!(result, expected, "input bit {input}");
        }
    }

    #[test]
    fn uses_only_the_low_five_bits_of_the_input_index() {
        let mut result = 0;

        unsafe { big_endian_word_bit_index(0xffff_fffd, &mut result) };

        assert_eq!(result, 5, "index 29 maps to byte zero, bit five");
    }
}
