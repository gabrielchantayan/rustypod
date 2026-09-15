//! Expansion of two 32-bit values into two zero-extended 64-bit values.

/// expand_u32_pair_to_u64_pair — retailOS `FUN_08158cb0` @ 0x08158cb0
/// (64 bytes, 0x08158cb0..0x08158cf0; five inbound unconditional `bl` call
/// sites, no predicated `bl` forms).
///
/// Loads the first input word, writes it and a zero high word to `output`,
/// then loads the second input word and writes it and a zero high word to the
/// next two output words. The output therefore contains two little-endian,
/// zero-extended `u64` values. The second input load deliberately follows the
/// first output pair stores, preserving the original aliasing behavior.
///
/// RetailOS invokes the eight-byte `FUN_081b4e10` copy helper twice. This port
/// performs the equivalent ordered word stores directly rather than creating
/// a seam for that otherwise-unported helper. Volatile accesses retain the
/// load/store order against LLVM optimization. Deliberate deviations: the
/// helper calls are inlined; observable memory behavior and returned pointer
/// are unchanged.
///
/// # Safety
/// `output` must be valid for four aligned `u32` writes; `first` and `second`
/// must each be valid for an aligned `u32` read when reached. They may alias
/// `output`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.expand_u32_pair_to_u64_pair")]
#[inline(never)]
pub unsafe extern "C" fn expand_u32_pair_to_u64_pair(
    output: *mut u32,
    first: *const u32,
    second: *const u32,
) -> *mut u32 {
    output.write_volatile(first.read_volatile());
    output.add(1).write_volatile(0);
    output.add(2).write_volatile(second.read_volatile());
    output.add(3).write_volatile(0);
    output
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::expand_u32_pair_to_u64_pair;

    #[test]
    fn expands_full_width_input_words() {
        let first = 0x89ab_cdef;
        let second = 0x0123_4567;
        let mut output = [u32::MAX; 4];

        let returned = unsafe {
            expand_u32_pair_to_u64_pair(output.as_mut_ptr(), &first, &second)
        };

        assert_eq!(returned, output.as_mut_ptr());
        assert_eq!(output, [first, 0, second, 0]);
    }

    #[test]
    fn reads_second_input_after_writing_first_output_pair() {
        let first = 0xfeed_face;
        let mut words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444];
        let output = words.as_mut_ptr();
        let second = output.cast_const();

        unsafe {
            expand_u32_pair_to_u64_pair(output, &first, second);
        }

        assert_eq!(words, [first, 0, first, 0]);
    }
}
