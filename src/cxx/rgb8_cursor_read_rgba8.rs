//! `rgb8_cursor_read_rgba8` — original: `FUN_082605ac` @ `0x082605ac` (68
//! bytes; **3 unconditional `bl` call sites** at `0x0825e698`, `0x0825e6e8`,
//! and `0x08260310`; no predicated `bl` forms or direct tail branches).
//!
//! The complete seventeen-word body begins with `push {lr}` at `0x082605ac`
//! and ends with `pop {pc}` at `0x082605ec`; the separately linked next
//! function begins at `0x082605f0`. It advances the input cursor through three
//! RGB8 bytes, reads each byte before any output write, then writes the three
//! bytes and a zero alpha byte as RGBA8.
//!
//! # Deliberate deviations
//!
//! Volatile accesses preserve the ARM cursor-update/load/store ordering when
//! the output overlaps the input range.

/// Reads one RGB8 triplet through `input_cursor` as an RGBA8 quadruplet.
///
/// # Safety
///
/// `input_cursor` must point to a readable pointer to at least three readable
/// bytes; `components` must identify four writable bytes. The original has no
/// NULL, alignment, or bounds checks, and the ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgb8_cursor_read_rgba8(
    components: *mut u8,
    _unused: u32,
    input_cursor: *mut *const u8,
) {
    let input = input_cursor.read_volatile();
    input_cursor.write_volatile(input.add(1));
    let first = input.read_volatile();
    input_cursor.write_volatile(input.add(2));
    let second = input.add(1).read_volatile();
    input_cursor.write_volatile(input.add(3));
    let third = input.add(2).read_volatile();
    components.write_volatile(first);
    components.add(1).write_volatile(second);
    components.add(2).write_volatile(third);
    components.add(3).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::rgb8_cursor_read_rgba8;

    fn reference_rgb8_cursor_read_rgba8(bytes: &mut [u8], output: usize, input: usize) -> usize {
        let first = bytes[input];
        let second = bytes[input + 1];
        let third = bytes[input + 2];
        bytes[output] = first;
        bytes[output + 1] = second;
        bytes[output + 2] = third;
        bytes[output + 3] = 0;
        input + 3
    }

    #[test]
    fn reads_triplet_as_rgba8_and_advances_cursor() {
        let mut input = [0x12, 0xab, 0xfe, 0x45];
        let mut output = [0xde; 4];
        let mut cursor = input.as_ptr();

        unsafe { rgb8_cursor_read_rgba8(output.as_mut_ptr(), 0xffff_ffff, &mut cursor) };

        assert_eq!(output, [0x12, 0xab, 0xfe, 0]);
        assert_eq!(cursor, input.as_ptr().wrapping_add(3));
    }

    #[test]
    fn matches_ordered_arm_accesses_for_all_quadruplet_overlaps() {
        for output in 0..=7 {
            let input = 3;
            let initial = [0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba];
            let mut expected = initial;
            let mut actual = initial;
            let expected_cursor = reference_rgb8_cursor_read_rgba8(&mut expected, output, input);
            let mut cursor = actual.as_ptr().wrapping_add(input);

            unsafe {
                rgb8_cursor_read_rgba8(actual.as_mut_ptr().wrapping_add(output), 0, &mut cursor)
            };

            assert_eq!(actual, expected, "output={output}");
            assert_eq!(cursor, actual.as_ptr().wrapping_add(expected_cursor));
        }
    }
}
