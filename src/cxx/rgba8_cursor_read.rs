//! `rgba8_cursor_read` — original: `FUN_0825ebcc` @ `0x0825ebcc` (76 bytes;
//! **4 unconditional `bl` call sites**; no predicated `bl` forms).
//!
//! The complete 19-word body begins with `push {r4,lr}` at `0x0825ebcc` and
//! ends with `pop {r4,pc}` at `0x0825ec14`; the next function begins at
//! `0x0825ec18`. It advances the input cursor one byte at a time, then copies
//! the corresponding four source bytes to an RGBA8 output in source order.
//!
//! # Deliberate deviations
//!
//! Volatile accesses preserve the ARM cursor-update/load/store ordering when
//! the output overlaps the input range.

/// Reads one RGBA8 quadruplet through `input_cursor`.
///
/// # Safety
///
/// `input_cursor` must point to a readable pointer to at least four readable
/// bytes; `components` must identify four writable bytes. The original has no
/// NULL, alignment, or bounds checks, and the ranges may overlap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rgba8_cursor_read(
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
    input_cursor.write_volatile(input.add(4));
    let fourth = input.add(3).read_volatile();
    components.write_volatile(first);
    components.add(1).write_volatile(second);
    components.add(2).write_volatile(third);
    components.add(3).write_volatile(fourth);
}

#[cfg(test)]
mod tests {
    use super::rgba8_cursor_read;

    fn reference_rgba8_cursor_read(bytes: &mut [u8], output: usize, input: usize) -> usize {
        let mut cursor = input;
        let first = bytes[cursor];
        cursor += 1;
        let second = bytes[cursor];
        cursor += 1;
        let third = bytes[cursor];
        cursor += 1;
        let fourth = bytes[cursor];
        cursor += 1;
        bytes[output] = first;
        bytes[output + 1] = second;
        bytes[output + 2] = third;
        bytes[output + 3] = fourth;
        cursor
    }

    #[test]
    fn reads_quadruplet_and_advances_cursor() {
        let mut input = [0x12, 0xab, 0xfe, 0x45, 0x99];
        let mut output = [0xde; 4];
        let mut cursor = input.as_ptr();

        unsafe { rgba8_cursor_read(output.as_mut_ptr(), 0xffff_ffff, &mut cursor) };

        assert_eq!(output, [0x12, 0xab, 0xfe, 0x45]);
        assert_eq!(cursor, input.as_ptr().wrapping_add(4));
    }

    #[test]
    fn matches_ordered_arm_accesses_for_all_quadruplet_overlaps() {
        for output in 0..=8 {
            let input = 3;
            let initial = [0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb];
            let mut expected = initial;
            let mut actual = initial;
            let expected_cursor = reference_rgba8_cursor_read(&mut expected, output, input);
            let mut cursor = actual.as_ptr().wrapping_add(input);

            unsafe { rgba8_cursor_read(actual.as_mut_ptr().wrapping_add(output), 0, &mut cursor) };

            assert_eq!(actual, expected, "output={output}");
            assert_eq!(cursor, actual.as_ptr().wrapping_add(expected_cursor));
        }
    }
}
