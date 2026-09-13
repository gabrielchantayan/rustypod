//! Reads the one-byte payload size in an MPEG-4 ESDS descriptor.
//!
//! `esds_read_descriptor_size_if_tag` — original: `FUN_0815404c` at load
//! address `0x0815404c` (**72 bytes**, `0x0815404c..0x08154094`; all code).
//! Raw `osos.dec` disassembly confirms the next separately linked function
//! starts at `0x08154094`. Decoding every aligned ARM B/BL immediate in the
//! complete image finds **six direct `bl` call sites**, all unconditional, at
//! `0x08154468`, `0x081544f4`, `0x081545f4`, `0x08154c2c`, `0x08154cc0`, and
//! `0x08154dd8`; there are no predicated calls, tail branches, or aligned
//! data-word references to this entry.
//!
//! The ESDS parser supplies the observed descriptor tag and an expected tag.
//! A mismatch returns 1 without reading or writing any pointer argument. A
//! match consumes zero or more literal `0x80` size-prefix bytes, copies the
//! first other byte to `size_out`, advances `cursor` past that byte, and
//! returns 0. This is deliberately not a general MPEG-4 variable-length-size
//! decoder: raw ARM compares only to `0x80`, so `0x81..=0xff` are copied as
//! sizes rather than treated as continuation bytes. No deliberate deviations.

/// Consumes an ESDS descriptor size byte only when the descriptor tag matches.
///
/// # Safety
///
/// On a matching tag, `descriptor.add(*cursor)` must be readable through the
/// first non-`0x80` byte, and `size_out` and `cursor` must be writable. The
/// original has no pointer, range, or alias guards; its 32-bit cursor addition
/// wraps. On a mismatching tag none of those pointers are accessed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn esds_read_descriptor_size_if_tag(
    _parser: *mut u8,
    observed_tag: u32,
    expected_tag: u32,
    descriptor: *const u8,
    size_out: *mut u8,
    cursor: *mut u32,
) -> u32 {
    if observed_tag != expected_tag {
        return 1;
    }

    loop {
        let index = unsafe { cursor.read() };
        let size = unsafe { descriptor.add(index as usize).read() };
        if size == 0x80 {
            unsafe { cursor.write(index.wrapping_add(1)) };
            continue;
        }

        let output_index = unsafe { cursor.read() };
        unsafe {
            cursor.write(index.wrapping_add(1));
            size_out.write(descriptor.add(output_index as usize).read());
        }
        return 0;
    }
}

#[cfg(test)]
mod tests {
    use super::esds_read_descriptor_size_if_tag;
    use core::ptr;

    #[test]
    fn mismatch_preserves_outputs_without_dereferencing_descriptor() {
        let mut cursor = 7u32;
        let mut size = 0xa5u8;

        let result = unsafe {
            esds_read_descriptor_size_if_tag(
                ptr::null_mut(),
                4,
                5,
                ptr::null(),
                &mut size,
                &mut cursor,
            )
        };

        assert_eq!(result, 1);
        assert_eq!(cursor, 7);
        assert_eq!(size, 0xa5);
    }

    #[test]
    fn skips_only_zero_continuation_groups_then_consumes_size() {
        let descriptor = [0x11, 0x80, 0x80, 0x2a, 0x99];
        let mut cursor = 1u32;
        let mut size = 0u8;

        let result = unsafe {
            esds_read_descriptor_size_if_tag(
                ptr::null_mut(),
                3,
                3,
                descriptor.as_ptr(),
                &mut size,
                &mut cursor,
            )
        };

        assert_eq!(result, 0);
        assert_eq!(size, 0x2a);
        assert_eq!(cursor, 4);
    }

    #[test]
    fn high_bit_values_other_than_80_are_sizes_not_continuations() {
        let descriptor = [0x80, 0x81, 0x2a];
        let mut cursor = 0u32;
        let mut size = 0u8;

        let result = unsafe {
            esds_read_descriptor_size_if_tag(
                ptr::null_mut(),
                5,
                5,
                descriptor.as_ptr(),
                &mut size,
                &mut cursor,
            )
        };

        assert_eq!(result, 0);
        assert_eq!(size, 0x81);
        assert_eq!(cursor, 2);
    }
}
