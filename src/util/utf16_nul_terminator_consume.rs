//! `utf16_nul_terminator_consume` — consume a UTF-16 NUL terminator.
//!
//! Original: `FUN_08087b7c` at load address **0x08087b7c**, 48 bytes
//! (`0x08087b7c..0x08087bac`; the distinct next function begins at
//! `0x08087bac`). Raw ARM decoding finds **5 direct `bl` call sites**, all
//! unconditional (0x0803ae70, 0x0803af44, 0x0807b4a0, 0x080b6694, and
//! 0x080cc7fc), and no predicated calls.
//!
//! When at least two bytes remain, it tests the two bytes at `*cursor` for a
//! UTF-16 NUL code unit. On success it advances `*cursor` by two bytes and
//! returns one; otherwise it leaves the cursor unchanged and returns zero.
//! Deliberate deviation: the stock `remaining_bytes < 2` path compares an
//! incoming scratch register and can dereference an address derived from the
//! length, so it has no stable C-level meaning. The Rust port returns zero for
//! that malformed, incomplete-code-unit input.

/// Consumes a UTF-16 NUL code unit at `*cursor` when `remaining_bytes >= 2`.
///
/// # Safety
/// `cursor` must point to one writable pointer word. When `remaining_bytes`
/// is at least two, `*cursor` must point to two readable bytes.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn utf16_nul_terminator_consume(
    cursor: *mut *const u8,
    remaining_bytes: i32,
) -> u32 {
    if remaining_bytes < 2 {
        return 0;
    }

    let input = unsafe { cursor.read() };
    if unsafe { input.read() } != 0 || unsafe { input.add(1).read() } != 0 {
        return 0;
    }

    unsafe { cursor.write(input.add(2)) };
    1
}

#[cfg(test)]
mod tests {
    use super::utf16_nul_terminator_consume;

    #[test]
    fn consumes_exactly_a_utf16_nul_code_unit() {
        let text = [0, 0, 0x41, 0];
        let mut cursor = text.as_ptr();

        assert_eq!(unsafe { utf16_nul_terminator_consume(&mut cursor, 2) }, 1);
        assert_eq!(cursor, unsafe { text.as_ptr().add(2) });
    }

    #[test]
    fn rejects_non_nul_and_incomplete_code_units_without_advancing() {
        for (text, remaining_bytes) in [
            ([0, 1], 2),
            ([1, 0], 2),
            ([0, 0], 1),
            ([0, 0], 0),
            ([0, 0], -1),
        ] {
            let mut cursor = text.as_ptr();
            assert_eq!(unsafe { utf16_nul_terminator_consume(&mut cursor, remaining_bytes) }, 0);
            assert_eq!(cursor, text.as_ptr());
        }
    }
}
