//! parse_wide_decimal_counted — original: `FUN_0808ce8c` @ 0x0808ce8c (56 bytes).
//!
//! Verified direct call count: 9, all unconditional `bl`; no predicated call
//! forms. The function consumes exactly a signed-positive count of 16-bit code
//! units from the caller-owned cursor slot. Every unit, without validating that
//! it is an ASCII digit, contributes `unit - '0'` to a wrapping base-10
//! accumulator; the cursor slot advances by one unit after every read.
//!
//! Deliberate ABI deviations: Ghidra spells the cursor slot as `undefined4 *`
//! and the result as `int`. This port uses `*mut *const u16` and `u32`, which
//! retain the 32-bit ARM pointer layout and return-word bit pattern while
//! documenting the read-only input and wrapping arithmetic.
//! Volatile cursor-slot accesses intentionally retain the target's load/store
//! on every iteration instead of allowing LLVM to hoist the cursor load.

/// Consume exactly `count` UTF-16 code units through `cursor` and return their
/// unchecked, wrapping base-10 accumulation. A non-positive count touches
/// neither pointer, matching the target's signed `gt` loop guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_wide_decimal_counted(
    cursor: *mut *const u16,
    mut count: i32,
) -> u32 {
    let mut value = 0u32;

    while count > 0 {
        let input = cursor.read_volatile();
        let code_unit = input.read();
        cursor.write_volatile(input.add(1));
        value = value
            .wrapping_mul(10)
            .wrapping_add(code_unit as u32)
            .wrapping_sub(b'0' as u32);
        count -= 1;
    }

    value
}


#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn parse(input: &[u16], count: i32) -> (u32, usize) {
        let start = input.as_ptr();
        let mut cursor = start;
        let value = unsafe { parse_wide_decimal_counted(&mut cursor, count) };
        let consumed = unsafe { cursor.offset_from(start) as usize };
        (value, consumed)
    }

    fn reference(input: &[u16], count: usize) -> u32 {
        input[..count].iter().fold(0u32, |value, &code_unit| {
            value
                .wrapping_mul(10)
                .wrapping_add(code_unit as u32)
                .wrapping_sub(b'0' as u32)
        })
    }

    #[test]
    fn consumes_exactly_the_requested_code_units() {
        let input = [b'0' as u16, b'0' as u16, b'1' as u16, b'4' as u16, b'2' as u16, b'x' as u16];
        assert_eq!(parse(&input, 5), (142, 5));
        assert_eq!(parse(&input, 3), (1, 3));
    }

    #[test]
    fn does_not_validate_decimal_code_units() {
        let input = [b'1' as u16, b'A' as u16, 0x0100, b'2' as u16];
        assert_eq!(parse(&input, 4), (reference(&input, 4), 4));
    }

    #[test]
    fn wraps_the_accumulator_at_u32_width() {
        let input = [
            b'4' as u16, b'2' as u16, b'9' as u16, b'4' as u16, b'9' as u16,
            b'6' as u16, b'7' as u16, b'2' as u16, b'9' as u16, b'6' as u16,
        ];
        assert_eq!(parse(&input, 10), (0, 10));
    }

    #[test]
    fn non_positive_count_dereferences_neither_pointer() {
        for count in [0, -1, i32::MIN] {
            assert_eq!(unsafe { parse_wide_decimal_counted(core::ptr::null_mut(), count) }, 0);
        }
    }
}
