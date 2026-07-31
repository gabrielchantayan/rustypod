//! scan_decimal_cursor — original: `FUN_080e9310` @ 0x080e9310 (60 bytes).
//!
//! Algorithm: load the input cursor from the caller-owned cursor slot, then
//! consume ASCII decimal digits. The firmware's character-class table tests
//! bit 0x10, which classifies precisely `'0'..='9'`; for each digit it uses
//! shift-add arithmetic equivalent to `acc * 10 + (byte - '0')`. Both the
//! multiply and addition wrap modulo 2^32. On the first non-digit, it writes
//! the cursor at that byte back through the slot and returns the accumulator.
//!
//! Deliberate ABI deviations: the original is recovered as
//! `int FUN_080e9310(undefined4 *param_1)`. This port spells the cursor slot
//! as `*mut *const u8` and returns `u32`; these preserve the same 32-bit ARM
//! word layout and return bit pattern while documenting that bytes are read
//! but never written.

/// Consume leading decimal digits at `*cursor`, update `*cursor` to the first
/// non-digit, and return their wrapping u32 value.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scan_decimal_cursor(cursor: *mut *const u8) -> u32 {
    let mut input = cursor.read();
    let mut acc = 0u32;

    loop {
        let byte = input.read();
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
            break;
        }

        acc = acc.wrapping_mul(10).wrapping_add(digit as u32);
        input = input.add(1);
    }

    cursor.write(input);
    acc
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn scan(input: &[u8]) -> (u32, usize) {
        let start = input.as_ptr();
        let mut cursor = start;
        let value = unsafe { scan_decimal_cursor(&mut cursor) };
        let consumed = unsafe { cursor.offset_from(start) as usize };
        (value, consumed)
    }

    #[test]
    fn updates_the_caller_cursor_past_consumed_digits() {
        assert_eq!(scan(b"00142x"), (142, 5));
    }

    #[test]
    fn stops_at_the_first_non_digit_without_consuming_it() {
        assert_eq!(scan(b"12a34\0"), (12, 2));
        assert_eq!(scan(b"+12\0"), (0, 0));
        assert_eq!(scan(b"\xff12\0"), (0, 0));
    }

    #[test]
    fn accumulator_wraps_as_a_u32() {
        assert_eq!(scan(b"4294967296!"), (0, 10));
        assert_eq!(scan(b"4294967297!"), (1, 10));
        assert_eq!(scan(b"9999999999!"), (9999999999u64 as u32, 10));
    }
}
