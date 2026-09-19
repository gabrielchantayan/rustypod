//! `parse_hash_radix_i32` — original: `FUN_0807f740` @ `0x0807f740`
//! (72 bytes, `0x0807f740..0x0807f788`; the next real function starts at
//! `0x0807f788`).
//!
//! Verified calls: four incoming plain `bl` call sites and no incoming
//! predicated `bl` calls. The 18 body words contain one plain `bl` to the
//! unported generic radix worker at `0x08087490`, followed by a predicated
//! tail branch to that same worker.
//!
//! Algorithm: parse a signed base-10 prefix through the caller-owned cursor.
//! When that prefix is immediately followed by `#`, treat it as a radix from
//! 2 through 36 and parse the remaining signed digit prefix in that radix.
//! Every multiply-add and negation wraps modulo $2^{32}$.
//!
//! Deliberate deviations: the generic radix worker is inlined rather than
//! exposed as a seam because `FUN_08087490` has no confirmed semantic name.

/// Parses either a signed decimal prefix or `radix#signed-digits` from a
/// bounded byte range.
///
/// # Safety
///
/// `cursor` must point to a readable and writable target-width pointer slot.
/// The range from `*cursor` through (but excluding) `end` must be readable,
/// and `*cursor <= end`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_hash_radix_i32(cursor: *mut *const u8, end: *const u8) -> i32 {
    let radix = unsafe { parse_radix_prefix(cursor, end, 10) };
    let current = unsafe { cursor.read() };
    if current >= end || unsafe { current.read() } != b'#' {
        return radix;
    }

    unsafe { cursor.write(current.add(1)) };
    unsafe { parse_radix_prefix(cursor, end, radix) }
}

#[inline(always)]
unsafe fn parse_radix_prefix(cursor_slot: *mut *const u8, end: *const u8, radix: i32) -> i32 {
    let mut cursor = unsafe { cursor_slot.read() };
    if cursor == end || !(2..=36).contains(&radix) {
        return 0;
    }

    let negative = match unsafe { cursor.read() } {
        b'-' => {
            cursor = unsafe { cursor.add(1) };
            true
        }
        b'+' => {
            cursor = unsafe { cursor.add(1) };
            false
        }
        _ => false,
    };
    if cursor == end {
        return 0;
    }

    let mut value = 0i32;
    while cursor < end {
        let Some(digit) = digit_value(unsafe { cursor.read() }) else {
            break;
        };
        if digit >= radix {
            break;
        }
        value = value.wrapping_mul(radix).wrapping_add(digit);
        cursor = unsafe { cursor.add(1) };
    }
    if negative {
        value = value.wrapping_neg();
    }
    unsafe { cursor_slot.write(cursor) };
    value
}

#[inline(always)]
fn digit_value(byte: u8) -> Option<i32> {
    match byte {
        b'0'..=b'9' => Some(i32::from(byte - b'0')),
        b'A'..=b'Z' => Some(i32::from(byte - b'A') + 10),
        b'a'..=b'z' => Some(i32::from(byte - b'a') + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn reference(input: &[u8]) -> (i32, usize) {
        fn parse(input: &[u8], mut at: usize, radix: i32) -> (i32, usize) {
            if at == input.len() || !(2..=36).contains(&radix) {
                return (0, at);
            }
            let negative = match input[at] {
                b'-' => { at += 1; true }
                b'+' => { at += 1; false }
                _ => false,
            };
            if at == input.len() { return (0, at - 1); }
            let mut value = 0i32;
            while at < input.len() {
                let digit = match input[at] {
                    b'0'..=b'9' => i32::from(input[at] - b'0'),
                    b'A'..=b'Z' => i32::from(input[at] - b'A') + 10,
                    b'a'..=b'z' => i32::from(input[at] - b'a') + 10,
                    _ => break,
                };
                if digit >= radix { break; }
                value = value.wrapping_mul(radix).wrapping_add(digit);
                at += 1;
            }
            (if negative { value.wrapping_neg() } else { value }, at)
        }

        let (radix, at) = parse(input, 0, 10);
        if input.get(at) == Some(&b'#') {
            parse(input, at + 1, radix)
        } else {
            (radix, at)
        }
    }

    fn check(input: &[u8]) {
        let mut cursor = input.as_ptr();
        let actual = unsafe { parse_hash_radix_i32(&mut cursor, unsafe { input.as_ptr().add(input.len()) }) };
        let (expected, expected_at) = reference(input);
        assert_eq!((actual, unsafe { cursor.offset_from(input.as_ptr()) as usize }), (expected, expected_at), "input {input:?}");
    }

    #[test]
    fn decimal_prefix_and_hash_radices_stop_exactly() {
        for input in [b"42rest".as_slice(), b"2#1012", b"16#Cafe!", b"36#zZ?", b"1#123", b"37#123"] {
            check(input);
        }
    }

    #[test]
    fn signs_empty_bodies_and_wrapping_follow_the_worker() {
        for input in [b"-10#-80000000".as_slice(), b"+16#+FF", b"16#-", b"-", b"10#4294967296", b"16#FFFFFFFFF"] {
            check(input);
        }
    }

    #[test]
    fn all_byte_terminators_preserve_the_first_rejected_byte() {
        for byte in u8::MIN..=u8::MAX {
            check(&[b'8', b'#', b'7', byte, b'1']);
        }
    }
}
