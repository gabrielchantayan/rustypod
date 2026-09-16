//! Bounded UTF-8 character counting for SQLite text ranges.
//!
/// `sqlite_utf8_char_len` — original: `FUN_08386384` @ `0x08386384`
/// (**80 bytes**, 0x08386384..0x083863d4; the next function begins with
/// `mov r3, r0; push {lr}`). A complete raw-ARM scan of `osos.dec` finds
/// **4 direct call sites**: 4 unconditional plain `bl`, 0 predicated `bl`,
/// and 0 direct `b` tail sites.
///
/// SQLite 3.5.9's `sqlite3Utf8CharLen`: count each non-NUL leading byte before
/// the signed byte limit, skipping every following continuation byte (`10xxxxxx`).
/// A negative limit is unbounded. The continuation loop deliberately does not
/// recheck the byte limit, so a sequence that starts before it counts as one
/// even when its continuation bytes lie beyond it. It neither validates UTF-8
/// nor treats `0x80..=0xbf` specially; each such byte is a character. No
/// deviations.
///
/// # Safety
///
/// `text` must be readable at least through the first NUL byte for a negative
/// `byte_limit`, or through each sequence begun before a nonnegative limit;
/// the original also reads `*text` before checking a zero limit.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_utf8_char_len(text: *const u8, byte_limit: i32) -> i32 {
    let terminator = if byte_limit >= 0 {
        text.wrapping_offset(byte_limit as isize)
    } else {
        usize::MAX as *const u8
    };
    let mut cursor = text;
    let mut count = 0i32;
    let mut leading = cursor.read_volatile();

    while leading != 0 && cursor < terminator {
        cursor = cursor.add(1);
        if leading > 0xbf {
            while cursor.read_volatile() & 0xc0 == 0x80 {
                cursor = cursor.add(1);
            }
        }
        count = count.wrapping_add(1);
        leading = cursor.read_volatile();
    }
    count
}

#[cfg(test)]
mod tests {
    use super::sqlite_utf8_char_len;

    unsafe fn count(text: &[u8], byte_limit: i32) -> i32 {
        sqlite_utf8_char_len(text.as_ptr(), byte_limit)
    }

    #[test]
    fn counts_ascii_and_honors_byte_limit() {
        let text = b"album\0";
        unsafe {
            assert_eq!(count(text, -1), 5);
            assert_eq!(count(text, 3), 3);
            assert_eq!(count(text, 0), 0);
        }
    }

    #[test]
    fn counts_leads_and_orphan_continuations_without_validation() {
        let text = [0xc3, 0xa9, 0x80, b'x', 0];
        unsafe { assert_eq!(count(&text, -1), 2) };
    }

    #[test]
    fn completes_sequence_that_starts_before_limit() {
        let text = [b'a', 0xe2, 0x82, 0xac, b'b', 0];
        unsafe {
            assert_eq!(count(&text, 2), 2);
            assert_eq!(count(&text, 4), 2);
            assert_eq!(count(&text, 5), 3);
        }
    }
}
