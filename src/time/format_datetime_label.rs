//! Relative calendar label — FUN_080ca834 @ 0x080ca834.
//!
//! True extent: 256 bytes, [0x080ca834,0x080ca934), including 36 bytes of
//! strings/literal pool; executable body is 220 bytes. Raw A32 decoding finds
//! two incoming plain BLs, six outgoing plain BLs, and zero predicated BLs.
//! An absolute request tail-formats month/day and twelve-hour time. Relative
//! requests query the current calendar, compare it to the supplied record,
//! and use time below 86400 seconds, uppercase weekday below 604800 seconds,
//! otherwise month/day. Timestamp subtraction wraps as u32. Future records
//! always use month/day. The weekday path translates each non-NUL byte through
//! the firmware's 256-byte case table and returns zero, not formatter status.
//!
//! Deliberate deviations: none on target; existing calendar and formatter
//! ports are reused. The second argument to the original timestamp converter
//! is dead (raw 0x08093c38 immediately replaces r1), so its Rust API omits it.

use super::datetime::{DateTime, datetime_compare, datetime_to_unix_seconds};
use super::current_datetime::current_datetime_to_normalized_record;
use crate::printf::format_with_descriptor::format_with_default_descriptor;
use core::mem::MaybeUninit;

const ABSOLUTE: &[u8] = b"%-m-%-d %-I:%M%1p\0";
const TIME: &[u8] = b"%-I:%M%1p\0";
const DATE: &[u8] = b"%-m-%-d\0";
const WEEKDAY: &[u8] = b"%a\0";

#[derive(Debug, PartialEq, Eq)]
enum Label { Time, Weekday, Date }

fn relative_label(comparison: i32, elapsed: u32) -> Label {
    if comparison < 0 { Label::Date }
    else if elapsed < 86_400 { Label::Time }
    else if elapsed < 604_800 { Label::Weekday }
    else { Label::Date }
}

unsafe fn translate_label(mut destination: *mut u8, table: *const u8) {
    loop {
        let byte = destination.read();
        if byte == 0 { break; }
        destination.write(table.add(byte as usize).read());
        destination = destination.add(1);
    }
}

/// Formats into a writable 40-byte buffer. `datetime` must be a readable,
/// writable aligned DateTime (timestamp conversion updates its weekday).
/// Relative weekday formatting requires the stock case table at 0x083ed1dd.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn format_datetime_label(
    datetime: *mut DateTime, relative: u32, destination: *mut u8,
) -> i32 {
    if relative == 0 {
        return format_with_default_descriptor(destination, 40, ABSOLUTE.as_ptr(), datetime.cast());
    }
    let mut current = MaybeUninit::<DateTime>::uninit();
    current_datetime_to_normalized_record(current.as_mut_ptr());
    let comparison = datetime_compare(current.as_ptr(), datetime);
    let elapsed = if comparison >= 0 {
        let timestamp = datetime_to_unix_seconds(datetime) as u32;
        (datetime_to_unix_seconds(current.as_mut_ptr()) as u32).wrapping_sub(timestamp)
    } else { 0 };
    let label = relative_label(comparison, elapsed);
    let format = match label { Label::Time => TIME, Label::Weekday => WEEKDAY, Label::Date => DATE };
    let result = format_with_default_descriptor(destination, 40, format.as_ptr(), datetime.cast());
    if label == Label::Weekday {
        translate_label(destination, 0x083e_d1dd as *const u8);
        0
    } else { result }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_relative_boundaries_and_future_precedence() {
        for comparison in [0, 1, 65_535] {
            for (elapsed, expected) in [
                (0, Label::Time), (81_919, Label::Time), (81_920, Label::Time),
                (86_399, Label::Time), (86_400, Label::Weekday),
                (589_823, Label::Weekday), (589_824, Label::Weekday),
                (604_799, Label::Weekday), (604_800, Label::Date),
                (u32::MAX, Label::Date),
            ] {
                assert_eq!(relative_label(comparison, elapsed), expected);
            }
        }
        for elapsed in [0, 86_399, 86_400, 604_799, u32::MAX] {
            assert_eq!(relative_label(-1, elapsed), Label::Date);
        }
    }

    #[test]
    fn translation_stops_at_original_nul_and_uses_unsigned_indices() {
        let mut table = [0u8; 256];
        for (i, byte) in table.iter_mut().enumerate() { *byte = i as u8; }
        table[b'm' as usize] = b'M';
        table[0xff] = b'!';
        table[b'x' as usize] = 0;
        let mut output = [b'm', 0xff, b'x', b'm', 0, b'm'];
        unsafe { translate_label(output.as_mut_ptr(), table.as_ptr()); }
        assert_eq!(output, [b'M', b'!', 0, b'M', 0, b'm']);
        let mut empty = [0, b'm'];
        unsafe { translate_label(empty.as_mut_ptr(), table.as_ptr()); }
        assert_eq!(empty, [0, b'm']);
    }
}
