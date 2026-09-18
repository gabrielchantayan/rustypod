//! Format a duration into a StringObject.
//!
//! `format_duration` — original: `FUN_0815d7e4` @ 0x0815d7e4 (124 bytes,
//! 0x0815d7e4..0x0815d860). The next separately linked function starts at
//! 0x0815d884 after the two format strings and their 999-ms literal. Raw ARM
//! has four direct, unconditional plain `bl` calls and no predicated `bl`.
//!
//! The body divides milliseconds into hours, minutes, seconds, and a residual
//! millisecond component, then formats either `%02d:%02d:%02d` or
//! `%02d:%02d:%02d.%03d` into `out`. It keeps the retail `remainder == 1000`
//! clamp, although a conforming unsigned divider cannot produce it.
//!
//! Deliberate deviation: stable Rust represents the formatter's variadic spill
//! as an explicit four-word `VaList`; this is the established formatter ABI.

use crate::cxx::string_object::{string_object_format, StringObject};
use crate::printf::printf_api::VaList;

const SECONDS_PER_MINUTE: u32 = 60;
const SECONDS_PER_HOUR: u32 = 3600;
const MILLIS_PER_SECOND: u32 = 1000;
const WHOLE_SECONDS_FORMAT: &[u8] = b"%02d:%02d:%02d\0";
const MILLIS_FORMAT: &[u8] = b"%02d:%02d:%02d.%03d\0";

/// Formats `milliseconds` as an elapsed `HH:MM:SS` value, optionally including
/// a three-digit millisecond suffix.
///
/// `out` must be a valid StringObject. The unused leading word is retained for
/// the retail ABI; the only recovered caller supplies an opaque context there.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn format_duration(
    _unused: u32,
    milliseconds: u32,
    include_milliseconds: u32,
    out: *mut StringObject,
) {
    let whole_seconds = milliseconds / MILLIS_PER_SECOND;
    let mut millis = milliseconds % MILLIS_PER_SECOND;
    let hours = whole_seconds / SECONDS_PER_HOUR;
    let within_hour = whole_seconds.wrapping_sub(hours.wrapping_mul(SECONDS_PER_HOUR));
    let minutes = within_hour / SECONDS_PER_MINUTE;
    let seconds = within_hour.wrapping_sub(minutes.wrapping_mul(SECONDS_PER_MINUTE));
    if millis == MILLIS_PER_SECOND {
        millis = MILLIS_PER_SECOND - 1;
    }

    let args = [hours, minutes, seconds, millis];
    let format = if include_milliseconds == 0 { WHOLE_SECONDS_FORMAT } else { MILLIS_FORMAT };
    unsafe { string_object_format(out, format.as_ptr(), args.as_ptr() as VaList) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::{
        RetailVsnprintfEngineFn, StringObjectAssignCstrOps, RETAIL_VSNPRINTF_ENGINE,
        STRING_OBJECT_ASSIGN_CSTR_OPS,
    };
    use crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK;
    use core::ptr;

    static mut OBSERVED_FORMAT: *const u8 = ptr::null();
    static mut OBSERVED_ARGS: [u32; 4] = [0; 4];
    static mut OUTPUT: [u8; 16] = [0; 16];

    unsafe extern "C" fn record_format(
        _sink: usize,
        cursor: *mut *mut u8,
        _maximum: usize,
        format: *const u8,
        args: VaList,
    ) -> i32 {
        OBSERVED_FORMAT = format;
        ptr::copy_nonoverlapping(args, ptr::addr_of_mut!(OBSERVED_ARGS).cast(), 4);
        let text = b"formatted\0";
        ptr::copy_nonoverlapping(text.as_ptr(), *cursor, text.len());
        *cursor = (*cursor).add(text.len() - 1);
        9
    }

    unsafe extern "C" fn allocate(_this: *mut StringObject, size: usize, _flags: u32) -> *mut u8 {
        assert_eq!(size, 10);
        ptr::addr_of_mut!(OUTPUT).cast()
    }

    struct FormatterGuard {
        engine: RetailVsnprintfEngineFn,
        ops: StringObjectAssignCstrOps,
    }

    impl Drop for FormatterGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(RETAIL_VSNPRINTF_ENGINE).write_volatile(self.engine);
                ptr::addr_of_mut!(STRING_OBJECT_ASSIGN_CSTR_OPS).write_volatile(self.ops);
            }
        }
    }

    fn format_with(milliseconds: u32, include_milliseconds: u32) -> (*const u8, [u32; 4], [u8; 16]) {
        let _lock = STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let guard = FormatterGuard {
                engine: ptr::addr_of!(RETAIL_VSNPRINTF_ENGINE).read_volatile(),
                ops: ptr::addr_of!(STRING_OBJECT_ASSIGN_CSTR_OPS).read_volatile(),
            };
            OUTPUT = [0; 16];
            RETAIL_VSNPRINTF_ENGINE = record_format;
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps {
                allocate_payload: allocate,
                clear_payload: guard.ops.clear_payload,
            };
            let mut out = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };
            format_duration(0x1234, milliseconds, include_milliseconds, &mut out);
            let result = (OBSERVED_FORMAT, OBSERVED_ARGS, OUTPUT);
            drop(guard);
            result
        }
    }

    #[test]
    fn splits_an_exact_hour_without_milliseconds() {
        let (format, args, output) = format_with(3_600_000, 0);
        assert_eq!(format, WHOLE_SECONDS_FORMAT.as_ptr());
        assert_eq!(args, [1, 0, 0, 0]);
        assert_eq!(&output[..10], b"formatted\0");
    }

    #[test]
    fn wraps_minutes_within_an_hour_and_preserves_millis() {
        let (format, args, _) = format_with(7_261_009, 1);
        assert_eq!(format, MILLIS_FORMAT.as_ptr());
        assert_eq!(args, [2, 1, 1, 9]);
    }
}
