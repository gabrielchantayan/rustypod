//! Runtime-epoch seconds to seven calendar halfwords: `FUN_08066328`
//! @ **0x08066328**, **156 bytes** (144 executable bytes plus 12 literal
//! bytes; next function begins at 0x080663c4). Raw aligned ARM decoding
//! verifies two plain inbound BLs (0x080d72a0, 0x080d72d4), two plain
//! outgoing BLs (unsigned division and unix_seconds_to_datetime), and no
//! predicated BLs in either direction.
//!
//! Divide unsigned seconds by 86400, add the runtime day bias at 0x083f50a4,
//! subtract the epoch day at 0x083e2e58, then multiply by 86400 and restore
//! the remainder, all modulo 2^32. Convert the result to a zero-initialized
//! packed DateTime and widen year/month/day/hour/minute/second into u16s;
//! weekday is widened before adding one. NULL output skips all global reads
//! and calls. Deliberate deviation: Rust unsigned arithmetic replaces the
//! ADS quotient/remainder call; the existing Rust calendar converter is
//! called directly. Runtime globals are not replaced with assumed epochs.

use super::datetime::DateTime;
use super::unix_to_datetime::unix_seconds_to_datetime;

/// Firmware expanded calendar layout, seven consecutive target halfwords.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calendar {
    pub year: u16,
    pub month: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub weekday: u16,
}

#[inline(always)]
unsafe fn convert(seconds: u32, out: *mut Calendar, day_bias: *const u32, epoch_day: *const u32) {
    if out.is_null() { return; }
    let days = (seconds / 86_400).wrapping_add(day_bias.read_volatile())
        .wrapping_sub(epoch_day.read_volatile());
    let adjusted = days.wrapping_mul(86_400).wrapping_add(seconds % 86_400);
    let mut date = DateTime { second: 0, minute: 0, hour: 0, day: 0,
        month: 0, reserved: 0, year: 0, weekday: 0, reserved2: 0 };
    unix_seconds_to_datetime(adjusted, &mut date);
    (*out).year = date.year;
    (*out).month = date.month as u16;
    (*out).day = date.day as u16;
    (*out).hour = date.hour as u16;
    (*out).minute = date.minute as u16;
    (*out).second = date.second as u16;
    (*out).weekday = date.weekday as u16 + 1;
}

/// Expand a runtime-epoch timestamp; a NULL output is a no-op.
///
/// # Safety
/// Non-NULL `out` must be aligned and writable for seven u16 fields. The
/// retailOS day globals and the existing packed-calendar provider must be
/// available. Host callers of non-NULL outputs must provide mapped globals.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn seconds_to_calendar(seconds: u32, out: *mut Calendar) {
    convert(seconds, out, 0x083f_50a4 as *const u32, 0x083e_2e58 as *const u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::unix_to_datetime::{DAY_NUMBER_TO_DATETIME, DAY_NUMBER_TO_DATETIME_TEST_LOCK};
    use core::ptr;

    unsafe extern "C" fn calendar_date(_day: u32, out: *mut DateTime) {
        // Leave time and padding untouched, exercising the initialized scratch
        // record and the real converter's time decomposition.
        assert_eq!((*out).reserved, 0);
        assert_eq!((*out).reserved2, 0);
        (*out).year = 0xfedc;
        (*out).month = 12;
        (*out).day = 31;
        (*out).weekday = 255;
    }

    #[test]
    fn null_output_does_not_read_runtime_globals() {
        unsafe { seconds_to_calendar(u32::MAX, ptr::null_mut()); }
    }

    #[test]
    fn expands_fields_and_preserves_modular_day_adjustment() {
        let _lock = DAY_NUMBER_TO_DATETIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        struct Restore(super::super::unix_to_datetime::DayNumberToDateTimeFn);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { ptr::write_volatile(ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME), self.0); } }
        }
        unsafe {
            let _restore = Restore(ptr::read_volatile(ptr::addr_of!(DAY_NUMBER_TO_DATETIME)));
            ptr::write_volatile(ptr::addr_of_mut!(DAY_NUMBER_TO_DATETIME), calendar_date);
            for seconds in [0, 1, 59, 60, 3599, 3600, 86_399, 86_400, u32::MAX] {
                for (bias, epoch) in [(0u32, 0u32), (1, 0), (0, 1), (u32::MAX, 7), (7, u32::MAX)] {
                    let expected = (seconds as u64).wrapping_add((bias as u64).wrapping_sub(epoch as u64)
                        .wrapping_mul(86_400)) as u32;
                    let mut guarded = [0xa5a5u16; 9];
                    convert(seconds, guarded.as_mut_ptr().add(1).cast(), &bias, &epoch);
                    assert_eq!(guarded, [0xa5a5, 0xfedc, 12, 31,
                        ((expected % 86_400) / 3600) as u16,
                        ((expected % 3600) / 60) as u16, (expected % 60) as u16, 256, 0xa5a5]);
                }
            }
        }
    }
}
