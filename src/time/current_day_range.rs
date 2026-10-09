//! Lazy current-day range cache, `FUN_080d7278` @ **0x080d7278**.
//!
//! True extent: **156 bytes**, 0x080d7278..0x080d7314; the next function
//! starts with `ldr r3, [pc, #56]`. Raw ARM words contain five unconditional
//! outgoing BLs and no predicated outgoing BLs. Whole-image decoding finds
//! zero plain and two predicated incoming BLs (BLEQ at 0x080aaef8/0x080aaf24).
//!
//! If the ready byte is zero, obtain raw current Macintosh-epoch seconds,
//! convert twice to seven u16 calendar fields, replace hour/minute/second
//! with 00:00:00 and 23:59:59, convert back, and cache each result as a
//! zero-extended 64-bit pair. Publish ready last. Nonzero ready is a no-op.
//!
//! No deliberate behavioral deviations. Calendar converters remain direct
//! firmware seams: 0x08066328 reads runtime epoch globals at 0x083f50a4 and
//! 0x083e2e58; 0x08048080 reads 0x083f50a4. Their semantics must not be
//! replaced with a presumed Unix or Macintosh epoch arithmetic shortcut.

use core::mem::MaybeUninit;

/// Seven halfwords used by the firmware's expanded calendar converters.
#[repr(C)]
struct Calendar {
    year: u16,
    month: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    weekday: u16,
}

/// Word-pair timestamps deliberately avoid host u64 alignment differences.
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct CurrentDayRange {
    pub ready: u8,
    pub reserved: [u8; 3],
    pub current_seconds: u32,
    pub start_seconds: u32,
    pub start_high: u32,
    pub end_seconds: u32,
    pub end_high: u32,
}

type ExpandCalendar = unsafe extern "C" fn(u32, *mut Calendar);
type CollapseCalendar = unsafe extern "C" fn(*const Calendar, *mut u32);

unsafe extern "C" fn expand_calendar(seconds: u32, out: *mut Calendar) {
    #[cfg(target_os = "none")]
    {
        let convert: ExpandCalendar = core::mem::transmute(0x0806_6328usize);
        convert(seconds, out);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (seconds, out); panic!("requires firmware calendar converter 0x08066328"); }
}

unsafe extern "C" fn collapse_calendar(calendar: *const Calendar, out: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let convert: CollapseCalendar = core::mem::transmute(0x0804_8080usize);
        convert(calendar, out);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (calendar, out); panic!("requires firmware calendar converter 0x08048080"); }
}

#[inline(always)]
unsafe fn initialize(
    cache: *mut CurrentDayRange,
    current: unsafe extern "C" fn(*mut u32),
    expand: ExpandCalendar,
    collapse: CollapseCalendar,
) {
    if (*cache).ready != 0 { return; }
    current(core::ptr::addr_of_mut!((*cache).current_seconds));
    let mut calendar = MaybeUninit::<Calendar>::uninit();
    let calendar = calendar.as_mut_ptr();
    let mut seconds = MaybeUninit::<u32>::uninit();
    expand((*cache).current_seconds, calendar);
    (*calendar).hour = 0;
    (*calendar).minute = 0;
    (*calendar).second = 0;
    collapse(calendar, seconds.as_mut_ptr());
    (*cache).start_seconds = seconds.assume_init();
    (*cache).start_high = 0;
    expand((*cache).current_seconds, calendar);
    (*calendar).hour = 23;
    (*calendar).minute = 59;
    (*calendar).second = 59;
    collapse(calendar, seconds.as_mut_ptr());
    (*cache).end_seconds = seconds.assume_init();
    (*cache).end_high = 0;
    (*cache).ready = 1;
}

/// Initialize a current-day range once, preserving any nonzero ready state.
///
/// # Safety
/// `cache` must be aligned, writable, and exclusively accessible for 24 bytes.
/// The current-time service and firmware calendar converters must be available.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_day_range_initialize(cache: *mut CurrentDayRange) {
    initialize(cache, super::current_mac_epoch_seconds_raw::current_mac_epoch_seconds_raw,
        expand_calendar, collapse_calendar);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent calendar model: a 2000-02-29 day whose start wraps u32.
    const DAY_START: u32 = u32::MAX - 40_000;
    unsafe extern "C" fn now(out: *mut u32) { out.write(DAY_START.wrapping_add(43_210)); }
    unsafe extern "C" fn expand(seconds: u32, out: *mut Calendar) {
        let elapsed = seconds.wrapping_sub(DAY_START);
        assert!(elapsed < 86_400);
        out.write(Calendar { year: 2000, month: 2, day: 29,
            hour: (elapsed / 3600) as u16, minute: ((elapsed / 60) % 60) as u16,
            second: (elapsed % 60) as u16, weekday: 3 });
    }
    unsafe extern "C" fn collapse(calendar: *const Calendar, out: *mut u32) {
        let c = &*calendar;
        assert_eq!((c.year, c.month, c.day, c.weekday), (2000, 2, 29, 3));
        out.write(DAY_START.wrapping_add(c.hour as u32 * 3600 + c.minute as u32 * 60 + c.second as u32));
        // A converter may clobber its input: the second expansion must restore it.
        (*(calendar as *mut Calendar)).day = 0;
    }
    fn cache(ready: u8) -> CurrentDayRange {
        CurrentDayRange { ready, reserved: [0xa5, 0x5a, 0xff], current_seconds: 9,
            start_seconds: 10, start_high: u32::MAX, end_seconds: 11, end_high: u32::MAX }
    }
    #[test]
    fn wraps_end_seconds_without_sign_extension_and_preserves_calendar_date() {
        let mut c = cache(0);
        unsafe { initialize(&mut c, now, expand, collapse); }
        assert_eq!(c, CurrentDayRange { ready: 1, reserved: [0xa5, 0x5a, 0xff],
            current_seconds: DAY_START.wrapping_add(43_210), start_seconds: DAY_START,
            start_high: 0, end_seconds: DAY_START.wrapping_add(86_399), end_high: 0 });
        unsafe { current_day_range_initialize(&mut c); }
        assert_eq!(c.end_seconds, DAY_START.wrapping_add(86_399));
    }
    #[test]
    fn every_nonzero_ready_byte_leaves_the_cache_untouched() {
        for ready in 1..=255 {
            let mut c = cache(ready);
            unsafe { current_day_range_initialize(&mut c); }
            assert_eq!(c, cache(ready));
        }
    }
}
