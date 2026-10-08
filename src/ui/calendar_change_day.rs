//! Change calendar day — FUN_0812805c @ 0x0812805c.
//!
//! True extent: 184 bytes, [0x0812805c,0x08128114), including four
//! literals after the return at 0x08128100; the next entry starts with push.
//! Raw decoding: two plain and zero predicated inbound BLs (0x08126d3c,
//! 0x08126d94). Body: two plain BLs, one BLNE, one BLX and two BLXNE.
//! If the day differs, convert the old day, publish the new day, optionally
//! clear cached elements, notify Str /0x36dd, then reconvert the current
//! day and notify weekday /0x36de and month /0x36df changes in that order.
//! Reloading after notification preserves reentrant changes to the day.
//! Deviations: scratch bytes not read by this function are zero-initialized;
//! existing Rust clear and volatile calendar-converter dispatch replace BLs.
//! Incoming r2/r3 are irrelevant scratch, not additional ABI arguments.

use crate::time::datetime::DateTime;
use crate::time::unix_to_datetime::{day_number_to_datetime, DayNumberToDateTimeFn};
use crate::cxx::observable_element_array_clear::observable_element_array_clear;

const DAY: usize = 0x288 / 4;
const EVENT_GROUP: u32 = 0x5374_7220;
type Clear = unsafe extern "C" fn(*mut u32);
type Notify = unsafe extern "C" fn(*mut u32, u32);

unsafe extern "C" fn clear_elements(array: *mut u32) {
    observable_element_array_clear(array.cast());
}

unsafe extern "C" fn notify(view: *mut u32, event: u32) {
    let vtable = view.read() as usize as *const u32;
    let dispatch: unsafe extern "C" fn(*mut u32, u32, u32) =
        core::mem::transmute(vtable.add(0x58 / 4).read() as usize);
    dispatch(view, EVENT_GROUP, event);
}

/// Change the selected day and invalidate dependent calendar state.
///
/// Original: 0x0812805c, 184 bytes; two verified plain inbound BLs.
///
/// # Safety
/// `view` must be a writable retailOS calendar object through +0x28b.
/// Its +0x58 vtable slot and embedded array at +0xc0 must obey their
/// notification and observable-element-array contracts. Day numbers must
/// be accepted by the retailOS calendar converter.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn calendar_change_day(view: *mut u32, day: u32) {
    // Do not resolve any dependencies on the unchanged-day path.
    if view.add(DAY).read() == day { return; }
    change_day_with(view, day, day_number_to_datetime(), clear_elements, notify);
}

#[inline(always)]
unsafe fn change_day_with(view: *mut u32, day: u32,
    convert: DayNumberToDateTimeFn, clear: Clear, notify: Notify,
) {
    let old_day = view.add(DAY).read();
    if old_day == day { return; }
    let mut date: DateTime = core::mem::zeroed();
    convert(old_day, &mut date);
    let old_month = date.month;
    let old_weekday = date.weekday;
    view.add(DAY).write(day);
    if view.cast::<u8>().add(0xec).read() != 0 {
        clear(view.add(0xc0 / 4));
    }
    notify(view, 0x36dd);
    convert(view.add(DAY).read(), &mut date);
    if date.weekday != old_weekday { notify(view, 0x36de); }
    if date.month != old_month { notify(view, 0x36df); }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compact calendar model: low byte = weekday, next byte = month.
    unsafe extern "C" fn convert(day: u32, out: *mut DateTime) {
        (*out).weekday = day as u8;
        (*out).month = (day >> 8) as u8;
    }
    unsafe extern "C" fn clear(array: *mut u32) {
        let view = array.sub(0xc0 / 4);
        // Clearing sees the newly published day and destroys cached contents.
        assert_eq!(view.add(DAY).read(), view.add(DAY + 1).read());
        array.add(1).write(0);
    }
    unsafe extern "C" fn record(view: *mut u32, event: u32) {
        let count = view.add(DAY + 2).read() as usize;
        view.add(DAY + 3 + count).write(event);
        view.add(DAY + 2).write(count as u32 + 1);
        if event == 0x36dd && view.add(DAY + 7).read() != 0 {
            view.add(DAY).write(view.add(DAY + 7).read());
        }
    }

    #[test]
    fn changes_only_dependent_fields_and_preserves_notification_order() {
        for (old, new, flag, expected) in [
            (0x0101, 0x0101, 1, &[][..]),
            (0x0101, 0x0102, 0, &[0x36dd, 0x36de][..]),
            (0x0101, 0x0201, 0xff, &[0x36dd, 0x36df][..]),
            (0x0101, 0x0202, 1, &[0x36dd, 0x36de, 0x36df][..]),
            (0x0101, 0x0000, 1, &[0x36dd, 0x36de, 0x36df][..]),
        ] {
            let mut view = [0u32; DAY + 8];
            view[DAY] = old;
            view[DAY + 1] = new;
            view[0xc0 / 4 + 1] = 9;
            view[0xec / 4] = 0xaabbcc00 | flag;
            unsafe { change_day_with(view.as_mut_ptr(), new, convert, clear, record); }
            assert_eq!(view[DAY], new);
            assert_eq!(view[DAY + 2] as usize, expected.len());
            assert_eq!(&view[DAY + 3..DAY + 3 + expected.len()], expected);
            assert_eq!(view[0xc0 / 4 + 1], if old != new && flag != 0 { 0 } else { 9 });
            assert_eq!(view[0xec / 4], 0xaabbcc00 | flag);
        }
    }

    #[test]
    fn reconverts_reentrant_day_not_requested_day() {
        let mut view = [0u32; DAY + 8];
        view[DAY] = 0x0101;
        view[DAY + 7] = 0x0201;
        unsafe { change_day_with(view.as_mut_ptr(), 0x0102, convert, clear, record); }
        assert_eq!(view[DAY], 0x0201);
        assert_eq!(view[DAY + 2], 2);
        assert_eq!(&view[DAY + 3..DAY + 5], &[0x36dd, 0x36df]);
    }

    #[test]
    fn unchanged_day_needs_no_vtable_or_calendar_backend() {
        let mut view = [0u32; DAY + 1];
        view[DAY] = u32::MAX;
        unsafe { calendar_change_day(view.as_mut_ptr(), u32::MAX); }
        assert_eq!(view[DAY], u32::MAX);
    }
}
