//! Advance calendar day — FUN_08126d80 at 0x08126d80, 44 bytes.
//! Raw extent [0x08126d80,0x08126dac) ends before the next PUSH.
//! Verified calls: two plain inbound BLs, zero predicated inbound BLs;
//! body has one plain BL, zero predicated BLs, and one tail B.
//! Add the delta modulo 2^32 to the day at +0x288, change the day through
//! the existing Rust port, then reload it and rebuild calendar elements
//! with mode zero. Reloading preserves reentrant notification changes.
//! Deviations: C ABI call replaces the tail B to the unported refresh
//! helper at 0x08127720; host execution requires an injected backend.

use crate::ui::calendar_change_day::calendar_change_day;

type ChangeDay = unsafe extern "C" fn(*mut u32, u32);
type Refresh = unsafe extern "C" fn(*mut u32, u32, u32);
const DAY: usize = 0x288 / 4;

#[cfg(target_os = "none")]
pub(super) unsafe extern "C" fn refresh_calendar_elements(view: *mut u32, day: u32, mode: u32) {
    core::mem::transmute::<usize, Refresh>(0x0812_7720usize)(view, day, mode)
}

#[cfg(not(target_os = "none"))]
pub(super) unsafe extern "C" fn refresh_calendar_elements(_: *mut u32, _: u32, _: u32) {
    panic!("calendar refresh requires retailOS helper 0x08127720")
}

/// Advance the selected calendar day and rebuild its elements.
///
/// # Safety
/// `view` must satisfy `calendar_change_day`'s contract and be a complete
/// live retailOS calendar object accepted by refresh helper 0x08127720.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn calendar_advance_day(view: *mut u32, delta: u32) {
    advance_day_with(view, delta, calendar_change_day, refresh_calendar_elements);
}

#[inline(always)]
unsafe fn advance_day_with(view: *mut u32, delta: u32, change: ChangeDay, refresh: Refresh) {
    let requested = view.add(DAY).read().wrapping_add(delta);
    change(view, requested);
    refresh(view, view.add(DAY).read(), 0);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Notification model redirects a requested day to another selection.
    unsafe extern "C" fn change(view: *mut u32, requested: u32) {
        view.add(DAY + 1).write(requested);
        view.add(DAY).write(requested.wrapping_add(view.add(DAY + 2).read()));
    }

    // Refresh commits the reloaded selection to the visible calendar state.
    unsafe extern "C" fn refresh(view: *mut u32, day: u32, mode: u32) {
        assert_eq!(mode, 0);
        view.add(DAY + 3).write(day);
        view.add(DAY + 4).write(view.add(DAY + 4).read() + 1);
    }

    #[test]
    fn wraps_forward_backward_and_refreshes_even_without_a_day_change() {
        for (old, delta, expected) in [
            (0, u32::MAX, u32::MAX), (u32::MAX, 1, 0),
            (17, u32::MAX, 16), (17, 0, 17),
            (0x80000000, 0x80000000, 0),
        ] {
            let mut view = [0x12345678u32; DAY + 5];
            view[DAY] = old;
            view[DAY + 2] = 0;
            view[DAY + 4] = 0;
            unsafe { advance_day_with(view.as_mut_ptr(), delta, change, refresh); }
            assert_eq!(view[DAY], expected);
            assert_eq!(view[DAY + 1], expected);
            assert_eq!(view[DAY + 3], expected);
            assert_eq!(view[DAY + 4], 1);
            assert!(view[..DAY].iter().all(|&word| word == 0x12345678));
        }
    }

    #[test]
    fn refresh_uses_reentrant_selection_not_arithmetic_result() {
        let mut view = [0u32; DAY + 5];
        view[DAY] = u32::MAX;
        view[DAY + 2] = 7;
        unsafe { advance_day_with(view.as_mut_ptr(), 1, change, refresh); }
        assert_eq!(view[DAY + 1], 0);
        assert_eq!(view[DAY], 7);
        assert_eq!(view[DAY + 3], 7);
        assert_eq!(view[DAY + 4], 1);
    }
}
