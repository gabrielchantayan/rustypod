//! Refresh a calendar day and notify — FUN_081268dc at 0x081268dc.
//! True extent: 52 bytes [0x081268dc,0x08126910): 44 code bytes and 8 literal
//! bytes. Verified two plain inbound BLs, zero predicated inbound BLs;
//! body contains one plain BL, zero predicated BLs, and a virtual tail BX.
//! Refresh calendar elements with (view, day, 1), then reload the object's
//! vtable and dispatch slot +0x58 with (view, 0x53747220, 0x36df).
//! Deviations: reuse the verified retailOS refresh backend; host tests inject
//! it. Native-width vtable slots preserve the 32-bit target layout while
//! allowing native host fixtures. LLVM may use a call rather than tail BX.

use super::calendar_advance_day::refresh_calendar_elements;

type Refresh = unsafe extern "C" fn(*mut u32, u32, u32);
type Notify = unsafe extern "C" fn(*mut u32, u32, u32);
const NOTIFY_SLOT: usize = 0x58 / 4;

/// Refresh the selected day, then send the calendar string notification.
///
/// # Safety
/// `view` must be a complete live calendar object accepted by 0x08127720.
/// Its first field must point to a vtable with a valid C ABI method in slot 22;
/// the refresh backend may replace that vtable but must leave `view` alive.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refresh_calendar_day_and_notify(view: *mut u32, day: u32) {
    refresh_and_notify_with(view, day, refresh_calendar_elements);
}

#[inline(always)]
unsafe fn refresh_and_notify_with(view: *mut u32, day: u32, refresh: Refresh) {
    refresh(view, day, 1);
    let vtable = view.cast::<*const usize>().read();
    let notify: Notify = core::mem::transmute(vtable.add(NOTIFY_SLOT).read());
    notify(view, 0x5374_7220, 0x36df);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct View {
        vtable: *const usize,
        replacement: *const usize,
        selected: u32,
        visible: u32,
        notifications: u32,
    }

    unsafe extern "C" fn refresh(view: *mut u32, day: u32, mode: u32) {
        assert_eq!(mode, 1);
        let view = &mut *view.cast::<View>();
        view.selected = day;
        view.vtable = view.replacement;
    }

    unsafe extern "C" fn notify(view: *mut u32, kind: u32, resource: u32) {
        assert_eq!((kind, resource), (0x53747220, 0x36df));
        let view = &mut *view.cast::<View>();
        view.visible = view.selected;
        view.notifications += 1;
    }

    #[test]
    fn refresh_replaces_vtable_before_dispatch_and_preserves_full_day() {
        let mut table = [0usize; NOTIFY_SLOT + 1];
        table[NOTIFY_SLOT] = notify as *const () as usize;
        // The old vtable is deliberately null: dispatch must reload it.
        let mut view = View { vtable: core::ptr::null(), replacement: table.as_ptr(),
            selected: 99, visible: 99, notifications: 0 };
        for (index, day) in [0, 733773, 0x80000000, u32::MAX, u32::MAX].into_iter().enumerate() {
            unsafe { refresh_and_notify_with((&mut view as *mut View).cast(), day, refresh); }
            assert_eq!(view.visible, day);
            assert_eq!(view.selected, day);
            assert_eq!(view.notifications, index as u32 + 1);
            view.vtable = core::ptr::null();
        }
    }
}
