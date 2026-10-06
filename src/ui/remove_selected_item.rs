//! Remove the selected UI collection item — `FUN_0815dcb8` @ 0x0815dcb8.
//! True extent: 140 bytes, 0x0815dcb8..0x0815dd44 (132 instruction bytes,
//! eight literal bytes). The next entry is independently called. Whole-image
//! A32 decoding finds two inbound plain BLs, no predicated BLs. The body has
//! two plain BLs, one BLNE and one virtual BLX through +0x58.
//!
//! Negative selection returns immediately. Selection zero with nonzero +0x48
//! invokes verified retail reset entry 0x0815e634 with mode zero. Reload the
//! selection, release/erase from the embedded array at +0x30, then reload count
//! and selection: empty sets -1, selection equal to count decrements, otherwise
//! preserve it. Dispatch ('VMax', 0x568a) before setting byte +0x98 to one.
//! Deliberate deviations: the unported reset remains a retail-address seam;
//! host seams model reset/erase effects because embedded target fields cannot
//! contain the existing array port's widened host layout. Hosts use native
//! vtable pointers/slots; all other fields retain target word indices. No
//! class identity or meaning for the resource code is asserted.

use super::nonzero_flags::ui_element_has_nonzero_flags;

pub type ResetSelection = unsafe extern "C" fn(*mut u32, u32) -> u32;
pub type EraseSelection = unsafe extern "C" fn(*mut u32, i32) -> i32;
pub type NotifySelection = unsafe extern "C" fn(*mut u32, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_reset(_: *mut u32, _: u32) -> u32 {
    panic!("selection reset requires retail entry 0x0815e634")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_erase(_: *mut u32, _: i32) -> i32 {
    panic!("embedded selection array requires a host model")
}
#[cfg(not(target_os = "none"))]
pub static mut SELECTION_RESET: ResetSelection = missing_reset;
#[cfg(not(target_os = "none"))]
pub static mut SELECTION_ERASE: EraseSelection = missing_erase;

/// # Safety
/// `element` must be aligned and readable at +0x80. A nonnegative selection
/// requires a complete writable element through +0x98, a valid embedded array
/// and reset contract, and callable vtable slot +0x58. Callbacks may mutate it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_collection_remove_selected_item(element: *mut u32) {
    let selected = element.add(0x80 / 4).read() as i32;
    if selected < 0 { return; }
    if selected == 0 && ui_element_has_nonzero_flags(element.cast()) != 0 {
        #[cfg(target_os = "none")]
        {
            let reset: ResetSelection = core::mem::transmute(0x0815_e634usize);
            reset(element, 0);
        }
        #[cfg(not(target_os = "none"))]
        core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_RESET))(element, 0);
    }
    let selected = element.add(0x80 / 4).read() as i32;
    #[cfg(target_os = "none")]
    crate::cxx::opaque_observable_array_release_erase_at::opaque_observable_array_release_erase_at(
        element.add(0x30 / 4).cast(), selected);
    #[cfg(not(target_os = "none"))]
    core::ptr::read_volatile(core::ptr::addr_of!(SELECTION_ERASE))(element.add(0x30 / 4), selected);
    let count = element.add(0x34 / 4).read();
    if count == 0 {
        element.add(0x80 / 4).write(u32::MAX);
    } else {
        let selected = element.add(0x80 / 4).read();
        if count == selected { element.add(0x80 / 4).write(selected.wrapping_sub(1)); }
    }
    #[cfg(target_os = "none")]
    let notify: NotifySelection = {
        let vtable = element.read() as *const u32;
        core::mem::transmute(vtable.add(0x58 / 4).read())
    };
    #[cfg(not(target_os = "none"))]
    let notify = element.cast::<*const NotifySelection>().read().add(0x58 / 4).read();
    notify(element, 0x564d_6178, 0x568a);
    element.cast::<u8>().add(0x98).write(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    #[repr(C, align(8))]
    struct Element([u32; 40]);
    static mut PHASE: u32 = 0;
    static mut RESET_EXPECTED: bool = false;
    static mut ERASE_INDEX: i32 = 0;
    static mut AFTER_COUNT: u32 = 0;
    static mut AFTER_INDEX: u32 = 0;
    static mut NOTIFIED_INDEX: u32 = 0;
    static mut TABLE: *const NotifySelection = core::ptr::null();
    unsafe extern "C" fn reset(element: *mut u32, mode: u32) -> u32 {
        assert!(RESET_EXPECTED);
        assert_eq!((PHASE, mode), (0, 0));
        element.add(32).write(2); // Reset callbacks may change selection.
        PHASE = 1;
        1 // Ignored by the caller.
    }
    unsafe extern "C" fn erase(array: *mut u32, index: i32) -> i32 {
        assert_eq!(PHASE, RESET_EXPECTED as u32);
        assert_eq!(index, ERASE_INDEX);
        let element = array.sub(12);
        array.add(1).write(AFTER_COUNT);
        element.add(32).write(AFTER_INDEX);
        element.cast::<*const NotifySelection>().write(TABLE);
        PHASE = 2;
        -1 // Failure-like return does not suppress notification.
    }
    unsafe extern "C" fn stale(_: *mut u32, _: u32, _: u32) {
        panic!("stale vtable used after erase")
    }
    unsafe extern "C" fn notify(element: *mut u32, action: u32, resource: u32) {
        assert_eq!(PHASE, 2);
        assert_eq!((action, resource), (0x564d6178, 0x568a));
        assert_eq!(element.add(32).read(), NOTIFIED_INDEX);
        assert_eq!(element.cast::<u8>().add(0x98).read(), 0x5a);
        PHASE = 3;
    }
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            SELECTION_RESET = missing_reset;
            SELECTION_ERASE = missing_erase;
            TABLE = core::ptr::null();
        } }
    }
    #[test]
    fn removal_reloads_callback_state_and_marks_dirty_after_notification() {
        let _lock = LOCK.lock();
        let _restore = Restore;
        let old = [stale as NotifySelection; 23];
        let new = [notify as NotifySelection; 23];
        unsafe {
            SELECTION_RESET = reset;
            SELECTION_ERASE = erase;
            TABLE = new.as_ptr();
            // Initial index, flags, post-erase count/index, expected selection.
            for (initial, flags, count, after, expected) in [
                (0, 0x80000000, 3, 3, 2),
                (0, 0, 0, 0, u32::MAX),
                (4, 1, 4, 4, 3),
                (2, 0, 5, 2, 2),
                (1, 1, 0x80000000, 0x80000000, 0x7fffffff),
                (1, 1, 3, u32::MAX, u32::MAX),
            ] {
                let mut element = Element([0x5a5a5a5a; 40]);
                let p = element.0.as_mut_ptr();
                p.cast::<*const NotifySelection>().write(old.as_ptr());
                p.add(18).write(flags);
                p.add(32).write(initial);
                PHASE = 0;
                RESET_EXPECTED = initial == 0 && flags != 0;
                ERASE_INDEX = if RESET_EXPECTED { 2 } else { initial as i32 };
                AFTER_COUNT = count;
                AFTER_INDEX = after;
                NOTIFIED_INDEX = expected;
                ui_collection_remove_selected_item(p);
                assert_eq!(PHASE, 3);
                assert_eq!(p.add(32).read(), expected);
                assert_eq!(p.add(38).read(), 0x5a5a5a01);
                assert_eq!(p.add(39).read(), 0x5a5a5a5a);
            }
        }
    }
    #[test]
    fn negative_selection_has_no_side_effects_or_vtable_access() {
        let _lock = LOCK.lock();
        for index in [u32::MAX, 0x80000000, 0xfffffff0] {
            let mut element = Element([0; 40]);
            element.0[32] = index;
            let before = element.0;
            unsafe { ui_collection_remove_selected_item(element.0.as_mut_ptr()); }
            assert_eq!(element.0, before);
        }
    }
}
