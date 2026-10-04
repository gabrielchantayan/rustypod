//! Bind the application singleton state before applying a view's staged flags.
//!
//! Original: `FUN_08212b40` @ 0x08212b40, exactly 136 bytes; next real
//! function starts at 0x08212bc8. Raw ARM decoding verifies two incoming
//! plain BLs, zero predicated BLs, and two incoming plain tail branches.
//! The body has one plain BL, zero predicated BLs, four register BLX sites,
//! and a tail B to 0x0810de48.
//!
//! Passes the singleton base to view vtable slot +0xc0, obtains the related
//! object through +0xc4, and queries its +0xa4 slot. When that query is
//! nonzero, a zero event invokes view slot +0xb8 with 0x10; a nonzero event
//! instead skips flag application if byte +0xb4 is nonzero. All other paths
//! apply mapped staged flags. Every path returns the handled verdict, 1.
//! Concrete virtual-method identities remain unknown; names describe only
//! the observed operations. Deliberate deviations: call the existing Rust
//! singleton accessor and mapped-flag handler directly (the latter ignores
//! the original dead forwarded r1). Host vtables use native pointer words;
//! target vtable entries remain four bytes apart. No new firmware seam.

use super::singleton_state::singleton_state_base_get;
use super::view_event::{view_event_apply_mapped_staged_flags, EVENT_HANDLED};

unsafe fn virtual_slot(object: *mut u8, byte_offset: usize) -> usize {
    let table = unsafe { (object as *const *const usize).read() };
    unsafe { table.add(byte_offset / 4).read() }
}

/// # Safety
/// `view` must be valid through byte +0xb4 and for the staged-flag helper.
/// Its vtable must provide +0xb8, +0xc0 and +0xc4 with the signatures below;
/// +0xc4 must return a valid object with a unary u32 query at vtable +0xa4.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_event_bind_state(view: *mut u8, event: u32) -> u32 {
    let state = unsafe { singleton_state_base_get() };
    let bind: unsafe extern "C" fn(*mut u8, *mut u8) =
        unsafe { core::mem::transmute(virtual_slot(view, 0xc0)) };
    unsafe { bind(view, state) };
    let related_get: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        unsafe { core::mem::transmute(virtual_slot(view, 0xc4)) };
    let related = unsafe { related_get(view) };
    let query: unsafe extern "C" fn(*mut u8) -> u32 =
        unsafe { core::mem::transmute(virtual_slot(related, 0xa4)) };
    if unsafe { query(related) } != 0 {
        if event == 0 {
            let notify: unsafe extern "C" fn(*mut u8, u32) =
                unsafe { core::mem::transmute(virtual_slot(view, 0xb8)) };
            unsafe { notify(view, 0x10) };
        } else if unsafe { view.add(0xb4).read() } != 0 {
            return EVENT_HANDLED;
        }
    }
    unsafe { view_event_apply_mapped_staged_flags(view) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::view_event::{ViewEventOps, VIEW_EVENT_OPS};
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;
    use std::vec::Vec;

    static TRACE: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    #[repr(C)]
    struct Related {
        table: *const usize,
        answer: u32,
    }

    #[repr(C)]
    struct View {
        table: *const usize,
        bytes: [u8; 0xb8],
        related: *mut Related,
        rebound_table: *const usize,
    }

    unsafe extern "C" fn bind(view: *mut u8, _state: *mut u8) {
        TRACE.lock().push(1);
        // The callback may change the vtable: the following dispatch must
        // reload it, as the original does after every virtual call.
        let view = unsafe { &mut *(view as *mut View) };
        view.table = view.rebound_table;
    }
    unsafe extern "C" fn related_get(view: *mut u8) -> *mut u8 {
        TRACE.lock().push(2);
        unsafe { (*(view as *mut View)).related as *mut u8 }
    }
    unsafe extern "C" fn query(related: *mut u8) -> u32 {
        TRACE.lock().push(3);
        unsafe { (*(related as *mut Related)).answer }
    }
    unsafe extern "C" fn notify(_view: *mut u8, code: u32) {
        TRACE.lock().push(code);
    }
    unsafe extern "C" fn apply(_view: *mut u8) {
        TRACE.lock().push(4);
    }
    struct Restore(ViewEventOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { addr_of_mut!(VIEW_EVENT_OPS).write(self.0) };
        }
    }

    #[test]
    fn query_event_and_flag_control_notification_and_flag_application() {
        let _view_lock = crate::testing::VIEW_EVENT_OPS_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        let _singleton_lock = super::super::singleton_state::tests::ACCESS_TEST_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        let _restore = Restore(unsafe { addr_of!(VIEW_EVENT_OPS).read() });
        unsafe { VIEW_EVENT_OPS.apply_mapped_staged_flags = apply };
        let mut initial_table = [0usize; 50];
        initial_table[0xc0 / 4] = bind as *const () as usize;
        let mut rebound_table = [0usize; 50];
        rebound_table[0xc4 / 4] = related_get as *const () as usize;
        rebound_table[0xb8 / 4] = notify as *const () as usize;
        let mut related_table = [0usize; 42];
        related_table[0xa4 / 4] = query as *const () as usize;
        let mut related = Related { table: related_table.as_ptr(), answer: 0 };
        for answer in [0, 1, 0x8000_0000, u32::MAX] {
            for event in [0, 1, 0x8000_0000, u32::MAX] {
                for flag in [0, 1, 0x80, 0xff] {
                    related.answer = answer;
                    let mut view = View {
                        table: initial_table.as_ptr(), bytes: [0; 0xb8],
                        related: &mut related, rebound_table: rebound_table.as_ptr(),
                    };
                    let view_ptr = &mut view as *mut View as *mut u8;
                    unsafe { view_ptr.add(0xb4).write(flag) };
                    TRACE.lock().clear();
                    assert_eq!(unsafe { view_event_bind_state(view_ptr, event) }, 1);
                    let mut expected = std::vec![1, 2, 3];
                    if answer != 0 && event == 0 { expected.push(0x10); }
                    if !(answer != 0 && event != 0 && flag != 0) { expected.push(4); }
                    assert_eq!(*TRACE.lock(), expected,
                        "answer={answer:#x}, event={event:#x}, flag={flag:#x}");
                    assert_eq!(unsafe { view_ptr.add(0xb4).read() }, flag);
                }
            }
        }
    }
}
