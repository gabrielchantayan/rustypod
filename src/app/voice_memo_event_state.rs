//! Voice-memo event state application — FUN_081a40e4 @ 0x081a40e4.
//!
//! True extent: 200 bytes, 0x081a40e4..0x081a41ac; the next function
//! starts with LDR at 0x081a41ac. Raw aligned A32 decoding verifies two
//! inbound plain BLs, zero predicated BLs; seven outgoing plain BLs,
//! zero predicated BLs, three virtual BLX sites and one virtual tail BX.
//!
//! Ignore event states other than 0/1. State 1 with a nonzero source applies
//! 1 directly. With source zero, query vtable +0x38 and apply 0 when nonzero,
//! otherwise 255. State 0 with source zero uses the same query, applying
//! 1 when nonzero, otherwise 255. State 0 with nonzero source requests 1
//! through +0x3c; only a zero result causes application of 0 through +0x44.
//! Each operation obtains the singleton anew, including after a query.
//!
//! Deviations: typed repr(C) vtable fields scale naturally on hosts while
//! retaining target word offsets. Slot identities beyond the observed state
//! protocol remain unknown. The getter reuses lazy_singleton_0xbc, including
//! its documented NOT-HOOK-READY constructor/cache deviations; host tests
//! replace only that getter. The unused context argument is retained.

#[repr(C)]
pub struct EventStateVtable {
    pub preceding_slots: [usize; 14],
    pub query_state: unsafe extern "C" fn(*mut EventStateController) -> u32,
    pub request_state: unsafe extern "C" fn(*mut EventStateController, u32) -> u32,
    pub slot_40: usize,
    pub apply_state: unsafe extern "C" fn(*mut EventStateController, u32),
}

#[repr(C)]
pub struct EventStateController {
    pub vtable: *const EventStateVtable,
}

#[cfg(target_os = "none")]
unsafe fn controller_get() -> *mut EventStateController {
    super::singletons::lazy_singleton_0xbc().cast()
}
#[cfg(not(target_os = "none"))]
unsafe fn controller_get() -> *mut EventStateController {
    (core::ptr::addr_of!(HOST_EVENT_STATE_GET).read_volatile())()
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_controller() -> *mut EventStateController {
    panic!("missing event state controller")
}
#[cfg(not(target_os = "none"))]
pub static mut HOST_EVENT_STATE_GET: unsafe extern "C" fn() -> *mut EventStateController = missing_controller;

/// # Safety
/// The singleton must expose valid virtual operations at +0x38/+0x3c/+0x44.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn voice_memo_event_state_apply(_context: *mut u8, event_state: u32, source: u32) {
    let next_state = match (event_state, source != 0) {
        (1, true) => 1,
        (0, true) => {
            let controller = controller_get();
            if ((*(*controller).vtable).request_state)(controller, 1) != 0 { return; }
            0
        }
        (state @ 0..=1, false) => {
            let controller = controller_get();
            if ((*(*controller).vtable).query_state)(controller) == 0 { 255 } else { 1 - state }
        }
        _ => return,
    };
    let controller = controller_get();
    ((*(*controller).vtable).apply_state)(controller, next_state);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut RESULT: u32 = 0;
    static mut GETS: usize = 0;
    static mut LOG: std::vec::Vec<(u32, u32)> = std::vec::Vec::new();
    static VTABLE: EventStateVtable = EventStateVtable {
        preceding_slots: [0; 14], query_state: query, request_state: request,
        slot_40: 0, apply_state: apply,
    };
    static mut FIRST: EventStateController = EventStateController { vtable: &VTABLE };
    static mut SECOND: EventStateController = EventStateController { vtable: &VTABLE };
    unsafe extern "C" fn get() -> *mut EventStateController {
        GETS += 1;
        if GETS == 1 { core::ptr::addr_of_mut!(FIRST) } else { core::ptr::addr_of_mut!(SECOND) }
    }
    unsafe extern "C" fn query(controller: *mut EventStateController) -> u32 {
        assert_eq!(controller, core::ptr::addr_of_mut!(FIRST));
        (*core::ptr::addr_of_mut!(LOG)).push((38, 0));
        RESULT
    }
    unsafe extern "C" fn request(controller: *mut EventStateController, state: u32) -> u32 {
        assert_eq!(controller, core::ptr::addr_of_mut!(FIRST));
        (*core::ptr::addr_of_mut!(LOG)).push((60, state));
        RESULT
    }
    unsafe extern "C" fn apply(controller: *mut EventStateController, state: u32) {
        assert_eq!(controller, if GETS == 1 { core::ptr::addr_of_mut!(FIRST) } else { core::ptr::addr_of_mut!(SECOND) });
        (*core::ptr::addr_of_mut!(LOG)).push((68, state));
    }
    struct Restore(unsafe extern "C" fn() -> *mut EventStateController);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { HOST_EVENT_STATE_GET = self.0; } }
    }
    #[test]
    fn event_truth_table_and_fresh_controller_after_query() {
        let _lock = LOCK.lock();
        unsafe {
            let _restore = Restore(core::ptr::addr_of!(HOST_EVENT_STATE_GET).read());
            HOST_EVENT_STATE_GET = get;
            for event in [0, 1, 2, u32::MAX] {
                for source in [0, 1, u32::MAX] {
                    for result in [0, 1, u32::MAX] {
                        RESULT = result;
                        GETS = 0;
                        (*core::ptr::addr_of_mut!(LOG)).clear();
                        voice_memo_event_state_apply(core::ptr::null_mut(), event, source);
                        let expected = match (event, source != 0, result != 0) {
                            (1, true, _) => std::vec![(68, 1)],
                            (0, true, true) => std::vec![(60, 1)],
                            (0, true, false) => std::vec![(60, 1), (68, 0)],
                            (0, false, true) => std::vec![(38, 0), (68, 1)],
                            (1, false, true) => std::vec![(38, 0), (68, 0)],
                            (0 | 1, false, false) => std::vec![(38, 0), (68, 255)],
                            _ => std::vec![],
                        };
                        assert_eq!(&*core::ptr::addr_of!(LOG), &expected, "event={event} source={source} result={result}");
                        assert_eq!(core::ptr::addr_of!(GETS).read(), expected.len());
                    }
                }
            }
        }
    }
}
