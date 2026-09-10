//! Setter for a UI element's three-state navigation mode.
//!
//! - `set_navigation_mode` — original: `FUN_08067300` @ `0x08067300`
//!   (100 bytes: 96 bytes of instructions plus the literal-pool word at
//!   `0x08067360`; 11 unconditional `bl` callers and no predicated calls).

use core::ptr;

/// Byte offset of the tagged-handler list passed to the notification walker.
const TAGGED_LIST_OFFSET: usize = 0x48;

/// Byte offset of this object's halfword navigation mode.
const NAVIGATION_MODE_OFFSET: usize = 0x184;

/// Literal-pool word at `0x08067360`, supplied to the notification walker.
/// Its semantic tag identity is not recovered.
const MODE_CHANGED_TAG: u32 = 0x6370_726d;

/// The first unported callee's observed ABI: it reports whether this object
/// may change modes and, when so, writes the current mode through `previous`.
pub type QueryModeChange = unsafe extern "C" fn(*mut u8, *mut u16) -> u32;

/// The second unported callee's observed ABI. It runs after the mode store;
/// its return is discarded.
pub type ApplyModeChange = unsafe extern "C" fn(*mut u8) -> u32;

/// The tagged-list notification walker's observed ABI.
pub type NotifyModeChange = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_query_mode_change(element: *mut u8, previous: *mut u16) -> u32 {
    let query: QueryModeChange = core::mem::transmute(0x0805_4568usize);
    query(element, previous)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_query_mode_change(_element: *mut u8, previous: *mut u16) -> u32 {
    previous.write(0);
    0
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_apply_mode_change(element: *mut u8) -> u32 {
    let apply: ApplyModeChange = core::mem::transmute(0x0805_d31cusize);
    apply(element)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_apply_mode_change(_element: *mut u8) -> u32 {
    0
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_notify_mode_change(
    list: *mut u8,
    tag: u32,
    context: *mut u8,
    previous: u32,
    mode: u32,
) -> u32 {
    let notify: NotifyModeChange = core::mem::transmute(0x0806_6bb8usize);
    notify(list, tag, context, previous, mode)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_notify_mode_change(
    _list: *mut u8,
    _tag: u32,
    _context: *mut u8,
    _previous: u32,
    _mode: u32,
) -> u32 {
    0
}

/// Calls outside this one-function port.
///
/// Target builds dispatch to the three unported callees at `0x08054568`,
/// `0x0805d31c`, and `0x08066bb8`; host tests replace this boundary to
/// observe the retail call sequence.
#[derive(Clone, Copy)]
pub struct NavigationModeOps {
    pub query_mode_change: QueryModeChange,
    pub apply_mode_change: ApplyModeChange,
    pub notify_mode_change: NotifyModeChange,
}

/// Production dispatch boundary for the unported callees.
pub const DEFAULT_NAVIGATION_MODE_OPS: NavigationModeOps = NavigationModeOps {
    query_mode_change: retail_query_mode_change,
    apply_mode_change: retail_apply_mode_change,
    notify_mode_change: retail_notify_mode_change,
};

/// Active dispatch boundary for the unported mode and notification operations.
pub static mut NAVIGATION_MODE_OPS: NavigationModeOps = DEFAULT_NAVIGATION_MODE_OPS;

#[inline(always)]
fn navigation_mode_ops() -> NavigationModeOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(NAVIGATION_MODE_OPS)) }
}

/// set_navigation_mode — original: `FUN_08067300` @ `0x08067300` (100 bytes).
///
/// Raw ARM spans `0x08067300..0x08067364`: its 96 instruction bytes end in
/// `pop {r2,r3,r4,r5,r6,pc}` at `0x0806735c`; the following literal-pool word
/// `0x6370726d` at `0x08067360` is referenced by the preceding `ldr`, and the
/// next separately linked function begins at `0x08067364`. Decoding every ARM
/// B/BL word in `osos.dec` finds 11 direct callers, all unconditional `bl`:
/// none is predicated.
///
/// It asks `0x08054568` whether `element` may change modes, obtaining the
/// prior halfword through its out-pointer. Only requested modes 0, 1, and 2
/// are accepted, and a request equal to that reported prior mode is a no-op.
/// On a real change it writes the low halfword to +0x184, invokes
/// `0x0805d31c`, then walks the tagged list at +0x48 through `0x08066bb8`
/// with literal tag `0x6370726d`, `(element, prior_mode, mode)` as context /
/// arguments. All callee results are discarded.
///
/// Deliberate deviation: none of those three callees has a `ported` ledger
/// entry, so the calls use [`NAVIGATION_MODE_OPS`]. Target defaults tail into
/// their stock addresses; host tests install recorders.
///
/// # Safety
///
/// `element` must be non-NULL and writable as an aligned `u16` at +0x184.
/// When the change proceeds it must also contain a live tagged-handler list
/// at +0x48 for the stock notification walker.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.set_navigation_mode")]
#[inline(never)]
pub unsafe extern "C" fn set_navigation_mode(element: *mut u8, mode: u32) {
    let mut previous = 0u16;
    if (navigation_mode_ops().query_mode_change)(element, &mut previous) == 0
        || mode > 2
        || mode == u32::from(previous)
    {
        return;
    }

    element.add(NAVIGATION_MODE_OFFSET).cast::<u16>().write(mode as u16);
    (navigation_mode_ops().apply_mode_change)(element);
    (navigation_mode_ops().notify_mode_change)(
        element.add(TAGGED_LIST_OFFSET),
        MODE_CHANGED_TAG,
        element,
        u32::from(previous),
        mode,
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CHANGE_ALLOWED: u32 = 0;
    static mut REPORTED_MODE: u16 = 0;
    static mut QUERY_CALLS: u32 = 0;
    static mut APPLY_CALLS: u32 = 0;
    static mut NOTIFY_CALLS: u32 = 0;
    static mut QUERY_ELEMENT: usize = 0;
    static mut APPLY_ELEMENT: usize = 0;
    static mut NOTIFY_LIST: usize = 0;
    static mut NOTIFY_TAG: u32 = 0;
    static mut NOTIFY_CONTEXT: usize = 0;
    static mut NOTIFY_PREVIOUS: u32 = 0;
    static mut NOTIFY_MODE: u32 = 0;

    unsafe extern "C" fn record_query(element: *mut u8, previous: *mut u16) -> u32 {
        QUERY_CALLS += 1;
        QUERY_ELEMENT = element as usize;
        previous.write(REPORTED_MODE);
        CHANGE_ALLOWED
    }

    unsafe extern "C" fn record_apply(element: *mut u8) -> u32 {
        APPLY_CALLS += 1;
        APPLY_ELEMENT = element as usize;
        0
    }

    unsafe extern "C" fn record_notify(
        list: *mut u8,
        tag: u32,
        context: *mut u8,
        previous: u32,
        mode: u32,
    ) -> u32 {
        NOTIFY_CALLS += 1;
        NOTIFY_LIST = list as usize;
        NOTIFY_TAG = tag;
        NOTIFY_CONTEXT = context as usize;
        NOTIFY_PREVIOUS = previous;
        NOTIFY_MODE = mode;
        0
    }

    struct OpsGuard(NavigationModeOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { NAVIGATION_MODE_OPS = self.0 };
        }
    }

    unsafe fn install_recorders(change_allowed: u32, reported_mode: u16) -> OpsGuard {
        let previous = NAVIGATION_MODE_OPS;
        NAVIGATION_MODE_OPS = NavigationModeOps {
            query_mode_change: record_query,
            apply_mode_change: record_apply,
            notify_mode_change: record_notify,
        };
        CHANGE_ALLOWED = change_allowed;
        REPORTED_MODE = reported_mode;
        QUERY_CALLS = 0;
        APPLY_CALLS = 0;
        NOTIFY_CALLS = 0;
        QUERY_ELEMENT = 0;
        APPLY_ELEMENT = 0;
        NOTIFY_LIST = 0;
        NOTIFY_TAG = 0;
        NOTIFY_CONTEXT = 0;
        NOTIFY_PREVIOUS = 0;
        NOTIFY_MODE = 0;
        OpsGuard(previous)
    }

    /// A word-backed object through the mode halfword at +0x184.
    fn element_with_mode(mode: u16) -> [u32; NAVIGATION_MODE_OFFSET / 4 + 1] {
        let mut element = [0u32; NAVIGATION_MODE_OFFSET / 4 + 1];
        unsafe {
            element.as_mut_ptr().cast::<u8>().add(NAVIGATION_MODE_OFFSET).cast::<u16>().write(mode);
        }
        element
    }

    unsafe fn navigation_mode(element: &[u32; NAVIGATION_MODE_OFFSET / 4 + 1]) -> u16 {
        element.as_ptr().cast::<u8>().add(NAVIGATION_MODE_OFFSET).cast::<u16>().read()
    }

    #[test]
    fn denied_change_leaves_mode_and_skips_side_effects() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = element_with_mode(1);
        let _ops = unsafe { install_recorders(0, 1) };

        unsafe { set_navigation_mode(element.as_ptr() as *mut u8, 2) };

        unsafe {
            assert_eq!(navigation_mode(&element), 1);
            assert_eq!((QUERY_CALLS, APPLY_CALLS, NOTIFY_CALLS), (1, 0, 0));
        }
    }

    #[test]
    fn invalid_mode_is_queried_but_never_applied() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = element_with_mode(1);
        let _ops = unsafe { install_recorders(1, 1) };

        unsafe { set_navigation_mode(element.as_ptr() as *mut u8, 3) };

        unsafe {
            assert_eq!(navigation_mode(&element), 1);
            assert_eq!((QUERY_CALLS, APPLY_CALLS, NOTIFY_CALLS), (1, 0, 0));
        }
    }

    #[test]
    fn reported_equal_mode_is_noop_even_if_storage_differs() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = element_with_mode(2);
        let _ops = unsafe { install_recorders(1, 1) };

        unsafe { set_navigation_mode(element.as_ptr() as *mut u8, 1) };

        unsafe {
            assert_eq!(navigation_mode(&element), 2);
            assert_eq!((QUERY_CALLS, APPLY_CALLS, NOTIFY_CALLS), (1, 0, 0));
        }
    }

    #[test]
    fn accepted_change_stores_halfword_and_notifies_exactly() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut element = element_with_mode(1);
        let _ops = unsafe { install_recorders(1, 1) };
        let base = element.as_mut_ptr().cast::<u8>() as usize;

        unsafe { set_navigation_mode(element.as_mut_ptr().cast::<u8>(), 2) };

        unsafe {
            assert_eq!(navigation_mode(&element), 2);
            assert_eq!((QUERY_CALLS, APPLY_CALLS, NOTIFY_CALLS), (1, 1, 1));
            assert_eq!(QUERY_ELEMENT, base);
            assert_eq!(APPLY_ELEMENT, base);
            assert_eq!(NOTIFY_LIST, base + TAGGED_LIST_OFFSET);
            assert_eq!(NOTIFY_TAG, MODE_CHANGED_TAG);
            assert_eq!(NOTIFY_CONTEXT, base);
            assert_eq!(NOTIFY_PREVIOUS, 1);
            assert_eq!(NOTIFY_MODE, 2);
        }
    }
}
