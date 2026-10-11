//! Query and setter for a UI element's three-state navigation mode.
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

/// Query the current mode and whether navigation changes are allowed.
///
/// Original `FUN_08054568` @ `0x08054568`: true extent 92 bytes, comprising
/// 84 instruction bytes and the 'dev '/'tune' literals at 0x080545bc/c0.
/// The next function begins at 0x080545c4. Raw A32 words contain zero outbound
/// plain or predicated BLs; two inbound plain BLs, zero predicated.
/// NULL and excluded kinds clear an optional halfword output and return zero.
/// Otherwise copy +0x184 to the output before testing +0x18d bit 6, returning
/// one when clear. The register-offset LDRH at 0x08054590 reads element+0x184.
/// Deliberate deviations: none; output aliases retain the original ordering.
///
/// # Safety
/// Non-NULL `element` must be word-aligned and readable through +0x19b.
/// Non-NULL `previous` must be halfword-aligned and writable; it may alias
/// element storage, which must then be writable for that halfword.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn query_navigation_mode(element: *mut u8, previous: *mut u16) -> u32 {
    if element.is_null() || matches!(element.add(0x198).cast::<u32>().read(), 0x6465_7620 | 0x7475_6e65) {
        if !previous.is_null() { previous.write(0); }
        return 0;
    }
    if !previous.is_null() { previous.write(element.add(NAVIGATION_MODE_OFFSET).cast::<u16>().read()); }
    (element.add(0x18d).read() & 0x40 == 0) as u32
}

/// The second unported callee's observed ABI. It runs after the mode store;
/// its return is discarded.
pub type ApplyModeChange = unsafe extern "C" fn(*mut u8) -> u32;

/// The tagged-list notification walker's observed ABI.
pub type NotifyModeChange = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32) -> u32;


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
/// Target builds dispatch to the unported callees at `0x0805d31c` and
/// `0x08066bb8`; host tests replace this boundary to observe side effects.
#[derive(Clone, Copy)]
pub struct NavigationModeOps {
    pub apply_mode_change: ApplyModeChange,
    pub notify_mode_change: NotifyModeChange,
}

/// Production dispatch boundary for the unported side-effect callees.
pub const DEFAULT_NAVIGATION_MODE_OPS: NavigationModeOps = NavigationModeOps {
    apply_mode_change: retail_apply_mode_change,
    notify_mode_change: retail_notify_mode_change,
};

/// Active dispatch boundary for the unported notification operations.
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
/// Deliberate deviation: the query uses the Rust port; the two unported
/// side-effect callees use [`NAVIGATION_MODE_OPS`]. Target defaults tail into
/// their stock addresses; host tests install recorders.
///
/// # Safety
///
/// `element` must be word-aligned, readable through +0x19b, and writable at +0x184.
/// When the change proceeds it must also contain a live tagged-handler list
/// at +0x48 for the stock notification walker.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.set_navigation_mode")]
#[inline(never)]
pub unsafe extern "C" fn set_navigation_mode(element: *mut u8, mode: u32) {
    let mut previous = 0u16;
    if query_navigation_mode(element, &mut previous) == 0
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
    static mut APPLY_CALLS: u32 = 0;
    static mut NOTIFY_CALLS: u32 = 0;
    static mut APPLY_ELEMENT: usize = 0;
    static mut NOTIFY_LIST: usize = 0;
    static mut NOTIFY_TAG: u32 = 0;
    static mut NOTIFY_CONTEXT: usize = 0;
    static mut NOTIFY_PREVIOUS: u32 = 0;
    static mut NOTIFY_MODE: u32 = 0;


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

    unsafe fn install_recorders() -> OpsGuard {
        let previous = NAVIGATION_MODE_OPS;
        NAVIGATION_MODE_OPS = NavigationModeOps {
            apply_mode_change: record_apply,
            notify_mode_change: record_notify,
        };
        APPLY_CALLS = 0;
        NOTIFY_CALLS = 0;
        APPLY_ELEMENT = 0;
        NOTIFY_LIST = 0;
        NOTIFY_TAG = 0;
        NOTIFY_CONTEXT = 0;
        NOTIFY_PREVIOUS = 0;
        NOTIFY_MODE = 0;
        OpsGuard(previous)
    }

    /// A word-backed object through the kind word at +0x198.
    fn element_with_mode(mode: u16) -> [u32; 0x19c / 4] {
        let mut element = [0u32; 0x19c / 4];
        unsafe {
            element.as_mut_ptr().cast::<u8>().add(NAVIGATION_MODE_OFFSET).cast::<u16>().write(mode);
        }
        element
    }

    unsafe fn navigation_mode(element: &[u32; 0x19c / 4]) -> u16 {
        element.as_ptr().cast::<u8>().add(NAVIGATION_MODE_OFFSET).cast::<u16>().read()
    }

    #[test]
    fn denied_change_leaves_mode_and_skips_side_effects() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut element = element_with_mode(1);
        unsafe { element.as_mut_ptr().cast::<u8>().add(0x18d).write(0x40); }
        let _ops = unsafe { install_recorders() };

        unsafe { set_navigation_mode(element.as_mut_ptr().cast(), 2) };

        unsafe {
            assert_eq!(navigation_mode(&element), 1);
            assert_eq!((APPLY_CALLS, NOTIFY_CALLS), (0, 0));
        }
    }

    #[test]
    fn invalid_mode_is_queried_but_never_applied() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut element = element_with_mode(1);
        let _ops = unsafe { install_recorders() };

        unsafe { set_navigation_mode(element.as_mut_ptr().cast(), 3) };

        unsafe {
            assert_eq!(navigation_mode(&element), 1);
            assert_eq!((APPLY_CALLS, NOTIFY_CALLS), (0, 0));
        }
    }

    #[test]
    fn equal_mode_is_noop() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut element = element_with_mode(1);
        let _ops = unsafe { install_recorders() };

        unsafe { set_navigation_mode(element.as_mut_ptr().cast(), 1) };

        unsafe {
            assert_eq!(navigation_mode(&element), 1);
            assert_eq!((APPLY_CALLS, NOTIFY_CALLS), (0, 0));
        }
    }

    #[test]
    fn accepted_change_stores_halfword_and_notifies_exactly() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut element = element_with_mode(1);
        let _ops = unsafe { install_recorders() };
        let base = element.as_mut_ptr().cast::<u8>() as usize;

        unsafe { set_navigation_mode(element.as_mut_ptr().cast::<u8>(), 2) };

        unsafe {
            assert_eq!(navigation_mode(&element), 2);
            assert_eq!((APPLY_CALLS, NOTIFY_CALLS), (1, 1));
            assert_eq!(APPLY_ELEMENT, base);
            assert_eq!(NOTIFY_LIST, base + TAGGED_LIST_OFFSET);
            assert_eq!(NOTIFY_TAG, MODE_CHANGED_TAG);
            assert_eq!(NOTIFY_CONTEXT, base);
            assert_eq!(NOTIFY_PREVIOUS, 1);
            assert_eq!(NOTIFY_MODE, 2);
        }
    }

    #[test]
    fn query_excluded_kinds_null_and_optional_output() {
        unsafe {
            let mut output = 0xffff;
            assert_eq!(query_navigation_mode(ptr::null_mut(), &mut output), 0);
            assert_eq!(output, 0);
            assert_eq!(query_navigation_mode(ptr::null_mut(), ptr::null_mut()), 0);
            for kind in [0x6465_7620, 0x7475_6e65] {
                let mut element = element_with_mode(0xffff);
                element[0x198 / 4] = kind;
                output = 0xffff;
                assert_eq!(query_navigation_mode(element.as_mut_ptr().cast(), &mut output), 0);
                assert_eq!(output, 0);
                assert_eq!(query_navigation_mode(element.as_mut_ptr().cast(), ptr::null_mut()), 0);
            }
        }
    }

    #[test]
    fn query_reports_all_halfwords_and_only_bit_six_inhibits() {
        unsafe {
            let mut element = element_with_mode(0);
            let base = element.as_mut_ptr().cast::<u8>();
            for mode in 0..=u16::MAX {
                base.add(0x184).cast::<u16>().write(mode);
                let mut output = !mode;
                assert_eq!(query_navigation_mode(base, &mut output), 1);
                assert_eq!(output, mode);
            }
            for flags in 0..=u8::MAX {
                base.add(0x18d).write(flags);
                let mut output = 0;
                let expected = (flags & 0x40 == 0) as u32;
                assert_eq!(query_navigation_mode(base, &mut output), expected);
                assert_eq!(output, 0xffff);
                assert_eq!(query_navigation_mode(base, ptr::null_mut()), expected);
            }
        }
    }

    #[test]
    fn query_output_alias_changes_inhibit_before_it_is_read() {
        unsafe {
            let mut element = element_with_mode(0);
            let base = element.as_mut_ptr().cast::<u8>();
            base.add(0x18d).write(0x40);
            assert_eq!(query_navigation_mode(base, base.add(0x18c).cast()), 1);
            base.add(0x184).cast::<u16>().write(0x4000);
            assert_eq!(query_navigation_mode(base, base.add(0x18c).cast()), 0);
            assert_eq!(query_navigation_mode(base, base.add(0x184).cast()), 0);
            assert_eq!(navigation_mode(&element), 0x4000);
        }
    }
}
