//! 'plst' UI-element teardown notification.
//!
//! - `plst_element_notify_teardown` — original: `FUN_08061378` @
//!   `0x08061378` (60 bytes including the event-key literal at `0x080613b0`;
//!   Ghidra reports 56 instruction bytes). Verified call count: 11 direct
//!   `bl` calls — 6 unconditional, 4 `blne`, and 1 `bleq`.

use core::ptr;

use super::plst_class_check::ui_element_is_plst_class;

/// Byte offset of the tagged-handler list passed to `0x08066bb8`
/// (`add r0, r4, #0x48`).
const TAGGED_LIST_OFFSET: usize = 0x48;

/// Teardown event key from the original's literal pool at `0x080613b0`.
/// Its semantic name is not recovered; preserve the raw FourCC word.
const TEARDOWN_NOTIFY_TAG: u32 = 0x6370_6c64;

/// ABI of the still-unported tagged-handler list walker at `0x08066bb8`.
pub type PlstTeardownNotify = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_plst_teardown_notify(
    list: *mut u8,
    tag: u32,
    context: *mut u8,
    flags: u32,
    stack_arg: u32,
) {
    let notify: PlstTeardownNotify = core::mem::transmute(0x0806_6bb8usize);
    notify(list, tag, context, flags, stack_arg)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_plst_teardown_notify(
    _list: *mut u8,
    _tag: u32,
    _context: *mut u8,
    _flags: u32,
    _stack_arg: u32,
) {}

/// Calls outside this one-function port.
///
/// The target build reaches the stock tagged-handler list walker. Host tests
/// replace the boundary to observe its exact ABI.
#[derive(Clone, Copy)]
pub struct PlstElementTeardownOps {
    pub tagged_list_notify: PlstTeardownNotify,
}

/// Production dispatch boundary for the unported list walker.
pub const DEFAULT_PLST_ELEMENT_TEARDOWN_OPS: PlstElementTeardownOps = PlstElementTeardownOps {
    tagged_list_notify: retail_plst_teardown_notify,
};

/// Active dispatch boundary for `0x08066bb8`.
///
/// `names.yaml` has no `ported` entry for the walker, so this seam retains the
/// stock target call without claiming its implementation.
pub static mut PLST_ELEMENT_TEARDOWN_OPS: PlstElementTeardownOps =
    DEFAULT_PLST_ELEMENT_TEARDOWN_OPS;

#[inline(always)]
fn plst_element_teardown_ops() -> PlstElementTeardownOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(PLST_ELEMENT_TEARDOWN_OPS)) }
}

/// plst_element_notify_teardown — original: `FUN_08061378` @ `0x08061378`
/// (60 bytes).
///
/// Assembly decoded from `work/firmware/osos.dec` @
/// `0x08061378..0x080613b4`:
///
/// ```text
/// 08061378  push {r3, r4, r5, lr}
/// 0806137c  mov r4, r0
/// 08061380  bl  0x080613e0       ; ui_element_is_plst_class
/// 08061384  cmp r0, #0
/// 08061388  beq 0x080613ac
/// 0806138c  mov r3, #0
/// 08061390  ldr r1, [pc, #0x18]  ; = 0x63706c64 @ 0x080613b0
/// 08061394  mov r2, r4
/// 08061398  add r0, r4, #0x48
/// 0806139c  str r3, [sp]
/// 080613a0  bl  0x08066bb8
/// 080613a4  ldr r0, [r4, #8]
/// 080613a8  bl  0x0806715c       ; bx lr
/// 080613ac  pop {r3, r4, r5, pc}
/// 080613b0  .word 0x63706c64
/// ```
///
/// The reported 56-byte instruction extent excludes the event-key literal;
/// the next function starts at `0x080613b4`, so the verified extent is 60
/// bytes. Call count was verified by decoding every ARM B/BL word in
/// `osos.dec`: 11 direct `bl` calls, split into 6 unconditional, 4 `blne`,
/// and 1 `bleq`. The predicated callers gate their own state; this function
/// itself relies on the internal 'plst' class predicate.
///
/// Algorithm: when `element` has the 'plst' class tag, notify its tagged
/// handler list at `element + 0x48` using event key `0x63706c64`, the element
/// as context, and zero flags and stack argument. Other elements, including
/// NULL, do nothing.
///
/// Deliberate deviations: `0x08066bb8` remains unported and is represented by
/// [`PLST_ELEMENT_TEARDOWN_OPS`]. The trailing direct call to `0x0806715c` is
/// deliberately elided: raw bytes prove it is a single `bx lr`, ignores its
/// `element + 8` argument, neither returns nor forwards that argument, and
/// its address appears in no aligned data word in `osos.dec`.
///
/// # Safety
///
/// `element` may be NULL. When non-NULL it must be readable through +0x7 for
/// the class predicate. A 'plst' element must provide a valid tagged-handler
/// list at +0x48 for the installed notification implementation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.plst_element_notify_teardown")]
pub unsafe extern "C" fn plst_element_notify_teardown(element: *mut u8) {
    if ui_element_is_plst_class(element) != 0 {
        (plst_element_teardown_ops().tagged_list_notify)(
            element.add(TAGGED_LIST_OFFSET),
            TEARDOWN_NOTIFY_TAG,
            element,
            0,
            0,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    const PLST_CLASS_TAG: u32 = 0x706c_7374;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut NOTIFY_CALLS: u32 = 0;
    static mut NOTIFY_LIST: usize = 0;
    static mut NOTIFY_TAG: u32 = 0;
    static mut NOTIFY_CONTEXT: usize = 0;
    static mut NOTIFY_FLAGS: u32 = u32::MAX;
    static mut NOTIFY_STACK_ARG: u32 = u32::MAX;

    unsafe extern "C" fn record_notify(
        list: *mut u8,
        tag: u32,
        context: *mut u8,
        flags: u32,
        stack_arg: u32,
    ) {
        NOTIFY_CALLS += 1;
        NOTIFY_LIST = list as usize;
        NOTIFY_TAG = tag;
        NOTIFY_CONTEXT = context as usize;
        NOTIFY_FLAGS = flags;
        NOTIFY_STACK_ARG = stack_arg;
    }

    struct OpsGuard(PlstElementTeardownOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { PLST_ELEMENT_TEARDOWN_OPS = self.0 };
        }
    }

    unsafe fn install_recorder() -> OpsGuard {
        let previous = PLST_ELEMENT_TEARDOWN_OPS;
        PLST_ELEMENT_TEARDOWN_OPS = PlstElementTeardownOps {
            tagged_list_notify: record_notify,
        };
        NOTIFY_CALLS = 0;
        NOTIFY_LIST = 0;
        NOTIFY_TAG = 0;
        NOTIFY_CONTEXT = 0;
        NOTIFY_FLAGS = u32::MAX;
        NOTIFY_STACK_ARG = u32::MAX;
        OpsGuard(previous)
    }

    /// A 0x50-byte stand-in with the only field the predicate reads at +0x4.
    fn element_with_tag(tag: u32) -> [u32; 20] {
        let mut element = [0u32; 20];
        element[0] = 0x080d_9fb0;
        element[1] = tag;
        element
    }

    #[test]
    fn plst_element_notifies_with_exact_retail_abi() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = element_with_tag(PLST_CLASS_TAG);
        let _ops = unsafe { install_recorder() };

        unsafe { plst_element_notify_teardown(element.as_ptr() as *mut u8) };

        unsafe {
            let base = element.as_ptr() as usize;
            assert_eq!(NOTIFY_CALLS, 1);
            assert_eq!(NOTIFY_LIST, base + TAGGED_LIST_OFFSET);
            assert_eq!(NOTIFY_TAG, TEARDOWN_NOTIFY_TAG);
            assert_eq!(NOTIFY_CONTEXT, base);
            assert_eq!(NOTIFY_FLAGS, 0);
            assert_eq!(NOTIFY_STACK_ARG, 0);
        }
    }

    #[test]
    fn foreign_tags_do_not_notify() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder() };

        for tag in [0u32, 0x7464_6174, PLST_CLASS_TAG ^ 1] {
            let element = element_with_tag(tag);
            unsafe { plst_element_notify_teardown(element.as_ptr() as *mut u8) };
        }

        unsafe { assert_eq!(NOTIFY_CALLS, 0) };
    }

    #[test]
    fn null_element_does_not_notify() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _ops = unsafe { install_recorder() };

        unsafe { plst_element_notify_teardown(core::ptr::null_mut()) };

        unsafe { assert_eq!(NOTIFY_CALLS, 0) };
    }
}
