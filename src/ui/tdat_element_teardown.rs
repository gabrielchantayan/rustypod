//! 'tdat' UI-element teardown.
//!
//! - `tdat_element_teardown` — original: `FUN_0806a994` @ `0x0806a994`
//!   (104 bytes including the event-key literal at `0x0806a9f8`; 96 instruction
//!   bytes). Verified caller count: 3 direct `bl` calls — 3 unconditional,
//!   0 predicated.

use core::ptr;

use super::plst_element_teardown::plst_element_notify_teardown;
use super::plst_next::ui_plst_next;
use super::tdat_class_check::ui_element_is_tdat_class;
use super::tdat_first_plst::ui_tdat_first_plst;

const TAGGED_LIST_OFFSET: usize = 0x54;
const TEARDOWN_NOTIFY_TAG: u32 = 0x7464_636d;

/// ABI of the still-unported tagged-handler list walker at `0x08066bb8`.
pub type TdatTeardownNotify = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tdat_teardown_notify(
    list: *mut u8,
    tag: u32,
    context: *mut u8,
    flags: u32,
    stack_arg: u32,
) {
    let notify: TdatTeardownNotify = core::mem::transmute(0x0806_6bb8usize);
    notify(list, tag, context, flags, stack_arg)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_tdat_teardown_notify(
    _list: *mut u8,
    _tag: u32,
    _context: *mut u8,
    _flags: u32,
    _stack_arg: u32,
) {}

/// Calls outside this one-function port.
#[derive(Clone, Copy)]
pub struct TdatElementTeardownOps {
    pub tagged_list_notify: TdatTeardownNotify,
}

/// Production dispatch boundary for the unported list walker.
pub const DEFAULT_TDAT_ELEMENT_TEARDOWN_OPS: TdatElementTeardownOps = TdatElementTeardownOps {
    tagged_list_notify: retail_tdat_teardown_notify,
};

/// Active dispatch boundary for `0x08066bb8`.
pub static mut TDAT_ELEMENT_TEARDOWN_OPS: TdatElementTeardownOps =
    DEFAULT_TDAT_ELEMENT_TEARDOWN_OPS;

#[inline(always)]
fn tdat_element_teardown_ops() -> TdatElementTeardownOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(TDAT_ELEMENT_TEARDOWN_OPS)) }
}

/// tdat_element_teardown — original: `FUN_0806a994` @ `0x0806a994` (104 bytes).
///
/// Raw ARM is `0x0806a994..0x0806a9f8`, followed by the event-key literal
/// `0x7464636d` at `0x0806a9f8`; the separately entered next function starts
/// at `0x0806a9fc`, establishing the true 104-byte extent. Decoding every
/// `B`/`BL` word in `osos.dec` finds three direct callers, all unconditional.
///
/// Algorithm: if `element` has the 'tdat' class tag, notify its tagged-handler
/// list at `element + 0x54` with event key `0x7464636d`, then walk the linked
/// 'plst' sequence rooted at `element + 0x34`. Save each successor before
/// issuing that element's teardown notification. The final call at `0x0806a9f0`
/// targets `0x0806715c`, whose raw body is only `bx lr` and is deliberately
/// omitted.
///
/// Deliberate deviations: the unported list walker `0x08066bb8` remains an
/// injectable seam; all three meaningful callees are existing Rust ports and
/// are called directly. The no-op tail call is elided without reading
/// `element + 0x8`, matching its lack of observable effect.
///
/// # Safety
///
/// `element` may be NULL. A non-NULL value must be readable through +0x57 and
/// represent a valid 'tdat' element; each linked 'plst' node must satisfy the
/// safety requirements of the existing selector and teardown ports.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tdat_element_teardown")]
pub unsafe extern "C" fn tdat_element_teardown(element: *mut u8) {
    if ui_element_is_tdat_class(element) == 0 {
        return;
    }

    (tdat_element_teardown_ops().tagged_list_notify)(
        element.add(TAGGED_LIST_OFFSET),
        TEARDOWN_NOTIFY_TAG,
        element,
        0,
        0,
    );

    let mut node = ui_tdat_first_plst(element);
    while node != 0 {
        let node_ptr = node as usize as *mut u8;
        let next = ui_plst_next(node_ptr);
        plst_element_notify_teardown(node_ptr);
        node = next;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use std::sync::Mutex;

    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    const PLST_CLASS_TAG: u32 = 0x706c_7374;
    const FIXTURE_LEN: usize = 0x1000;
    const ELEMENT_OFFSET: usize = 0;
    const FIRST_NODE_OFFSET: usize = 0x100;
    const SECOND_NODE_OFFSET: usize = 0x300;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut NOTIFY_CALLS: u32 = 0;
    static mut NOTIFY_LIST: usize = 0;
    static mut NOTIFY_TAG: u32 = 0;
    static mut NOTIFY_CONTEXT: usize = 0;

    unsafe extern "C" fn record_notify(
        list: *mut u8,
        tag: u32,
        context: *mut u8,
        _flags: u32,
        _stack_arg: u32,
    ) {
        NOTIFY_CALLS += 1;
        NOTIFY_LIST = list as usize;
        NOTIFY_TAG = tag;
        NOTIFY_CONTEXT = context as usize;
    }

    struct OpsGuard(TdatElementTeardownOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { TDAT_ELEMENT_TEARDOWN_OPS = self.0 };
        }
    }

    unsafe fn install_recorder() -> OpsGuard {
        let previous = TDAT_ELEMENT_TEARDOWN_OPS;
        TDAT_ELEMENT_TEARDOWN_OPS = TdatElementTeardownOps {
            tagged_list_notify: record_notify,
        };
        NOTIFY_CALLS = 0;
        NOTIFY_LIST = 0;
        NOTIFY_TAG = 0;
        NOTIFY_CONTEXT = 0;
        OpsGuard(previous)
    }

    unsafe fn word(base: *mut u8, offset: usize, value: u32) {
        ptr::write(base.add(offset).cast::<u32>(), value);
    }

    #[test]
    fn tdat_element_notifies_and_walks_target_width_plst_links() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = try_map_u32_slab(hints::TDAT_ELEMENT_TEARDOWN, FIXTURE_LEN) else {
            return;
        };
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            let element = base.add(ELEMENT_OFFSET);
            let first = base.add(FIRST_NODE_OFFSET);
            let second = base.add(SECOND_NODE_OFFSET);
            word(element, 4, TDAT_CLASS_TAG);
            word(element, 0x34, first as usize as u32);
            word(first, 4, PLST_CLASS_TAG);
            word(first, 0x24, second as usize as u32);
            word(second, 4, PLST_CLASS_TAG);
            let _ops = install_recorder();

            tdat_element_teardown(element);

            assert_eq!(NOTIFY_CALLS, 1);
            assert_eq!(NOTIFY_LIST, element as usize + TAGGED_LIST_OFFSET);
            assert_eq!(NOTIFY_TAG, TEARDOWN_NOTIFY_TAG);
            assert_eq!(NOTIFY_CONTEXT, element as usize);
        }
    }

    #[test]
    fn null_and_foreign_elements_do_not_notify() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let element = [0u32; 24];
        unsafe {
            let _ops = install_recorder();
            tdat_element_teardown(ptr::null_mut());
            tdat_element_teardown(element.as_ptr() as *mut u8);
            assert_eq!(NOTIFY_CALLS, 0);
        }
    }
}
