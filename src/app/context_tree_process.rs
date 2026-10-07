//! Process pointer payloads in a context tree — FUN_08147360 @ 0x08147360.
//!
//! True size 96 bytes, ending at 0x081473bc; next prologue 0x081473c0.
//! Verified raw calls: three outgoing plain BLs, zero predicated BLs;
//! two incoming plain BLs at 0x0812d7e0 and 0x081b9d10, none predicated.
//! Start at owner+0x1c's header left link, pass each node's +0x14 pointer
//! and the context word to resident 0x081e06f4, then advance in order.
//! Reload the owner's header before every comparison, including after callbacks.
//!
//! Deliberate deviations: omit unused iterator stack copies and reuse ported
//! equality/advance helpers. The unported payload processor retains its verified
//! address and two-word ABI; no class identity is assumed. Host tests inject
//! that processor into the same walk rather than executing firmware addresses.

use crate::cxx::red_black_tree_increment::red_black_tree_advance_cursor;
use crate::util::u32_indirect_equal::u32_indirect_equal;

type ProcessPayload = unsafe extern "C" fn(*mut u32, u32);

#[inline(always)]
unsafe fn process_tree(owner: *mut u32, context: u32, process: ProcessPayload) {
    let header = owner.add(7).read_volatile();
    let mut cursor = (header as usize as *const u32).add(2).read();
    loop {
        let end = owner.add(7).read_volatile();
        if u32_indirect_equal(&cursor, &end) == 1 { return; }
        let payload = (cursor as usize as *const u32).add(5).read();
        process(payload as usize as *mut u32, context);
        red_black_tree_advance_cursor(&mut cursor);
    }
}

/// Process every pointer payload in the owner's tree with `context`.
///
/// # Safety
/// Owner+0x1c must hold a valid target-width tree header. Every node and
/// payload must be valid for the resident processor, which must preserve
/// the current node and links required for successor traversal.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_tree_process(owner: *mut u32, context: u32) {
    let process: ProcessPayload = core::mem::transmute(0x081e_06f4usize);
    process_tree(owner, context, process);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;
    std::thread_local! {
        static SEEN: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
        static STOP: RefCell<(*mut u32, u32)> = const { RefCell::new((core::ptr::null_mut(), 0)) };
    }
    unsafe extern "C" fn process(payload: *mut u32, context: u32) {
        assert_eq!(context, 0xfedcba98);
        SEEN.with(|seen| seen.borrow_mut().push(payload.read()));
        payload.write(payload.read().wrapping_add(10));
        STOP.with(|stop| {
            let (owner, end) = *stop.borrow();
            if end != 0 { owner.add(7).write(end); }
        });
    }

    #[test]
    fn empty_singleton_order_and_callback_end_change() {
        unsafe {
            let Some(base) = crate::testing::try_map_u32_slab(
                crate::testing::hints::CONTEXT_TREE_PROCESS, 4096,
            ) else { return };
            let owner = base.cast::<u32>();
            let header = owner.add(32);
            let left = owner.add(64);
            let root = owner.add(80);
            let right = owner.add(96);
            let addr = |p: *mut u32| p as usize as u32;
            owner.add(7).write(addr(header));
            header.add(2).write(addr(header));
            process_tree(owner, 0xfedcba98, process);
            SEEN.with(|s| assert_eq!(*s.borrow(), []));

            header.add(1).write(addr(root));
            header.add(2).write(addr(root));
            root.add(1).write(addr(header));
            root.add(2).write(0);
            root.add(3).write(0);
            let payloads = owner.add(128);
            root.add(5).write(addr(payloads.add(1)));
            payloads.add(1).write(2);
            process_tree(owner, 0xfedcba98, process);
            SEEN.with(|s| { assert_eq!(*s.borrow(), [2]); s.borrow_mut().clear(); });
            assert_eq!(payloads.add(1).read(), 12);

            header.add(2).write(addr(left));
            root.add(2).write(addr(left));
            root.add(3).write(addr(right));
            for (i, node) in [left, root, right].into_iter().enumerate() {
                node.add(5).write(addr(payloads.add(i)));
                payloads.add(i).write(i as u32 + 1);
                if node != root {
                    node.add(1).write(addr(root));
                    node.add(2).write(0);
                    node.add(3).write(0);
                }
            }
            process_tree(owner, 0xfedcba98, process);
            SEEN.with(|s| { assert_eq!(*s.borrow(), [1, 2, 3]); s.borrow_mut().clear(); });
            assert_eq!(core::slice::from_raw_parts(payloads, 3), [11, 12, 13]);
            STOP.with(|s| *s.borrow_mut() = (owner, addr(root)));
            process_tree(owner, 0xfedcba98, process);
            SEEN.with(|s| { assert_eq!(*s.borrow(), [11]); s.borrow_mut().clear(); });
            assert_eq!(payloads.read(), 21);
            assert_eq!(payloads.add(1).read(), 12);
            assert_eq!(owner.add(7).read(), addr(root));
            STOP.with(|s| *s.borrow_mut() = (core::ptr::null_mut(), 0));
        }
    }
}
