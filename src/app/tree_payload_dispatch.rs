//! Dispatch every tree-node payload — retail `FUN_081f047c` @ `0x081f047c`.
//!
//! True extent: 80 bytes, through pop at 0x081f04c8, next prologue 0x081f04cc.
//! Raw A32 decoding finds two inbound plain BLs (0x081f05d0, 0x081f1590),
//! three outbound plain BLs, and zero predicated BLs in either direction.
//! Start at the header's leftmost link, dispatch node+0x14, advance in order,
//! and reload owner+0x24 before every end comparison. Always return one.
//!
//! Deliberate deviations: reuse the ported equality and cursor-advance helpers;
//! the unported 0x0811f150 payload-vector virtual-slot-0x24 dispatch remains
//! a fixed-address firmware seam, replaceable on hosts. No node is erased.

use crate::cxx::red_black_tree_increment::red_black_tree_advance_cursor;
use crate::cxx::templates::equal_deref;

type PayloadDispatch = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_payload_dispatch(payload: *mut u8) {
    let dispatch: PayloadDispatch = core::mem::transmute(0x0811_f150usize);
    dispatch(payload);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_payload_dispatch(_payload: *mut u8) {
    panic!("tree_payload_dispatch requires firmware payload dispatch 0x0811f150")
}

#[cfg(target_os = "none")]
pub static mut TREE_PAYLOAD_DISPATCH: PayloadDispatch = firmware_payload_dispatch;
#[cfg(not(target_os = "none"))]
pub static mut TREE_PAYLOAD_DISPATCH: PayloadDispatch = missing_payload_dispatch;

/// Dispatches every payload in the owner's tree and returns one.
///
/// # Safety
/// Owner+0x24 contains a valid aligned target-width header pointer. Its +8
/// link and all traversed nodes must be valid. Dispatch must preserve the
/// current node and links needed by iterator advancement.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tree_payload_dispatch(owner: *mut u32) -> u32 {
    let header = owner.add(9).read();
    let mut cursor = (header as usize as *const u32).add(2).read();
    loop {
        let end = owner.add(9).read();
        if equal_deref(&cursor, &end) == 1 {
            return 1;
        }
        let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(TREE_PAYLOAD_DISPATCH));
        dispatch((cursor as usize as *mut u8).add(0x14));
        red_black_tree_advance_cursor(&mut cursor);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    static CALLS: parking_lot::Mutex<Vec<usize>> = parking_lot::Mutex::new(Vec::new());
    static mut OWNER: *mut u32 = core::ptr::null_mut();
    static mut STOP_AT: u32 = 0;

    unsafe extern "C" fn record(payload: *mut u8) {
        CALLS.lock().push(payload as usize);
        // Mutate payload, not links; optionally replace the owner's end marker.
        payload.cast::<u32>().write(0xfeed_beef);
        if STOP_AT != 0 { OWNER.add(9).write(STOP_AT); }
    }

    #[test]
    fn empty_singleton_in_order_and_reloaded_end() {
        unsafe {
            let Some(base) = crate::testing::try_map_u32_slab(
                crate::testing::hints::TREE_PAYLOAD_DISPATCH, 4096,
            ) else { return };
            let owner = base.cast::<u32>();
            let header = owner.add(32);
            let left = owner.add(64);
            let root = owner.add(80);
            let right = owner.add(96);
            let addr = |p: *mut u32| p as usize as u32;
            let saved = TREE_PAYLOAD_DISPATCH;
            TREE_PAYLOAD_DISPATCH = record;
            OWNER = owner;
            STOP_AT = 0;
            owner.add(9).write(addr(header));
            header.add(2).write(addr(header));
            assert_eq!(tree_payload_dispatch(owner), 1);
            assert!(CALLS.lock().is_empty());

            header.add(1).write(addr(root));
            header.add(2).write(addr(root));
            root.add(1).write(addr(header));
            root.add(2).write(0);
            root.add(3).write(0);
            assert_eq!(tree_payload_dispatch(owner), 1);
            assert_eq!(*CALLS.lock(), [root.add(5) as usize]);
            CALLS.lock().clear();

            header.add(2).write(addr(left));
            root.add(2).write(addr(left));
            root.add(3).write(addr(right));
            for node in [left, right] {
                node.add(1).write(addr(root));
                node.add(2).write(0);
                node.add(3).write(0);
            }
            assert_eq!(tree_payload_dispatch(owner), 1);
            assert_eq!(*CALLS.lock(), [left.add(5) as usize, root.add(5) as usize, right.add(5) as usize]);
            for node in [left, root, right] { assert_eq!(node.add(5).read(), 0xfeed_beef); }
            assert_eq!(root.add(2).read(), addr(left));
            assert_eq!(root.add(3).read(), addr(right));
            CALLS.lock().clear();

            STOP_AT = addr(root);
            assert_eq!(tree_payload_dispatch(owner), 1);
            assert_eq!(*CALLS.lock(), [left.add(5) as usize]);
            assert_eq!(owner.add(9).read(), addr(root));
            CALLS.lock().clear();
            STOP_AT = 0;
            OWNER = core::ptr::null_mut();
            TREE_PAYLOAD_DISPATCH = saved;
        }
    }
}
