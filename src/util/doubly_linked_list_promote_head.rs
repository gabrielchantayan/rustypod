//! `doubly_linked_list_promote_head` — original: `FUN_08367390` @ `0x08367390`
//! (32 bytes; two verified inbound plain `bl` call sites, zero predicated `bl`
//! forms; one outbound plain `bl`).
//!
//! Raw `osos.dec` establishes the exact extent `0x08367390..0x083673af`:
//! `push {r4,r5,lr}` begins the function, and the next independently entered
//! function begins at `0x083673b0`. It removes `node` from its intrusive doubly
//! linked list, then tail-branches to the head-insertion routine at
//! `0x08367358`, making `node` the list head.
//!
//! # Deliberate deviations
//!
//! The target stores pointers in 32-bit words. The Rust ABI uses `*mut u32`
//! and converts links through `u32`, preserving the target layout on 64-bit
//! host test builds. The two retail helpers are expressed inline to avoid
//! unverified seams.

use core::ptr;

/// Removes `node` from `list` and reinserts it as the list head.
///
/// `list`, `node`, and the node's neighbors must be valid aligned target-word
/// addresses. As in retailOS, neither argument is NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.doubly_linked_list_promote_head")]
pub unsafe extern "C" fn doubly_linked_list_promote_head(list: *mut u32, node: *mut u32) {
    let previous = unsafe { ptr::read_volatile(node) } as *mut u32;
    let next = unsafe { ptr::read_volatile(node.add(1)) } as *mut u32;

    if previous.is_null() {
        unsafe { ptr::write_volatile(list, next as usize as u32) };
    } else {
        unsafe { ptr::write_volatile(previous.add(1), next as usize as u32) };
    }
    if next.is_null() {
        unsafe { ptr::write_volatile(list.add(1), previous as usize as u32) };
    } else {
        unsafe { ptr::write_volatile(next, previous as usize as u32) };
    }
    unsafe {
        ptr::write_volatile(node.add(1), 0);
        ptr::write_volatile(node, 0);
        ptr::write_volatile(node.add(2), 0);
    }

    let tail = unsafe { ptr::read_volatile(list.add(1)) } as *mut u32;
    if tail.is_null() {
        unsafe {
            ptr::write_volatile(list.add(1), node as usize as u32);
            ptr::write_volatile(list, node as usize as u32);
            ptr::write_volatile(node.add(1), 0);
        }
    }
    unsafe { ptr::write_volatile(node, 0) };
    if !tail.is_null() {
        let head = unsafe { ptr::read_volatile(list) };
        unsafe {
            ptr::write_volatile(node.add(1), head);
            ptr::write_volatile(head as usize as *mut u32, node as usize as u32);
            ptr::write_volatile(list, node as usize as u32);
        }
    }
    unsafe { ptr::write_volatile(node.add(2), list as usize as u32) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::doubly_linked_list_promote_head;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const WORDS: usize = 0x1000;
    const LIST: usize = 0;
    const FIRST: usize = 8;
    const SECOND: usize = 16;
    const THIRD: usize = 24;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::DOUBLY_LINKED_LIST_PROMOTE_HEAD, WORDS * core::mem::size_of::<u32>())
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    fn slab() -> Option<*mut u32> {
        (*SLAB).map(|address| address as *mut u32)
    }

    unsafe fn link(base: *mut u32, previous: usize, node: usize, next: usize) {
        unsafe {
            base.add(node).write(if previous == 0 { 0 } else { base.add(previous) as usize as u32 });
            base.add(node + 1).write(if next == 0 { 0 } else { base.add(next) as usize as u32 });
            base.add(node + 2).write(base.add(LIST) as usize as u32);
        }
    }

    #[test]
    fn promotes_a_middle_node_and_preserves_neighbors() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(LIST).write(base.add(FIRST) as usize as u32);
            base.add(LIST + 1).write(base.add(THIRD) as usize as u32);
            link(base, 0, FIRST, SECOND);
            link(base, FIRST, SECOND, THIRD);
            link(base, SECOND, THIRD, 0);

            doubly_linked_list_promote_head(base.add(LIST), base.add(SECOND));

            assert_eq!(base.add(LIST).read(), base.add(SECOND) as usize as u32);
            assert_eq!(base.add(LIST + 1).read(), base.add(THIRD) as usize as u32);
            assert_eq!(base.add(SECOND).read(), 0);
            assert_eq!(base.add(SECOND + 1).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(FIRST).read(), base.add(SECOND) as usize as u32);
            assert_eq!(base.add(FIRST + 1).read(), base.add(THIRD) as usize as u32);
            assert_eq!(base.add(THIRD).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(SECOND + 2).read(), base.add(LIST) as usize as u32);
        }
    }

    #[test]
    fn promotes_the_only_node_without_leaving_stale_links() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(LIST).write(base.add(FIRST) as usize as u32);

            base.add(LIST + 1).write(base.add(FIRST) as usize as u32);
            link(base, 0, FIRST, 0);

            doubly_linked_list_promote_head(base.add(LIST), base.add(FIRST));

            assert_eq!(base.add(LIST).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(LIST + 1).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(FIRST).read(), 0);
            assert_eq!(base.add(FIRST + 1).read(), 0);
            assert_eq!(base.add(FIRST + 2).read(), base.add(LIST) as usize as u32);
        }
    }
    #[test]
    fn promotes_a_tail_node_and_updates_the_tail_before_prepend() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(LIST).write(base.add(FIRST) as usize as u32);
            base.add(LIST + 1).write(base.add(THIRD) as usize as u32);
            link(base, 0, FIRST, SECOND);
            link(base, FIRST, SECOND, THIRD);
            link(base, SECOND, THIRD, 0);

            doubly_linked_list_promote_head(base.add(LIST), base.add(THIRD));

            assert_eq!(base.add(LIST).read(), base.add(THIRD) as usize as u32);
            assert_eq!(base.add(LIST + 1).read(), base.add(SECOND) as usize as u32);
            assert_eq!(base.add(THIRD).read(), 0);
            assert_eq!(base.add(THIRD + 1).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(FIRST).read(), base.add(THIRD) as usize as u32);
            assert_eq!(base.add(SECOND + 1).read(), 0);
            assert_eq!(base.add(THIRD + 2).read(), base.add(LIST) as usize as u32);
        }
    }
}
