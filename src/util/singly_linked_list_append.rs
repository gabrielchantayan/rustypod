//! `singly_linked_list_append` — original: `FUN_0803c588` @ `0x0803c588`
//! (48 bytes; four verified inbound plain `bl` call sites and zero predicated
//! `bl` forms).
//!
//! Raw `osos.dec` words establish the exact 48-byte extent
//! `0x0803c588..0x0803c5b7`: `bx lr` (`e12fff1e`) is the final instruction,
//! and the next independently entered function starts at `0x0803c5b8` with
//! `stmdb sp!, {r2,r3,r4,lr}`. The leaf follows target-width `next` words at
//! offset zero until NULL, clears `node->next`, then installs `node` as either
//! the empty list's head or the old tail's successor.
//!
//! # Deliberate deviations
//!
//! The target stores pointers in 32-bit words. The Rust ABI uses `*mut u32`
//! for the input pointers but converts node links through `u32`, preserving
//! target layout on 64-bit host test builds.

/// Appends `node` to the NULL-terminated singly linked list rooted at `head`.
///
/// `head`, `node`, and every reachable node must be valid aligned target-word
/// addresses. As in retailOS, neither argument is NULL-checked.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.singly_linked_list_append")]
pub unsafe extern "C" fn singly_linked_list_append(head: *mut u32, node: *mut u32) {
    let mut current = unsafe { core::ptr::read_volatile(head) } as *mut u32;
    let mut tail = core::ptr::null_mut();

    while !current.is_null() {
        tail = current;
        current = unsafe { core::ptr::read_volatile(current) } as *mut u32;
    }

    unsafe { core::ptr::write_volatile(node, 0) };
    if tail.is_null() {
        unsafe { core::ptr::write_volatile(head, node as usize as u32) };
    } else {
        unsafe { core::ptr::write_volatile(tail, node as usize as u32) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::singly_linked_list_append;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const WORDS: usize = 0x1000;
    const HEAD: usize = 0;
    const FIRST: usize = 8;
    const SECOND: usize = 16;
    const THIRD: usize = 24;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SINGLY_LINKED_LIST_APPEND, WORDS * core::mem::size_of::<u32>())
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    fn slab() -> Option<*mut u32> {
        (*SLAB).map(|address| address as *mut u32)
    }

    #[test]
    fn appends_to_an_empty_list_and_clears_node_link() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(HEAD).write(0);
            base.add(FIRST).write(0xdead_beef);
            singly_linked_list_append(base.add(HEAD), base.add(FIRST));
            assert_eq!(base.add(HEAD).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(FIRST).read(), 0);
        }
    }

    #[test]
    fn appends_after_the_actual_tail() {
        let _lock = LOCK.lock();
        let Some(base) = slab() else { return };
        unsafe {
            base.add(HEAD).write(base.add(FIRST) as usize as u32);
            base.add(FIRST).write(base.add(SECOND) as usize as u32);
            base.add(SECOND).write(0);
            base.add(THIRD).write(base.add(FIRST) as usize as u32);
            singly_linked_list_append(base.add(HEAD), base.add(THIRD));
            assert_eq!(base.add(HEAD).read(), base.add(FIRST) as usize as u32);
            assert_eq!(base.add(FIRST).read(), base.add(SECOND) as usize as u32);
            assert_eq!(base.add(SECOND).read(), base.add(THIRD) as usize as u32);
            assert_eq!(base.add(THIRD).read(), 0);
        }
    }
}
