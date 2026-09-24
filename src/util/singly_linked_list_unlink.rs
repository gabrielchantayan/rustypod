//! `singly_linked_list_unlink` — original: `FUN_080e8430` @ `0x080e8430`
//! (52 bytes; one verified inbound plain `bl` call site and two predicated
//! `bleq` call sites).
//!
//! Raw osos.dec establishes the exact 52-byte extent `0x080e8430..0x080e8463`:
//! `bx lr` at `0x080e8460` is the final instruction, and the next independent
//! function opens with `push {r3-r9,sl,fp,lr}` at `0x080e8464`. The leaf walks
//! a NULL-terminated chain through each node's target-width `next` word at +4.
//! It replaces the link that names `node` with `node->next`, leaving the
//! unlinked node unchanged. Empty chains and absent nodes are untouched.
//!
//! Deliberate deviations: none.

/// Unlinks `node` from the singly linked list rooted at `head`.
///
/// `head` and every reachable node must hold aligned target-width words. The
/// routine compares raw target addresses and does not clear the removed node's
/// `next` word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.singly_linked_list_unlink")]
pub unsafe extern "C" fn singly_linked_list_unlink(head: *mut u32, node: u32) {
    let mut link = head;
    let mut current = unsafe { link.read() };

    while current != 0 {
        if current == node {
            unsafe { link.write((current as *const u32).add(1).read()) };
            return;
        }
        link = unsafe { (current as *mut u32).add(1) };
        current = unsafe { link.read() };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const HEAD: usize = 0;
    const FIRST: usize = 16;
    const MIDDLE: usize = 32;
    const LAST: usize = 48;
    const ABSENT: usize = 64;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SINGLY_LINKED_LIST_UNLINK, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<*mut u32> {
        (*FIXTURE).map(|pointer| pointer as *mut u32)
    }
    unsafe fn at(base: *mut u32, word: usize) -> *mut u32 {
        unsafe { base.add(word) }
    }

    unsafe fn reset(base: *mut u32) {
        for word in 0..FIXTURE_LEN {
            unsafe { base.add(word).write(0) };
        }
    }

    unsafe fn link(first: *mut u32, middle: *mut u32, last: *mut u32) {
        unsafe {
            first.add(1).write(middle as usize as u32);
            middle.add(1).write(last as usize as u32);
            last.add(1).write(0);
        }
    }

    #[test]
    fn empty_absent_and_null_target_leave_the_head_unchanged() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        unsafe {
            reset(base);
            let head = at(base, HEAD);
            singly_linked_list_unlink(head, 0);
            assert_eq!(head.read(), 0);

            let first = at(base, FIRST);
            let last = at(base, LAST);
            head.write(first as usize as u32);
            first.add(1).write(last as usize as u32);
            last.add(1).write(0);
            singly_linked_list_unlink(head, at(base, ABSENT) as usize as u32);
            assert_eq!(head.read(), first as usize as u32);
            assert_eq!(first.add(1).read(), last as usize as u32);
        }
    }

    #[test]
    fn unlinks_head_without_clearing_its_next_word() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        unsafe {
            reset(base);
            let head = at(base, HEAD);
            let first = at(base, FIRST);
            let last = at(base, LAST);
            head.write(first as usize as u32);
            first.add(1).write(last as usize as u32);
            last.add(1).write(0);

            singly_linked_list_unlink(head, first as usize as u32);
            assert_eq!(head.read(), last as usize as u32);
            assert_eq!(first.add(1).read(), last as usize as u32);
        }
    }

    #[test]
    fn unlinks_interior_and_tail_nodes() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else { return };
        unsafe {
            reset(base);
            let head = at(base, HEAD);
            let first = at(base, FIRST);
            let middle = at(base, MIDDLE);
            let last = at(base, LAST);
            head.write(first as usize as u32);
            link(first, middle, last);

            singly_linked_list_unlink(head, middle as usize as u32);
            assert_eq!(first.add(1).read(), last as usize as u32);
            assert_eq!(middle.add(1).read(), last as usize as u32);

            singly_linked_list_unlink(head, last as usize as u32);
            assert_eq!(first.add(1).read(), 0);
            assert_eq!(last.add(1).read(), 0);
        }
    }
}
