//! `singly_linked_list_remove` — original: `FUN_0806473c` @ `0x0806473c`
//! (80 bytes; four verified inbound plain `bl` call sites and zero predicated
//! `bl` forms).
//!
//! Raw ARM establishes the exact 80-byte extent `0x0806473c..0x0806478b`:
//! `bx lr` at `0x08064788` is the final instruction, and the next independent
//! function opens with `push {r4-r8,lr}` at `0x0806478c`. The leaf walks the
//! NULL-terminated chain rooted at `head`, whose only observed node field is
//! its target-width `next` word at +0. If `node` is found, it splices it from
//! the list and clears `node->next`; an empty list or absent node is untouched.
//!
//! Deliberate deviations: none.

/// Removes `node` from the NULL-terminated singly linked list at `head`.
///
/// `head` and each reachable node must hold aligned target-width words. The
/// routine does not validate ownership: `node` is changed only when its exact
/// address occurs in the chain.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.singly_linked_list_remove")]
pub unsafe extern "C" fn singly_linked_list_remove(head: *mut u32, node: *mut u32) {
    let mut current = unsafe { head.read() } as *mut u32;
    let mut previous: *mut u32 = core::ptr::null_mut();

    while !current.is_null() {
        if current == node {
            let next = unsafe { node.read() };
            if previous.is_null() {
                unsafe { head.write(next) };
            } else {
                unsafe { previous.write(next) };
            }
            unsafe { node.write(0) };
            return;
        }
        previous = current;
        current = unsafe { current.read() } as *mut u32;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const HEAD: usize = 0;
    const FIRST: usize = 16;
    const MIDDLE: usize = 32;
    const LAST: usize = 48;
    const ABSENT: usize = 64;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SINGLY_LINKED_LIST_REMOVE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<*mut u32> {
        let base = *FIXTURE.as_ref()? as *mut u8;
        unsafe { base.write_bytes(0, FIXTURE_LEN) };
        Some(base.cast())
    }

    unsafe fn at(base: *mut u32, word: usize) -> *mut u32 {
        unsafe { base.add(word) }
    }

    unsafe fn link(first: *mut u32, middle: *mut u32, last: *mut u32) {
        unsafe {
            first.write(middle as usize as u32);
            middle.write(last as usize as u32);
            last.write(0);
        }
    }

    #[test]
    fn empty_and_absent_nodes_leave_list_unchanged() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util/singly_linked_list_remove"));
            return;
        };
        unsafe {
            let head = at(base, HEAD);
            let absent = at(base, ABSENT);
            singly_linked_list_remove(head, absent);
            assert_eq!(head.read(), 0);

            let first = at(base, FIRST);
            let last = at(base, LAST);
            head.write(first as usize as u32);
            first.write(last as usize as u32);
            last.write(0);
            absent.write(0x1234_5678);
            singly_linked_list_remove(head, absent);
            assert_eq!(head.read(), first as usize as u32);
            assert_eq!(first.read(), last as usize as u32);
            assert_eq!(absent.read(), 0x1234_5678);
        }
    }

    #[test]
    fn removes_head_and_clears_its_link() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util/singly_linked_list_remove"));
            return;
        };
        unsafe {
            let head = at(base, HEAD);
            let first = at(base, FIRST);
            let middle = at(base, MIDDLE);
            let last = at(base, LAST);
            link(first, middle, last);
            head.write(first as usize as u32);
            singly_linked_list_remove(head, first);
            assert_eq!(head.read(), middle as usize as u32);
            assert_eq!(first.read(), 0);
            assert_eq!(middle.read(), last as usize as u32);
        }
    }

    #[test]
    fn removes_interior_and_tail_nodes() {
        let _guard = LOCK.lock();
        let Some(base) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("util/singly_linked_list_remove"));
            return;
        };
        unsafe {
            let head = at(base, HEAD);
            let first = at(base, FIRST);
            let middle = at(base, MIDDLE);
            let last = at(base, LAST);
            link(first, middle, last);
            head.write(first as usize as u32);
            singly_linked_list_remove(head, middle);
            assert_eq!(head.read(), first as usize as u32);
            assert_eq!(first.read(), last as usize as u32);
            assert_eq!(middle.read(), 0);
            singly_linked_list_remove(head, last);
            assert_eq!(first.read(), 0);
            assert_eq!(last.read(), 0);
        }
    }
}
