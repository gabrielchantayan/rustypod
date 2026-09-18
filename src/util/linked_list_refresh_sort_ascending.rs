//! Refresh and ascending-sort an intrusive list — original: `FUN_080e7514`
//! @ **0x080e7514** (152 bytes, 0x080e7514..0x080e75ac, 38 ARM
//! instructions). The next real function starts at 0x080e75ac.
//! Raw A32 decoding finds four inbound direct `bl` call sites, all plain
//! unconditional `bl`; no predicated `bl` form targets this function.
//!
//! Each node first loads its key from the current cursor word, advances that
//! cursor by its word stride, and decrements its remaining count. The routine
//! then stably bubble-sorts the singly linked nodes by ascending signed key.
//!
//! # Deliberate deviations
//!
//! RetailOS stores pointers as target-width words. The Rust ABI therefore uses
//! `u32` fields and converts them only at dereference time, preserving every
//! target offset on 64-bit host fixtures.

/// Target-width anchor holding the head of an intrusive singly linked list.
#[repr(C)]
pub struct RefreshSortAnchor {
    pub head: u32,
}

/// Target-width node used by [`linked_list_refresh_sort_ascending`].
#[repr(C)]
pub struct RefreshSortNode {
    pub key: u32,
    pub next: u32,
    pub cursor: u32,
    pub stride_words: u32,
    pub remaining: u32,
}

/// Refreshes every node's key, then stably sorts the list by ascending signed
/// key. As in retailOS, `anchor`, every node, and every cursor must be valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.linked_list_refresh_sort_ascending")]
pub unsafe extern "C" fn linked_list_refresh_sort_ascending(anchor: *mut RefreshSortAnchor) {
    let mut node_address = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*anchor).head)) };
    while node_address != 0 {
        let node = node_address as usize as *mut RefreshSortNode;
        let cursor = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).cursor)) };
        let key = unsafe { core::ptr::read_volatile(cursor as usize as *const u32) };
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).key), key) };
        let stride = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).stride_words)) };
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*node).cursor),
                cursor.wrapping_add(stride.wrapping_mul(4)),
            )
        };
        let remaining = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).remaining)) };
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*node).remaining), remaining.wrapping_sub(1)) };
        node_address = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*node).next)) };
    }

    let mut current_address = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*anchor).head)) };
    let mut previous_next = core::ptr::addr_of_mut!((*anchor).head);
    loop {
        if current_address == 0 {
            return;
        }
        let current = current_address as usize as *mut RefreshSortNode;
        let next_address = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*current).next)) };
        if next_address == 0 {
            return;
        }
        let next = next_address as usize as *mut RefreshSortNode;
        let current_key = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*current).key)) } as i32;
        let next_key = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*next).key)) } as i32;
        if current_key <= next_key {
            previous_next = unsafe { core::ptr::addr_of_mut!((*current).next) };
            current_address = next_address;
            continue;
        }

        let following_address = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*next).next)) };
        unsafe { core::ptr::write_volatile(previous_next, next_address) };
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*current).next), following_address) };
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*next).next), current_address) };
        current_address = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*anchor).head)) };
        previous_next = core::ptr::addr_of_mut!((*anchor).head);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{linked_list_refresh_sort_ascending, RefreshSortAnchor};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex as TestMutex;
    use std::sync::LazyLock;

    const WORDS: usize = 64;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LINKED_LIST_REFRESH_SORT_ASCENDING, WORDS * 4).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: TestMutex<()> = TestMutex::new(());

    fn slab() -> Option<*mut u32> {
        (*SLAB).map(|address| address as *mut u32)
    }

    #[test]
    fn refreshes_cursors_and_sorts_signed_ascending() {
        let _guard = TEST_LOCK.lock();
        let Some(words) = slab() else {
            note_missing_u32_fixture("util::linked_list_refresh_sort_ascending");
            return;
        };
        unsafe { core::ptr::write_bytes(words, 0, WORDS) };
        let a = unsafe { words.add(4) };
        let b = unsafe { words.add(9) };
        let c = unsafe { words.add(14) };
        unsafe {
            *words = a as usize as u32;
            *a.add(1) = b as usize as u32;
            *a.add(2) = words.add(40) as usize as u32;
            *a.add(3) = 2;
            *a.add(4) = 3;
            *b.add(1) = c as usize as u32;
            *b.add(2) = words.add(44) as usize as u32;
            *b.add(3) = 1;
            *b.add(4) = 1;
            *c.add(2) = words.add(48) as usize as u32;
            *c.add(3) = 0;
            *c.add(4) = 0;
            *words.add(40) = (-3_i32) as u32;
            *words.add(44) = 7;
            *words.add(48) = 2;
            linked_list_refresh_sort_ascending(words as *mut RefreshSortAnchor);
            assert_eq!(*words, a as usize as u32);
            assert_eq!(*a.add(1), c as usize as u32);
            assert_eq!(*c.add(1), b as usize as u32);
            assert_eq!(*a.add(0), (-3_i32) as u32);
            assert_eq!(*b.add(0), 7);
            assert_eq!(*c.add(0), 2);
            assert_eq!(*a.add(2), words.add(42) as usize as u32);
            assert_eq!(*b.add(2), words.add(45) as usize as u32);
            assert_eq!(*c.add(2), words.add(48) as usize as u32);
            assert_eq!(*a.add(4), 2);
            assert_eq!(*b.add(4), 0);
            assert_eq!(*c.add(4), u32::MAX);
        }
    }

    #[test]
    fn equal_keys_remain_in_original_order() {
        let _guard = TEST_LOCK.lock();
        let Some(words) = slab() else {
            return;
        };
        unsafe { core::ptr::write_bytes(words, 0, WORDS) };
        let a = unsafe { words.add(4) };
        let b = unsafe { words.add(9) };
        unsafe {
            *words = a as usize as u32;
            *a.add(1) = b as usize as u32;
            *a.add(2) = words.add(40) as usize as u32;
            *b.add(2) = words.add(41) as usize as u32;
            *words.add(40) = 5;
            *words.add(41) = 5;
            linked_list_refresh_sort_ascending(words as *mut RefreshSortAnchor);
            assert_eq!(*words, a as usize as u32);
            assert_eq!(*a.add(1), b as usize as u32);
            assert_eq!(*b.add(1), 0);
        }
    }

    #[test]
    fn empty_anchor_is_unchanged() {
        let mut anchor = RefreshSortAnchor { head: 0 };
        unsafe { linked_list_refresh_sort_ascending(&mut anchor) };
        assert_eq!(anchor.head, 0);
    }
}
