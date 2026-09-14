//! `linked_list_find_and_promote` — original: `FUN_08053850` @ 0x08053850
//! (84 bytes; six direct `bl` call sites, all unconditional: 0x080516d0,
//! 0x08059130, 0x08059dbc, 0x08065ec4, 0x0806d908, and 0x081c0034).
//!
//! Raw `osos.dec` disassembly establishes the exact extent
//! `0x08053850..0x080538a4`: the independent accessor at 0x080538a4 follows.
//! It walks `list.front` through each node's `next` word, ignoring nodes whose
//! key is `0xffffffff`. On a key match it calls `FUN_08058b60` to move the node
//! to the list front, stores the node payload start (+0x14 on ARM) through
//! `output`, and returns zero. A miss returns `-123` without touching
//! `output`. There are no NULL guards for `list` or `output` on the success
//! path.
//!
//! # Deliberate deviations
//!
//! `FUN_08058b60` has no ledger entry, so this port preserves its direct call
//! boundary with a volatile operation seam: the device default calls the
//! verified retail address, while host tests install an observable replacement.
//! Its recovered identity is deliberately not claimed beyond moving the found
//! node to the front.

use core::ptr;

/// Intrusive entry layout consumed by the retail lookup.
///
/// On ARM, `payload_start` is at +0x14. Native-width host pointers deliberately
/// make host fixtures wider; named `repr(C)` fields retain the target layout
/// without overlapping pointer fields.
#[repr(C)]
pub struct LinkedListEntry {
    pub next: *mut LinkedListEntry,
    pub previous: *mut LinkedListEntry,
    pub state: u32,
    pub key: u32,
    pub payload_state: u32,
    pub payload_start: [u8; 0],
}

/// Intrusive list header. The lookup reads only `front`; `back` is maintained
/// by the unported promotion helper.
#[repr(C)]
pub struct LinkedListHeader {
    pub state_0: u32,
    pub state_4: u32,
    pub state_8: u32,
    pub front: *mut LinkedListEntry,
    pub back: *mut LinkedListEntry,
}

/// The unported `FUN_08058b60` direct callee.
pub type MoveEntryToFront = unsafe extern "C" fn(*mut LinkedListHeader, *mut LinkedListEntry);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_move_entry_to_front(
    list: *mut LinkedListHeader,
    entry: *mut LinkedListEntry,
) {
    let move_entry: MoveEntryToFront = unsafe { core::mem::transmute(0x0805_8b60usize) };
    unsafe { move_entry(list, entry) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_move_entry_to_front(
    _list: *mut LinkedListHeader,
    _entry: *mut LinkedListEntry,
) {
    panic!("linked_list_find_and_promote requires FUN_08058b60 @ 0x08058b60")
}

#[cfg(target_os = "none")]
pub const DEFAULT_LINKED_LIST_FIND_AND_PROMOTE_OPS: MoveEntryToFront = firmware_move_entry_to_front;
#[cfg(not(target_os = "none"))]
pub const DEFAULT_LINKED_LIST_FIND_AND_PROMOTE_OPS: MoveEntryToFront = missing_move_entry_to_front;

/// Active operation for the retail promotion call. Host tests replace it to
/// observe the original call boundary.
pub static mut LINKED_LIST_FIND_AND_PROMOTE_OPS: MoveEntryToFront =
    DEFAULT_LINKED_LIST_FIND_AND_PROMOTE_OPS;

#[inline(always)]
unsafe fn move_entry_to_front() -> MoveEntryToFront {
    unsafe { ptr::read_volatile(ptr::addr_of!(LINKED_LIST_FIND_AND_PROMOTE_OPS)) }
}

/// `linked_list_find_and_promote` — original: `FUN_08053850` @ 0x08053850
/// (84 bytes; six verified, unconditional direct `bl` call sites). Finds the
/// first non-sentinel `key` in `list`, moves it to the front, and stores its
/// payload start in `output`. Returns zero on success or `-123` on a miss.
/// The successful path requires non-NULL writable `list` and `output`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.linked_list_find_and_promote")]
#[inline(never)]
pub unsafe extern "C" fn linked_list_find_and_promote(
    key: u32,
    list: *mut LinkedListHeader,
    output: *mut *mut u8,
) -> i32 {
    let mut entry = unsafe { (*list).front };
    while !entry.is_null() {
        let entry_key = unsafe { (*entry).key };
        if entry_key != u32::MAX && entry_key == key {
            unsafe { move_entry_to_front()(list, entry) };
            unsafe { *output = (*entry).payload_start.as_mut_ptr() };
            return 0;
        }
        entry = unsafe { (*entry).next };
    }
    -123
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{self, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut PROMOTION_CALLS: usize = 0;
    static mut SEEN_LIST: *mut LinkedListHeader = ptr::null_mut();
    static mut SEEN_ENTRY: *mut LinkedListEntry = ptr::null_mut();

    unsafe extern "C" fn recording_move_to_front(
        list: *mut LinkedListHeader,
        entry: *mut LinkedListEntry,
    ) {
        unsafe {
            PROMOTION_CALLS += 1;
            SEEN_LIST = list;
            SEEN_ENTRY = entry;
        }
    }

    fn install_recording_move() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            PROMOTION_CALLS = 0;
            SEEN_LIST = ptr::null_mut();
            SEEN_ENTRY = ptr::null_mut();
            addr_of_mut!(LINKED_LIST_FIND_AND_PROMOTE_OPS).write(recording_move_to_front);
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(LINKED_LIST_FIND_AND_PROMOTE_OPS)
                .write(DEFAULT_LINKED_LIST_FIND_AND_PROMOTE_OPS);
        }
        drop(guard);
    }

    fn entry(key: u32) -> LinkedListEntry {
        LinkedListEntry {
            next: ptr::null_mut(),
            previous: ptr::null_mut(),
            state: 0,
            key,
            payload_state: 0,
            payload_start: [],
        }
    }

    fn list(front: *mut LinkedListEntry, back: *mut LinkedListEntry) -> LinkedListHeader {
        LinkedListHeader { state_0: 0, state_4: 0, state_8: 0, front, back }
    }

    #[test]
    fn finds_a_later_entry_and_promotes_it_before_returning_its_payload() {
        let guard = install_recording_move();
        let mut entries = [entry(3), entry(5), entry(7)];
        entries[0].next = &mut entries[1];
        entries[1].next = &mut entries[2];
        let expected_payload = entries[2].payload_start.as_mut_ptr();
        let mut header = list(&mut entries[0], &mut entries[2]);
        let mut output = ptr::null_mut();

        assert_eq!(unsafe { linked_list_find_and_promote(7, &mut header, &mut output) }, 0);
        assert_eq!(output, expected_payload);
        assert_eq!(unsafe { PROMOTION_CALLS }, 1);
        assert_eq!(unsafe { SEEN_LIST as usize }, &mut header as *mut _ as usize);
        assert_eq!(unsafe { SEEN_ENTRY as usize }, &mut entries[2] as *mut _ as usize);
        restore_default(guard);
    }

    #[test]
    fn skips_sentinel_keys_even_when_the_lookup_key_is_the_sentinel() {
        let guard = install_recording_move();
        let mut entries = [entry(u32::MAX), entry(9)];
        entries[0].next = &mut entries[1];
        let mut header = list(&mut entries[0], &mut entries[1]);
        let marker = 0x1234usize as *mut u8;
        let mut output = marker;

        assert_eq!(unsafe { linked_list_find_and_promote(u32::MAX, &mut header, &mut output) }, -123);
        assert_eq!(output, marker);
        assert_eq!(unsafe { PROMOTION_CALLS }, 0);
        restore_default(guard);
    }

    #[test]
    fn missing_key_preserves_output_and_does_not_call_promotion() {
        let guard = install_recording_move();
        let mut only = entry(4);
        let mut header = list(&mut only, &mut only);
        let marker = 0x5678usize as *mut u8;
        let mut output = marker;

        assert_eq!(unsafe { linked_list_find_and_promote(8, &mut header, &mut output) }, -123);
        assert_eq!(output, marker);
        assert_eq!(unsafe { PROMOTION_CALLS }, 0);
        restore_default(guard);
    }
}
