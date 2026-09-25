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
//! None. Host pointer fields are wider than their ARM counterparts, but the
//! named `repr(C)` fields preserve the target's link operations.

use core::ptr;

/// Intrusive entry layout consumed by the retail lookup.
///
/// On ARM, `payload_start` is at +0x14. Native-width host pointers deliberately
/// make host fixtures wider; named `repr(C)` fields retain the target layout
/// without overlapping pointer fields.
#[derive(Debug)]
#[repr(C)]
pub struct LinkedListEntry {
    pub next: *mut LinkedListEntry,
    pub previous: *mut LinkedListEntry,
    pub state: u32,
    pub key: u32,
    pub payload_state: u32,
    pub payload_start: [u8; 0],
}

/// Intrusive list header. The lookup reads only `front`; the promotion helper
/// maintains `back` when moving the current last entry.
#[repr(C)]
pub struct LinkedListHeader {
    pub state_0: u32,
    pub state_4: u32,
    pub state_8: u32,
    pub front: *mut LinkedListEntry,
    pub back: *mut LinkedListEntry,
}

/// `move_entry_to_front` — original: `FUN_08058b60` @ 0x08058b60 (68 bytes;
/// three direct `bl` call sites, all unconditional: 0x08053874, 0x08059174,
/// and 0x0806d928).
///
/// Removes `entry` from its current position, repairs its adjacent links and
/// the list back pointer when it was last, then makes it the front entry. A
/// request to promote the current front is a no-op. The caller must provide an
/// entry already linked into `list`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.move_entry_to_front")]
#[inline(never)]
pub unsafe extern "C" fn move_entry_to_front(
    list: *mut LinkedListHeader,
    entry: *mut LinkedListEntry,
) {
    let old_front = unsafe { (*list).front };
    if old_front == entry {
        return;
    }
    unsafe { (*list).front = entry };

    let next = unsafe { (*entry).next };
    let previous = unsafe { (*entry).previous };
    unsafe { (*previous).next = next };
    if next.is_null() {
        unsafe { (*list).back = previous };
    } else {
        unsafe { (*next).previous = previous };
    }
    unsafe { (*entry).previous = ptr::null_mut() };
    unsafe { (*entry).next = old_front };
    unsafe { (*old_front).previous = entry };
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
            unsafe { move_entry_to_front(list, entry) };
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
    use core::ptr;

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
    fn promotes_a_middle_entry_and_repairs_both_neighbors() {
        let mut entries = [entry(3), entry(5), entry(7)];
        entries[0].next = &mut entries[1];
        entries[1].previous = &mut entries[0];
        entries[1].next = &mut entries[2];
        entries[2].previous = &mut entries[1];
        let mut header = list(&mut entries[0], &mut entries[2]);
        let entry0 = ptr::addr_of_mut!(entries[0]);
        let entry1 = ptr::addr_of_mut!(entries[1]);
        let entry2 = ptr::addr_of_mut!(entries[2]);

        unsafe { move_entry_to_front(&mut header, &mut entries[1]) };
        assert_eq!(header.front, entry1);
        assert_eq!(header.back, entry2);
        assert!(entries[1].previous.is_null());
        assert_eq!(entries[1].next, entry0);
        assert_eq!(entries[0].previous, entry1);
        assert_eq!(entries[0].next, entry2);
        assert_eq!(entries[2].previous, entry0);
    }

    #[test]
    fn promotes_last_entry_and_updates_back() {
        let mut entries = [entry(3), entry(5)];
        entries[0].next = &mut entries[1];
        entries[1].previous = &mut entries[0];
        let mut header = list(&mut entries[0], &mut entries[1]);
        let entry0 = ptr::addr_of_mut!(entries[0]);
        let entry1 = ptr::addr_of_mut!(entries[1]);

        unsafe { move_entry_to_front(&mut header, &mut entries[1]) };

        assert_eq!(header.front, entry1);
        assert_eq!(header.back, entry0);
        assert!(entries[1].previous.is_null());
        assert_eq!(entries[1].next, entry0);
        assert!(entries[0].next.is_null());
        assert_eq!(entries[0].previous, entry1);
    }

    #[test]
    fn leaves_the_current_front_unchanged() {
        let mut entries = [entry(3), entry(5)];
        entries[0].next = &mut entries[1];
        entries[1].previous = &mut entries[0];
        let mut header = list(&mut entries[0], &mut entries[1]);
        let entry0 = ptr::addr_of_mut!(entries[0]);
        let entry1 = ptr::addr_of_mut!(entries[1]);

        unsafe { move_entry_to_front(&mut header, &mut entries[0]) };

        assert_eq!(header.front, entry0);
        assert_eq!(header.back, entry1);
        assert!(entries[0].previous.is_null());
        assert_eq!(entries[0].next, entry1);
        assert_eq!(entries[1].previous, entry0);
    }

    #[test]
    fn lookup_promotes_the_matching_entry_before_returning_its_payload() {
        let mut entries = [entry(3), entry(5), entry(7)];
        entries[0].next = &mut entries[1];
        entries[1].previous = &mut entries[0];
        entries[1].next = &mut entries[2];
        entries[2].previous = &mut entries[1];
        let expected_payload = entries[2].payload_start.as_mut_ptr();
        let mut header = list(&mut entries[0], &mut entries[2]);
        let mut output = ptr::null_mut();

        assert_eq!(unsafe { linked_list_find_and_promote(7, &mut header, &mut output) }, 0);
        assert_eq!(output, expected_payload);
        assert_eq!(header.front, ptr::addr_of_mut!(entries[2]));
        assert_eq!(header.back, ptr::addr_of_mut!(entries[1]));
    }

    #[test]
    fn lookup_skips_sentinel_keys_and_preserves_output_on_a_miss() {
        let mut entries = [entry(u32::MAX), entry(9)];
        entries[0].next = &mut entries[1];
        entries[1].previous = &mut entries[0];
        let mut header = list(&mut entries[0], &mut entries[1]);
        let marker = 0x1234usize as *mut u8;
        let mut output = marker;

        assert_eq!(unsafe { linked_list_find_and_promote(u32::MAX, &mut header, &mut output) }, -123);
        assert_eq!(output, marker);
        assert_eq!(header.front, ptr::addr_of_mut!(entries[0]));
        assert_eq!(header.back, ptr::addr_of_mut!(entries[1]));
    }
}
