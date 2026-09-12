//! Window-list entry lookup by key.
//!
//! `window_list_find_by_key` — original: `FUN_082775f4` @ **0x082775f4**,
//! 96 bytes (`0x082775f4..0x08277654`; the next separately linked function
//! begins at `0x08277654`). Raw whole-image ARM B/BL decoding finds exactly
//! seven direct call sites, all unconditional `bl` instructions
//! (0x0817fc90, 0x08180d14, 0x08182d60, 0x08182fb4, 0x0818375c, 0x08183cf4,
//! and 0x08184430); there are no predicated calls, tail branches, or aligned
//! data-word references to this entry.
//!
//! # Algorithm
//!
//! Initialize a collection cursor over the list's embedded collection at
//! +0x80. Advance until an entry's u32 key at +0x100 equals `key`; invalidate
//! the cursor and return that entry on success. Invalidate and return NULL
//! after an exhausted traversal. The already ported cursor family supplies
//! the collection's vtable dispatch.
//!
//! # Deliberate deviations
//!
//! Ghidra infers four parameters because the prologue saves r1-r3, but raw
//! ARM reads only r0 (the list) and r1 (the key). The Rust ABI consequently
//! exposes those two recovered arguments. The stack item temporary is
//! initialized to NULL rather than left indeterminate; a conforming
//! `cursor_advance` writes it whenever it returns nonzero, so this changes no
//! defined retailOS behavior.

use core::mem::{offset_of, size_of};
use core::ptr;

use crate::util::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};

/// A window-list object modeled down to the embedded collection at +0x80.
#[repr(C)]
pub struct WindowList {
    _before_collection: [u32; 32],
    pub collection: Collection,
}

/// A window-list entry modeled down to its lookup key at +0x100.
#[repr(C)]
pub struct WindowListEntry {
    _before_key: [u32; 64],
    pub key: u32,
}

// Target-exact layouts; named fields keep host pointer widths disjoint.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x80] = [0; offset_of!(WindowList, collection)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x84] = [0; size_of::<WindowList>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x100] = [0; offset_of!(WindowListEntry, key)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x104] = [0; size_of::<WindowListEntry>()];

/// Finds the first list entry whose key equals `key`.
///
/// # Safety
///
/// `list` must name a readable [`WindowList`] whose collection is acceptable
/// to the cursor family. Every non-NULL item emitted by that collection must
/// name a readable [`WindowListEntry`]. The retail function validates none of
/// these pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.window_list_find_by_key")]
#[inline(never)]
pub unsafe extern "C" fn window_list_find_by_key(
    list: *mut WindowList,
    key: u32,
) -> *mut WindowListEntry {
    let mut cursor = Cursor { collection: ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, &mut (*list).collection);

    let mut entry: *mut WindowListEntry = ptr::null_mut();
    while cursor_advance(&mut cursor, ptr::addr_of_mut!(entry).cast()) != 0 {
        if (*entry).key == key {
            cursor_invalidate(&mut cursor);
            return entry;
        }
    }

    cursor_invalidate(&mut cursor);
    ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::util::cursor::CollectionVtable;


    #[repr(C)]
    struct Fixture {
        list: WindowList,
        entries: [WindowListEntry; 4],
        entry_count: usize,
    }

    unsafe extern "C" fn fixture_item_at(
        collection: *mut Collection,
        index: i32,
        out: *mut u8,
    ) -> u32 {
        let list = collection.cast::<u8>().sub(offset_of!(WindowList, collection)).cast::<WindowList>();
        let fixture = list.cast::<Fixture>();
        if index < 0 || index as usize >= (*fixture).entry_count {
            return 0;
        }

        out.cast::<*mut WindowListEntry>().write(ptr::addr_of_mut!((*fixture).entries[index as usize]));
        1
    }

    static FIXTURE_VTABLE: CollectionVtable = CollectionVtable {
        unresolved: [0; 15],
        item_at: fixture_item_at,
    };

    fn entry(key: u32) -> WindowListEntry {
        WindowListEntry { _before_key: [0; 64], key }
    }

    fn fixture(keys: [u32; 4], entry_count: usize) -> Fixture {
        Fixture {
            list: WindowList {
                _before_collection: [0; 32],
                collection: Collection { vtable: &FIXTURE_VTABLE },
            },
            entries: [entry(keys[0]), entry(keys[1]), entry(keys[2]), entry(keys[3])],
            entry_count,
        }
    }

    #[test]
    fn finds_first_matching_entry_and_stops_at_it() {
        let mut fixture = fixture([4, 9, 4, 12], 4);

        let found = unsafe { window_list_find_by_key(&mut fixture.list, 4) };

        assert_eq!(found, ptr::addr_of_mut!(fixture.entries[0]));
    }

    #[test]
    fn finds_later_entry_after_nonmatching_keys() {
        let mut fixture = fixture([3, 7, 11, 13], 4);

        let found = unsafe { window_list_find_by_key(&mut fixture.list, 11) };

        assert_eq!(found, ptr::addr_of_mut!(fixture.entries[2]));
    }

    #[test]
    fn returns_null_for_empty_and_missing_key() {
        let mut empty = fixture([1, 2, 3, 4], 0);
        let mut populated = fixture([1, 2, 3, 4], 4);

        assert!(unsafe { window_list_find_by_key(&mut empty.list, 1) }.is_null());
        assert!(unsafe { window_list_find_by_key(&mut populated.list, 5) }.is_null());
    }
}
