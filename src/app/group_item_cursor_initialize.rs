//! Group/item traversal cursor constructor at 0x0816373c (128 bytes,
//! ending at the real prologue at 0x081637bc). Raw BL-word scan: two incoming
//! plain BL sites, no predicated incoming BL; three outgoing plain BLs,
//! no predicated outgoing BLs (cursor_init, cursor_advance, cursor_invalidate).
//!
//! Stores the starting group and item index, walks the group collection, and
//! caches signed key bounds from group word 8 (+0x20). The upper bound is a
//! maximum; the lower bound deliberately compares the STARTING group's key
//! before assigning the CURRENT group's key. This is not a corrected minimum.
//! Empty collections retain i32::MAX/i32::MIN. Returns the destination in r0.
//! Deliberate ABI recovery: Ghidra's u64 result mistakes restored scratch r1
//! for a second return word; callers use the object, not that scratch value.
//! Typed pointer fields widen on hosts; the target retains the 16-byte layout.
//! LLVM removes the final invalidation of the dead stack cursor and splits
//! loop entry from the back edge; signed conditional bound stores remain.

use crate::util::cursor::{Collection, Cursor, cursor_init, cursor_advance, cursor_invalidate};

#[repr(C)]
pub struct GroupItemCursor {
    pub group: *const i32,
    pub item_index: i32,
    pub lower_key: i32,
    pub upper_key: i32,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 16] = [(); core::mem::size_of::<GroupItemCursor>()];

/// Initialize a traversal cursor and its cached group-key bounds.
/// The destination, collection and successful accessor outputs must be valid;
/// group word 8 must be readable whenever the collection yields an item.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn group_item_cursor_initialize(
    destination: *mut GroupItemCursor,
    collection: *mut Collection,
    starting_group: *const i32,
    item_index: i32,
) -> *mut GroupItemCursor {
    (*destination).group = starting_group;
    (*destination).item_index = item_index;
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, collection);
    let mut current_group: *const i32 = core::ptr::null();
    (*destination).lower_key = i32::MAX;
    (*destination).upper_key = i32::MIN;
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(current_group).cast()) != 0 {
        let key = current_group.add(8).read();
        if key > (*destination).upper_key {
            (*destination).upper_key = key;
        }
        if starting_group.add(8).read() < (*destination).lower_key {
            (*destination).lower_key = current_group.add(8).read();
        }
    }
    cursor_invalidate(&mut cursor);
    destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cursor::CollectionVtable;

    #[repr(C)]
    struct Groups {
        collection: Collection,
        items: *const [i32; 9],
        count: usize,
    }

    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let groups = &*(collection as *const Groups);
        if index < 0 || index as usize >= groups.count { return 0; }
        out.cast::<*const i32>().write(groups.items.add(index as usize).cast());
        7
    }

    #[test]
    fn signed_bounds_preserve_starting_key_comparison() {
        let vtable = CollectionVtable { unresolved: [0; 15], item_at };
        for (keys, start_key, expected_lower, expected_upper) in [
            ([0, 0, 0], 0, 0, 0),
            ([10, -20, 30], 5, -20, 30),
            ([-10, -20, 30], 5, -10, 30),
            ([i32::MIN, 0, i32::MAX], i32::MAX, i32::MAX, i32::MAX),
            ([3, 2, 1], i32::MIN, 1, 3),
        ] {
            let mut items = [[0; 9]; 3];
            for (item, key) in items.iter_mut().zip(keys) { item[8] = key; }
            let mut starting = [0; 9];
            starting[8] = start_key;
            let mut groups = Groups { collection: Collection { vtable: &vtable }, items: items.as_ptr(), count: 3 };
            let mut result = GroupItemCursor { group: core::ptr::null(), item_index: 0, lower_key: 0, upper_key: 0 };
            unsafe {
                let returned = group_item_cursor_initialize(&mut result, &mut groups.collection, starting.as_ptr(), -17);
                assert_eq!(returned, core::ptr::addr_of_mut!(result));
            }
            assert_eq!(result.group, starting.as_ptr());
            assert_eq!(result.item_index, -17);
            assert_eq!((result.lower_key, result.upper_key), (expected_lower, expected_upper));
        }
    }

    #[test]
    fn empty_collection_does_not_dereference_starting_group() {
        let vtable = CollectionVtable { unresolved: [0; 15], item_at };
        let mut groups = Groups { collection: Collection { vtable: &vtable }, items: core::ptr::null(), count: 0 };
        let mut result = GroupItemCursor { group: core::ptr::null(), item_index: 0, lower_key: 0, upper_key: 0 };
        unsafe { group_item_cursor_initialize(&mut result, &mut groups.collection, core::ptr::null(), i32::MIN); }
        assert!(result.group.is_null());
        assert_eq!(result.item_index, i32::MIN);
        assert_eq!((result.lower_key, result.upper_key), (i32::MAX, i32::MIN));
    }
}
