//! Counts unflagged collection items.
//!
//! Original: `FUN_0826b984` @ 0x0826b984 (76 bytes; 6 verified plain
//! `bl` call sites, 0 predicated). It initializes a collection cursor from
//! `owner.collection`, walks every item, and counts those whose byte at +0x4
//! has bit 0 clear. The cursor is invalidated after the walk.
//!
//! Deliberate deviations: the retailOS owner and item layouts are only
//! modeled through the fields read here. Host pointer widths make the named
//! `collection` field wider than its target +0x4 placement; the target layout
//! assertion below verifies the 32-bit ABI. The raw-verified but otherwise
//! unported `FUN_0829d3c0` predicate is inlined rather than given a speculative
//! identity or a new dispatch seam. A volatile function-pointer read retains
//! the otherwise-dead cursor invalidation call on the target.

use core::ffi::c_void;
use core::ptr;

use super::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};

/// Object holding the collection counted by [`count_unflagged_collection_items`].
#[repr(C)]
pub struct CollectionOwner {
    /// Untouched vtable pointer at +0x0.
    pub vtable: *const c_void,
    /// Collection walked by the original's `ldr r1, [r0, #4]`.
    pub collection: *mut Collection,
}

/// Collection item observed only through its status byte at +0x4.
#[repr(C)]
pub struct FlaggedCollectionItem {
    /// Untouched word at +0x0.
    pub unresolved: u32,
    /// Bit 0 set marks the item excluded from this count.
    pub flags: u8,
}

#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;

    const _: [u8; 0x04] = [0; core::mem::offset_of!(CollectionOwner, collection)];
    const _: [u8; 0x04] = [0; core::mem::offset_of!(FlaggedCollectionItem, flags)];
}

/// count_unflagged_collection_items — original: `FUN_0826b984` @ 0x0826b984
/// (76 bytes; 6 verified plain `bl` call sites, 0 predicated).
///
/// Walks `owner.collection` with the shared cursor machinery and returns the
/// number of items whose status byte has bit 0 clear. The original has no
/// null guards for `owner`, the collection, or yielded items; this port keeps
/// that contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn count_unflagged_collection_items(owner: *mut CollectionOwner) -> u32 {
    let mut cursor = Cursor {
        collection: ptr::null_mut(),
        index: 0,
    };
    cursor_init(&mut cursor, (*owner).collection);

    let mut item: *mut FlaggedCollectionItem = ptr::null_mut();
    let mut count = 0;
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
        if (*item).flags & 1 == 0 {
            count += 1;
        }
    }

    let invalidate = unsafe {
        core::ptr::read_volatile(&(cursor_invalidate as unsafe extern "C" fn(*mut Cursor)))
    };
    invalidate(&mut cursor);
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use super::super::cursor::CollectionVtable;

    #[repr(C)]
    struct TestCollection {
        collection: Collection,
        len: usize,
        items: [*mut FlaggedCollectionItem; 4],
    }

    unsafe extern "C" fn item_at(
        collection: *mut Collection,
        index: i32,
        out: *mut u8,
    ) -> u32 {
        let collection = collection.cast::<TestCollection>();
        if index < 0 || index as usize >= (*collection).len {
            return 0;
        }
        *out.cast::<*mut FlaggedCollectionItem>() = (*collection).items[index as usize];
        1
    }

    #[test]
    fn returns_zero_for_an_empty_collection() {
        let vtable = CollectionVtable {
            unresolved: [0; 15],
            item_at,
        };
        let mut collection = TestCollection {
            collection: Collection { vtable: &vtable },
            len: 0,
            items: [ptr::null_mut(); 4],
        };
        let mut owner = CollectionOwner {
            vtable: ptr::null(),
            collection: &mut collection.collection,
        };

        assert_eq!(unsafe { count_unflagged_collection_items(&mut owner) }, 0);
    }

    #[test]
    fn counts_only_items_with_clear_low_status_bit() {
        let mut items = [
            FlaggedCollectionItem { unresolved: 0, flags: 0x00 },
            FlaggedCollectionItem { unresolved: 0, flags: 0x01 },
            FlaggedCollectionItem { unresolved: 0, flags: 0xfe },
            FlaggedCollectionItem { unresolved: 0, flags: 0xff },
        ];
        let vtable = CollectionVtable {
            unresolved: [0; 15],
            item_at,
        };
        let mut collection = TestCollection {
            collection: Collection { vtable: &vtable },
            len: items.len(),
            items: [
                core::ptr::addr_of_mut!(items[0]),
                core::ptr::addr_of_mut!(items[1]),
                core::ptr::addr_of_mut!(items[2]),
                core::ptr::addr_of_mut!(items[3]),
            ],
        };
        let mut owner = CollectionOwner {
            vtable: ptr::null(),
            collection: &mut collection.collection,
        };

        assert_eq!(unsafe { count_unflagged_collection_items(&mut owner) }, 2);
    }
}
