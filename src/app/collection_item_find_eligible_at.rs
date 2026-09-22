//! `collection_item_find_eligible_at` — original: `FUN_0826b91c` @ `0x0826b91c`
//! (104 bytes; 4 plain `bl` instructions, 0 predicated `bl` instructions).
//!
//! Raw ARM establishes the extent `0x0826b91c..0x0826b984`: the next function
//! starts with `push {r1,r2,r3,r4,r5,lr}` at `0x0826b984`. The four direct
//! calls initialize, advance, and invalidate the shared cursor, plus the
//! one-instruction eligibility predicate at `0x0829d3c0`.
//!
//! # Algorithm
//!
//! Walks the collection in `owner + 4`, counting only items whose flag byte at
//! `+4` has bit zero clear. Returns the zero-based `ordinal`th eligible item,
//! or NULL when the cursor is exhausted. The cursor is invalidated on either
//! exit.
//!
//! # Deliberate deviations
//!
//! The verified `0x0829d3c0` predicate (`~item[4] & 1`) is inlined as its
//! equivalent bit test rather than creating an exported one-instruction seam.

use crate::util::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};

/// Target-layout owner whose collection field is at `+0x04` on 32-bit ARM.
#[repr(C)]
pub struct CollectionOwner {
    pub unresolved_00: u32,
    pub collection: *mut Collection,
}

/// Returns the `ordinal`th item whose flag byte at `+4` has bit zero clear.
///
/// # Safety
///
/// `owner` and its collection must be valid for the shared cursor dispatch.
/// Every item yielded by the collection must be non-NULL and readable at `+4`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_item_find_eligible_at(
    owner: *mut CollectionOwner,
    ordinal: u32,
) -> *mut u8 {
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, (*owner).collection);

    let mut item = core::ptr::null_mut::<u8>();
    let mut eligible_index = 0u32;
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
        if item.add(4).read() & 1 == 0 {
            if ordinal == eligible_index {
                cursor_invalidate(&mut cursor);
                core::ptr::read_volatile(core::ptr::addr_of!(cursor.index));
                return item;
            }
            eligible_index = eligible_index.wrapping_add(1);
        }
    }

    cursor_invalidate(&mut cursor);
    core::ptr::read_volatile(core::ptr::addr_of!(cursor.index));
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::{collection_item_find_eligible_at, CollectionOwner};
    use crate::util::cursor::{Collection, CollectionVtable};

    #[repr(C)]
    struct TestCollection {
        collection: Collection,
        items: [*mut Item; 4],
        len: usize,
    }

    #[repr(C)]
    struct Item {
        value: u32,
        flags: u8,
    }

    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let collection = collection.cast::<TestCollection>();
        if index < 0 || index as usize >= (*collection).len {
            return 0;
        }
        out.cast::<*mut Item>().write((*collection).items[index as usize]);
        1
    }

    static COLLECTION_VTABLE: CollectionVtable = CollectionVtable {
        unresolved: [0; 15],
        item_at,
    };

    fn collection(items: [*mut Item; 4], len: usize) -> TestCollection {
        TestCollection { collection: Collection { vtable: &COLLECTION_VTABLE }, items, len }
    }

    #[test]
    fn selects_by_eligible_ordinal_skipping_flagged_items() {
        let mut first = Item { value: 1, flags: 1 };
        let mut second = Item { value: 2, flags: 0 };
        let mut third = Item { value: 3, flags: 3 };
        let mut fourth = Item { value: 4, flags: 0 };
        let mut items = collection([
            &mut first,
            &mut second,
            &mut third,
            &mut fourth,
        ], 4);
        let mut owner = CollectionOwner { unresolved_00: 0, collection: &mut items.collection };

        assert_eq!(unsafe { collection_item_find_eligible_at(&mut owner, 0) }, core::ptr::addr_of_mut!(second).cast());
        assert_eq!(unsafe { collection_item_find_eligible_at(&mut owner, 1) }, core::ptr::addr_of_mut!(fourth).cast());
    }

    #[test]
    fn returns_null_when_no_requested_eligible_item_exists() {
        let mut flagged = Item { value: 1, flags: 1 };
        let mut items = collection([&mut flagged, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()], 1);
        let mut owner = CollectionOwner { unresolved_00: 0, collection: &mut items.collection };

        assert!(unsafe { collection_item_find_eligible_at(&mut owner, 0) }.is_null());
        assert!(unsafe { collection_item_find_eligible_at(&mut owner, 1) }.is_null());
    }
}
