//! `collection_item_find_by_key` — original: `FUN_0809e1bc` @ `0x0809e1bc`
//! (104 bytes; 4 plain `bl` instructions, 0 predicated `bl` instructions).
//!
//! # Algorithm
//! Walks the supplied collection through the shared cursor, returning the first
//! yielded item whose aligned word at target offset `+0x20` equals `key`. It
//! invalidates the cursor before either return. A volatile post-invalidate
//! read retains the cursor invalidation in optimized code without observing
//! firmware state; LLVM deliberately folds the equivalent exit paths.

use crate::util::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};

/// Finds the first collection item with `key` in its target word at `+0x20`.
///
/// Original: `FUN_0809e1bc` @ `0x0809e1bc` (104 bytes). Raw firmware ends at
/// the next separately entered function, `0x0809e224`.
///
/// # Safety
///
/// `collection` must be valid for the cursor's vtable dispatch. Each yielded
/// item must be non-null and readable through its aligned `u32` at `+0x20`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_item_find_by_key(collection: *mut Collection, key: u32) -> *mut u8 {
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, collection);

    let mut item = core::ptr::null_mut::<u8>();
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
        if item.add(0x20).cast::<u32>().read() == key {
            cursor_invalidate(&mut cursor);
            core::ptr::read_volatile(core::ptr::addr_of!(cursor.index));
            return item;
        }
    }

    cursor_invalidate(&mut cursor);
    core::ptr::read_volatile(core::ptr::addr_of!(cursor.index));
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::collection_item_find_by_key;
    use crate::util::cursor::{Collection, CollectionVtable};

    #[repr(C)]
    struct TestCollection {
        collection: Collection,
        items: [*mut Item; 3],
        len: usize,
    }

    #[repr(C)]
    struct Item {
        prefix: [u32; 8],
        key: u32,
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

    fn collection(items: [*mut Item; 3], len: usize) -> TestCollection {
        TestCollection { collection: Collection { vtable: &COLLECTION_VTABLE }, items, len }
    }

    #[test]
    fn returns_the_first_matching_item() {
        let mut first = Item { prefix: [0; 8], key: 7 };
        let mut second = Item { prefix: [0; 8], key: 42 };
        let mut third = Item { prefix: [0; 8], key: 42 };
        let mut collection = collection([&mut first, &mut second, &mut third], 3);

        let found = unsafe { collection_item_find_by_key(&mut collection.collection, 42) };

        assert_eq!(found, core::ptr::addr_of_mut!(second).cast());
    }

    #[test]
    fn returns_null_for_empty_and_missing_keys() {
        let mut item = Item { prefix: [0; 8], key: 7 };
        let mut empty = collection([core::ptr::null_mut(); 3], 0);
        let mut nonmatching = collection([&mut item, core::ptr::null_mut(), core::ptr::null_mut()], 1);

        assert!(unsafe { collection_item_find_by_key(&mut empty.collection, 7) }.is_null());
        assert!(unsafe { collection_item_find_by_key(&mut nonmatching.collection, 8) }.is_null());
    }
}
