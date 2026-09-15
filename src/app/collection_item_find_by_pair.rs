//! `collection_item_find_by_pair` — original: `FUN_0821129c` @ `0x0821129c`
//! (116 bytes; 4 plain `bl` instructions, 0 predicated `bl` instructions).
//!
//! # Algorithm
//!
//! Walks the collection embedded at `owner + 8`, comparing the first two words
//! of each yielded item against `first` and `second`. It invalidates the cursor
//! before returning either the matching item or NULL. No deliberate deviations.

use crate::util::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};

/// Finds the first item in `owner`'s collection whose first two words match.
///
/// Original: `FUN_0821129c` @ `0x0821129c` (116 bytes). The collection begins
/// at target offset `+0x08`; returned items must be readable for two aligned
/// `u32` words, matching the retail loads.
///
/// # Safety
///
/// `owner + 8` must be a valid [`Collection`], and its accessor must write
/// either NULL or a valid two-word item pointer to its output slot.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_item_find_by_pair(
    owner: *mut u8,
    first: u32,
    second: u32,
) -> *mut u8 {
    let collection = owner.add(8).cast::<Collection>();
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, collection);

    let mut item = core::ptr::null_mut::<u8>();
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
        if item.cast::<u32>().read() == first && item.cast::<u32>().add(1).read() == second {
            cursor_invalidate(&mut cursor);
            return item;
        }
    }

    cursor_invalidate(&mut cursor);
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::collection_item_find_by_pair;
    use crate::util::cursor::{Collection, CollectionVtable};

    #[repr(C)]
    struct Owner {
        prefix: [u32; 2],
        collection: Collection,
        items: [*mut Item; 3],
        len: usize,
    }

    #[repr(C)]
    struct Item {
        first: u32,
        second: u32,
        payload: u32,
    }

    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let owner = (collection.cast::<u8>().sub(8)).cast::<Owner>();
        if index < 0 || index as usize >= (*owner).len {
            out.cast::<*mut Item>().write(core::ptr::null_mut());
            return 0;
        }
        out.cast::<*mut Item>().write((*owner).items[index as usize]);
        1
    }

    static COLLECTION_VTABLE: CollectionVtable = CollectionVtable {
        unresolved: [0; 15],
        item_at,
    };

    fn owner(items: [*mut Item; 3], len: usize) -> Owner {
        Owner {
            prefix: [0; 2],
            collection: Collection { vtable: &COLLECTION_VTABLE },
            items,
            len,
        }
    }

    #[test]
    fn returns_the_first_exact_pair_match() {
        let mut first = Item { first: 7, second: 9, payload: 1 };
        let mut matching = Item { first: 7, second: 9, payload: 2 };
        let mut trailing = Item { first: 7, second: 9, payload: 3 };
        let mut owner = owner([&mut first, &mut matching, &mut trailing], 3);

        let found = unsafe { collection_item_find_by_pair((&mut owner as *mut Owner).cast(), 7, 9) };

        assert_eq!(found, (&mut first as *mut Item).cast());
    }

    #[test]
    fn requires_both_words_and_returns_null_when_absent() {
        let mut first_word_only = Item { first: 4, second: 8, payload: 0 };
        let mut second_word_only = Item { first: 3, second: 5, payload: 0 };
        let mut owner = owner([&mut first_word_only, &mut second_word_only, core::ptr::null_mut()], 2);

        let found = unsafe { collection_item_find_by_pair((&mut owner as *mut Owner).cast(), 3, 8) };

        assert!(found.is_null());
    }
}
