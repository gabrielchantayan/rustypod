//! Input-sequence item lookup — `FUN_0812b018` @ **0x0812b018**.
//!
//! Raw `osos.dec` establishes a 104-byte body from `0x0812b018` through
//! `0x0812b07c`; the next independently linked function begins at
//! `0x0812b080`. The body has four unconditional `bl` instructions to three
//! already-ported cursor callees (`cursor_init` once, `cursor_advance` once,
//! and `cursor_invalidate` twice), with no predicated `bl` instructions.
//!
//! Selects the collection at owner word `+0xac` when `mode` is zero, otherwise
//! `+0xa8`; walks it and returns the first item whose signed byte at `+0x10`
//! equals `action_index`. Every exit invalidates the cursor. Deliberate
//! deviations: the target's two 32-bit collection fields are read as word
//! indices rather than Rust pointer fields, preserving their offsets on hosts.

use crate::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};

/// Finds an item by its signed action-index byte in the mode-selected collection.
///
/// # Safety
///
/// `owner` must have valid 32-bit collection pointers at word indices 42 and
/// 43; each selected collection and yielded item must be valid for the cursor
/// walk and the item's byte at `+0x10` must be readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_sequence_find_item(
    owner: *mut u8,
    action_index: i32,
    mode: u32,
) -> *mut u8 {
    let collection_word = if mode == 0 { 43 } else { 42 };
    let collection = owner.cast::<u32>().add(collection_word).read() as usize as *mut Collection;
    let mut cursor = Cursor {
        collection: core::ptr::null_mut(),
        index: 0,
    };
    cursor_init(&mut cursor, collection);

    let mut item: *mut u8 = core::ptr::null_mut();
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
        if item.add(0x10).read() as i8 as i32 == action_index {
            cursor_invalidate(&mut cursor);
            return item;
        }
    }
    cursor_invalidate(&mut cursor);
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::cursor::CollectionVtable;

    #[repr(C)]
    struct Item {
        bytes: [u8; 17],
    }

    #[repr(C)]
    struct TestCollection {
        vtable: *const CollectionVtable,
        items: [*mut u8; 2],
    }

    unsafe extern "C" fn item_at(this: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let collection = this.cast::<TestCollection>();
        if index < 0 || index >= 2 {
            return 0;
        }
        (out as *mut *mut u8).write((*collection).items[index as usize]);
        1
    }

    static VTABLE: CollectionVtable = CollectionVtable {
        unresolved: [0; 15],
        item_at,
    };

    #[test]
    fn selects_the_mode_collection_and_matches_signed_action_indices() {
        let Some(slab) = try_map_u32_slab(hints::INPUT_SEQUENCE_FIND_ITEM, 0x1000) else {
            assert!(note_missing_u32_fixture("input_sequence_find_item"));
            return;
        };
        unsafe {
            let primary_items = slab.add(0x100).cast::<Item>();
            primary_items.write(Item { bytes: [0; 17] });
            (*primary_items).bytes[16] = 7;
            primary_items.add(1).write(Item { bytes: [0; 17] });
            (*primary_items.add(1)).bytes[16] = 0xfe;

            let alternate_items = slab.add(0x200).cast::<Item>();
            alternate_items.write(Item { bytes: [0; 17] });
            (*alternate_items).bytes[16] = 3;
            alternate_items.add(1).write(Item { bytes: [0; 17] });
            (*alternate_items.add(1)).bytes[16] = 7;

            let primary = slab.add(0x300).cast::<TestCollection>();
            primary.write(TestCollection { vtable: &VTABLE, items: [primary_items.cast(), primary_items.add(1).cast()] });
            let alternate = slab.add(0x400).cast::<TestCollection>();
            alternate.write(TestCollection { vtable: &VTABLE, items: [alternate_items.cast(), alternate_items.add(1).cast()] });
            slab.cast::<u32>().add(42).write(primary as u32);
            slab.cast::<u32>().add(43).write(alternate as u32);

            assert_eq!(input_sequence_find_item(slab, 7, 0), alternate_items.add(1).cast());
            assert_eq!(input_sequence_find_item(slab, 7, 1), primary_items.cast());
            assert_eq!(input_sequence_find_item(slab, -2, 1), primary_items.add(1).cast());
            assert!(input_sequence_find_item(slab, 99, 0).is_null());
        }
    }
}
