//! `collection_selection_move_previous` — `FUN_08135950` @ `0x08135950`.
//! True extent: 156 bytes, `0x08135950..0x081359ec`, where the next function
//! starts with `push {r4,r5,r6,lr}`. Raw-word scanning verifies two incoming
//! plain BL calls and zero predicated BL calls; the body has six plain BL
//! instructions and zero predicated BL instructions.
//!
//! Walks a collection until the first item with flag byte +0x18 bit 0x10 set.
//! Remembers the last preceding item with both bits 0x08 and 0x01 set. If one
//! exists, sets its bit 0x10, clears the current item's bit 0x10, and returns
//! 1. Otherwise returns 0 without modifying items. Stops at the first marked
//! item even when no eligible predecessor exists. Invalidates the cursor on
//! every exit. Both known callers consume only r0 as a Boolean result.
//!
//! Deliberate deviations: Ghidra's four-argument/u64 signature is discarded:
//! r1-r3 are saved stack scratch, not inputs, and the restored r1 is not a
//! second return value. Uses the existing typed cursor and predicate ports;
//! host pointer slots widen naturally. A volatile cursor-index read preserves
//! the final invalidation against dead-store elimination, matching existing
//! collection consumers. No wider meaning is assigned to bits 0x08 or 0x01.

use crate::util::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};
use crate::app::object_flag_0x8_is_set::object_flag_0x8_is_set;
use crate::util::object_flag_0x10_is_set::object_flag_0x10_is_set;

/// Moves the first marked item's selection to its last eligible predecessor.
///
/// # Safety
/// `collection` must support cursor dispatch. Every yielded item must be
/// non-NULL and have a readable/writable flag byte at +0x18.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_selection_move_previous(collection: *mut Collection) -> u32 {
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, collection);
    let mut item = core::ptr::null_mut::<u8>();
    let mut previous = core::ptr::null_mut::<u8>();
    let mut changed = 0;
    while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(item).cast()) != 0 {
        if object_flag_0x10_is_set(item) != 0 {
            if !previous.is_null() {
                previous.add(0x18).write(previous.add(0x18).read() | 0x10);
                item.add(0x18).write(item.add(0x18).read() & !0x10);
                changed = 1;
            }
            break;
        }
        if object_flag_0x8_is_set(item) != 0 && item.add(0x18).read() & 1 != 0 {
            previous = item;
        }
    }
    cursor_invalidate(&mut cursor);
    core::ptr::read_volatile(core::ptr::addr_of!(cursor.index));
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::cursor::CollectionVtable;

    #[repr(C)]
    struct TestCollection {
        collection: Collection,
        items: [[u8; 25]; 4],
        len: usize,
        visits: usize,
    }

    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let collection = &mut *collection.cast::<TestCollection>();
        collection.visits += 1;
        if index < 0 || index as usize >= collection.len {
            return 0;
        }
        out.cast::<*mut u8>().write(collection.items[index as usize].as_mut_ptr());
        1
    }

    static VTABLE: CollectionVtable = CollectionVtable { unresolved: [0; 15], item_at };

    fn check(flags: &[u8], expected: &[u8], result: u32, visits: usize) {
        let mut collection = TestCollection {
            collection: Collection { vtable: &VTABLE },
            items: [[0xa5; 25]; 4], len: flags.len(), visits: 0,
        };
        for (item, flag) in collection.items.iter_mut().zip(flags) {
            item[24] = *flag;
        }
        assert_eq!(unsafe { collection_selection_move_previous(&mut collection.collection) }, result);
        assert_eq!(collection.visits, visits);
        for (item, flag) in collection.items.iter().zip(expected) {
            assert_eq!(item[24], *flag);
            assert_eq!(&item[..24], &[0xa5; 24]);
        }
    }

    #[test]
    fn empty_unmarked_and_no_eligible_predecessor_leave_flags_unchanged() {
        check(&[], &[], 0, 1);
        check(&[0x09, 0x08, 0x01], &[0x09, 0x08, 0x01], 0, 4);
        check(&[0x08, 0x01, 0x10, 0x09], &[0x08, 0x01, 0x10, 0x09], 0, 3);
        check(&[0x19, 0x09, 0x10], &[0x19, 0x09, 0x10], 0, 1);
    }

    #[test]
    fn last_eligible_predecessor_wins_and_later_marked_items_are_untouched() {
        check(&[0x89, 0xc9, 0xff, 0x10], &[0x89, 0xd9, 0xef, 0x10], 1, 3);
        check(&[0x09, 0x08, 0x01, 0x10], &[0x19, 0x08, 0x01, 0x00], 1, 4);
    }

    #[test]
    fn all_predecessor_flag_combinations_preserve_unrelated_bits() {
        for flag in 0u8..=255 {
            let moves = flag & 0x10 == 0 && flag & 0x09 == 0x09;
            let first_marked = flag & 0x10 != 0;
            check(&[flag, 0xf0],
                &[if moves { flag | 0x10 } else { flag }, if moves { 0xe0 } else { 0xf0 }],
                moves as u32, if first_marked { 1 } else { 2 });
        }
    }
}
