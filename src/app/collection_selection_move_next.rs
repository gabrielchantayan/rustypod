//! `collection_selection_move_next` — `FUN_08135894` @ `0x08135894`.
//! True extent: 188 bytes, `0x08135894..0x08135950`; the next function
//! begins with `push {r1-r5,lr}`. Raw-word decoding verifies two incoming
//! plain BL calls, seven outgoing plain BL instructions, and zero predicated
//! BL forms in either count.
//!
//! Finds the first item with byte +0x18 bit 0x10 set, then scans strictly
//! later items for the first with bits 0x08 and 0x01 both set. Clears the
//! former's bit 0x10 before setting the latter's, returning 1; exhaustion
//! returns 0 without writes. The first scan tests advance == 1, whereas the
//! second accepts any nonzero result. Cursor invalidation occurs on all exits.
//!
//! Deliberate deviations: discard Ghidra's spurious r1-r3 arguments, which
//! are saved scratch slots, not caller inputs. Reuse the typed cursor and
//! existing flag predicates; host pointer slots widen naturally. A volatile
//! index read retains final invalidation, as in the previous-selection port.
//! No unverified object type or wider flag meaning is assigned.

use crate::util::cursor::{cursor_advance, cursor_init, cursor_invalidate, Collection, Cursor};
use crate::app::object_flag_0x8_is_set::object_flag_0x8_is_set;
use crate::util::object_flag_0x10_is_set::object_flag_0x10_is_set;

/// Transfers selection to the first later eligible item.
///
/// # Safety
/// `collection` must support cursor dispatch. Successful dispatch must write
/// a non-NULL item pointer with readable/writable byte +0x18. A nonzero result
/// other than 1 in the first scan must also leave a valid item in its output.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_selection_move_next(collection: *mut Collection) -> u32 {
    let mut cursor = Cursor { collection: core::ptr::null_mut(), index: 0 };
    cursor_init(&mut cursor, collection);
    let mut current = core::ptr::null_mut::<u8>();
    let found = loop {
        let status = cursor_advance(&mut cursor, core::ptr::addr_of_mut!(current).cast());
        if status != 1 || object_flag_0x10_is_set(current) != 0 {
            break status;
        }
    };
    let mut changed = 0;
    if found != 0 {
        let mut next = core::ptr::null_mut::<u8>();
        while cursor_advance(&mut cursor, core::ptr::addr_of_mut!(next).cast()) != 0 {
            if object_flag_0x8_is_set(next) != 0 && next.add(0x18).read() & 1 != 0 {
                current.add(0x18).write(current.add(0x18).read() & !0x10);
                next.add(0x18).write(next.add(0x18).read() | 0x10);
                changed = 1;
                break;
            }
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
        items: [[u8; 25]; 5],
        len: usize,
        visits: usize,
        statuses: [u32; 5],
        alias_second: bool,
    }

    unsafe extern "C" fn item_at(collection: *mut Collection, index: i32, out: *mut u8) -> u32 {
        let collection = &mut *collection.cast::<TestCollection>();
        collection.visits += 1;
        if index < 0 || index as usize >= collection.len {
            return 0;
        }
        let index = index as usize;
        let item = if collection.alias_second && index == 1 { 0 } else { index };
        out.cast::<*mut u8>().write(collection.items[item].as_mut_ptr());
        collection.statuses[index]
    }

    static VTABLE: CollectionVtable = CollectionVtable { unresolved: [0; 15], item_at };

    fn check(flags: &[u8], statuses: [u32; 5], alias_second: bool,
             expected: &[u8], result: u32, visits: usize) {
        let mut collection = TestCollection {
            collection: Collection { vtable: &VTABLE }, items: [[0xa5; 25]; 5],
            len: flags.len(), visits: 0, statuses, alias_second,
        };
        for (item, flag) in collection.items.iter_mut().zip(flags) { item[24] = *flag; }
        assert_eq!(unsafe { collection_selection_move_next(&mut collection.collection) }, result);
        assert_eq!(collection.visits, visits);
        for (item, flag) in collection.items.iter().zip(expected) {
            assert_eq!(item[24], *flag);
            assert_eq!(&item[..24], &[0xa5; 24]);
        }
    }

    #[test]
    fn exhaustion_and_missing_successor_do_not_change_flags() {
        check(&[], [1; 5], false, &[], 0, 1);
        check(&[9, 8, 1], [1; 5], false, &[9, 8, 1], 0, 4);
        check(&[9, 0x10, 8, 1], [1; 5], false, &[9, 0x10, 8, 1], 0, 5);
        check(&[9, 0x19], [1; 5], false, &[9, 0x19], 0, 3);
    }

    #[test]
    fn first_later_eligible_item_wins_without_wraparound() {
        check(&[9, 0xf0, 8, 0x89, 0x19], [1; 5], false,
              &[9, 0xe0, 8, 0x99, 0x19], 1, 4);
        check(&[0x10, 0x10, 9], [1; 5], false, &[0, 0x10, 0x19], 1, 3);
    }

    #[test]
    fn every_successor_flag_combination_preserves_other_bits() {
        for flag in 0u8..=255 {
            let eligible = flag & 9 == 9;
            check(&[0xf0, flag], [1; 5], false,
                  &[if eligible { 0xe0 } else { 0xf0 }, if eligible { flag | 0x10 } else { flag }],
                  eligible as u32, if eligible { 2 } else { 3 });
        }
    }

    #[test]
    fn noncanonical_accessor_results_preserve_asymmetric_scan_conditions() {
        check(&[0, 9], [2, 1, 1, 1, 1], false, &[0, 0x19], 1, 2);
        check(&[0x10, 9], [1, 2, 1, 1, 1], false, &[0, 0x19], 1, 2);
    }

    #[test]
    fn aliased_items_preserve_clear_then_set_order() {
        check(&[0x99, 0], [1; 5], true, &[0x99, 0], 1, 2);
    }
}
