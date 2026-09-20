//! Trigger availability test — SQLite 3.5.9's `sqlite3TriggersExist`.
//!
//! `triggers_exist` is `FUN_08385220` at 0x08385220. Raw `osos.dec` words
//! establish the 92-byte extent 0x08385220..0x0838527c: the next `stmdb`
//! begins at 0x0838527c. Its body has one unconditional `bl` (to
//! `checkColumnOverlap` @ 0x082c24f0) and no predicated `bl`; Ghidra reports
//! three direct `bl` callers.
//!
//! For a non-virtual table, walk its trigger chain. A trigger whose operation
//! matches `op` and whose update-column list overlaps `changes` contributes
//! its before/after/instead-of mask to the result. Virtual tables deliberately
//! report no triggers. The overlap helper is not ported, so its direct call is
//! represented by a volatile seam; host tests install the exact predicate.

const TABLE_TRIGGER_LIST: usize = 0x20;
const TABLE_IS_VIRTUAL: usize = 0x39;
const TRIGGER_OPERATION: usize = 0x08;
const TRIGGER_TIMING_MASK: usize = 0x09;
const TRIGGER_COLUMNS: usize = 0x10;
const TRIGGER_NEXT: usize = 0x28;

/// `checkColumnOverlap` @ 0x082c24f0, as called with a trigger's column list
/// and the update's changed-column list.
pub type CheckColumnOverlap = unsafe extern "C" fn(*const u8, *const u8) -> i32;

unsafe extern "C" fn missing_check_column_overlap(_columns: *const u8, _changes: *const u8) -> i32 {
    0
}

pub static mut TRIGGER_OPS: CheckColumnOverlap = missing_check_column_overlap;

#[inline(always)]
unsafe fn check_column_overlap() -> CheckColumnOverlap {
    core::ptr::read_volatile(core::ptr::addr_of!(TRIGGER_OPS))
}

#[inline(always)]
unsafe fn target_word(pointer: *const u8, offset: usize) -> *const u8 {
    (core::ptr::read_unaligned(pointer.add(offset) as *const u32) as usize) as *const u8
}

/// `sqlite3TriggersExist` — original: `FUN_08385220` @ 0x08385220 (92 bytes;
/// 3 direct `bl` callers, one body `bl`, none predicated).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn triggers_exist(
    _parse: *const u8,
    table: *const u8,
    op: u32,
    changes: *const u8,
) -> u8 {
    let mut trigger = if core::ptr::read(table.add(TABLE_IS_VIRTUAL)) == 0 {
        target_word(table, TABLE_TRIGGER_LIST)
    } else {
        core::ptr::null()
    };
    let mut mask = 0u8;
    while !trigger.is_null() {
        if core::ptr::read(trigger.add(TRIGGER_OPERATION)) as u32 == op
            && check_column_overlap()(target_word(trigger, TRIGGER_COLUMNS), changes) != 0 {
            mask |= core::ptr::read(trigger.add(TRIGGER_TIMING_MASK));
        }
        trigger = target_word(trigger, TRIGGER_NEXT);
    }
    mask
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EXPECTED_COLUMNS: *const u8 = core::ptr::null();
    static mut EXPECTED_CHANGES: *const u8 = core::ptr::null();

    unsafe extern "C" fn overlaps(columns: *const u8, changes: *const u8) -> i32 {
        if columns == EXPECTED_COLUMNS && changes == EXPECTED_CHANGES { 1 } else { 0 }
    }

    unsafe fn word(at: *mut u8, offset: usize, value: *const u8) {
        (at.add(offset) as *mut u32).write_unaligned(value as usize as u32);
    }

    #[test]
    fn combines_only_matching_overlapping_trigger_masks() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SQLITE_TRIGGERS_EXIST, 0x1000) else { return };
        unsafe {
            let table = slab;
            let first = slab.add(0x100);
            let second = slab.add(0x180);
            let third = slab.add(0x200);
            let columns = slab.add(0x300);
            let changes = slab.add(0x380);
            word(table, TABLE_TRIGGER_LIST, first);
            first.add(TRIGGER_OPERATION).write(99);
            first.add(TRIGGER_TIMING_MASK).write(1);
            word(first, TRIGGER_COLUMNS, columns);
            word(first, TRIGGER_NEXT, second);
            second.add(TRIGGER_TIMING_MASK).write(2);
            word(second, TRIGGER_COLUMNS, columns);
            word(second, TRIGGER_NEXT, third);
            third.add(TRIGGER_OPERATION).write(100);
            third.add(TRIGGER_TIMING_MASK).write(4);
            word(third, TRIGGER_COLUMNS, columns);
            EXPECTED_COLUMNS = columns;
            EXPECTED_CHANGES = changes;
            TRIGGER_OPS = overlaps;
            assert_eq!(triggers_exist(core::ptr::null(), table, 99, changes), 1);
            third.add(TRIGGER_OPERATION).write(99);
            assert_eq!(triggers_exist(core::ptr::null(), table, 99, changes), 5);
        }
    }

    #[test]
    fn virtual_table_skips_the_trigger_chain() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SQLITE_TRIGGERS_EXIST_VIRTUAL, 0x1000) else { return };
        unsafe {
            slab.add(TABLE_IS_VIRTUAL).write(1);
            TRIGGER_OPS = overlaps;
            assert_eq!(triggers_exist(core::ptr::null(), slab, 99, slab.add(0x300)), 0);
        }
    }
}
