//! SQLite virtual-table lock tracking.
//!
//! `vtab_lock` — original: `FUN_0838d6f0` @ 0x0838d6f0 (104 bytes;
//! confirmed extent 0x0838d6f0..0x0838d758 from the next `push` function
//! boundary; one plain `bl` at 0x0838d72c and no predicated `bl`).
//!
//! SQLite 3.5.x's `sqlite3VtabLock`: find a VTable pointer in Parse's
//! `apVtabLock` array, and append it only if absent. The array is reallocated
//! to exactly `nVtabLock + 1` words. A failed resize stores NULL in the array
//! field and sets `db->mallocFailed` at +0x1e; it does not increment the count.
//!
//! Deliberate deviations: Parse is accessed as target-width words rather than
//! a host-pointer `repr(C)` layout, because its pointer fields are four bytes
//! apart in retailOS and eight on the host. Reallocation dispatches through
//! `DB_MEM_OPS.realloc`; its wired default is the ported sqlite3_realloc.

use super::mem::db_realloc_op;

const N_VTAB_LOCK_OFFSET: usize = 0x19c;
const AP_VTAB_LOCK_OFFSET: usize = 0x1a0;
const MALLOC_FAILED_OFFSET: usize = 0x1e;

#[inline(always)]
unsafe fn read_word(base: *const u8, offset: usize) -> u32 {
    (base.add(offset) as *const u32).read()
}

#[inline(always)]
unsafe fn write_word(base: *mut u8, offset: usize, value: u32) {
    (base.add(offset) as *mut u32).write(value);
}

/// vtab_lock — original: `FUN_0838d6f0` @ 0x0838d6f0 (104 bytes; one plain
/// `bl`, no predicated calls, binary-decoded).
///
/// `sqlite3VtabLock`: append `vtab` to Parse's unique virtual-table lock list.
/// The original scans with a signed `nVtabLock > index` comparison, preserving
/// its behavior for a negative count (skip scan, request zero words, then
/// increment the count if allocation succeeds).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtab_lock(parse: *mut u8, vtab: *mut u8) {
    let count = read_word(parse, N_VTAB_LOCK_OFFSET) as i32;
    let locks = read_word(parse, AP_VTAB_LOCK_OFFSET) as usize as *mut u8;
    let mut index = 0;
    while count > index {
        if (locks.add(index as usize * 4) as *const u32).read() as usize as *mut u8 == vtab {
            return;
        }
        index += 1;
    }

    let resized = (db_realloc_op())(locks, count.wrapping_add(1).wrapping_mul(4));
    write_word(parse, AP_VTAB_LOCK_OFFSET, resized as usize as u32);
    if resized.is_null() {
        let db = read_word(parse, 0) as usize as *mut u8;
        db.add(MALLOC_FAILED_OFFSET).write(1);
        return;
    }

    write_word(parse, N_VTAB_LOCK_OFFSET, count.wrapping_add(1) as u32);
    (resized.add(count as usize * 4) as *mut u32).write(vtab as usize as u32);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::mem::{DbMemOps, DB_MEM_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const DB_OFFSET: usize = 0x200;
    const LOCKS_OFFSET: usize = 0x400;
    const GROWN_OFFSET: usize = 0x500;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_VTAB_LOCK, SLAB_LEN).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static mut REALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut REALLOC_CALL: (*mut u8, i32) = (core::ptr::null_mut(), 0);

    unsafe extern "C" fn recording_realloc(p: *mut u8, n: i32) -> *mut u8 {
        REALLOC_CALL = (p, n);
        REALLOC_RESULT
    }

    unsafe extern "C" fn unused_malloc(_: i32) -> *mut u8 { core::ptr::null_mut() }

    unsafe fn fixture() -> Option<*mut u8> {
        let base = (*SLAB)? as *mut u8;
        base.write_bytes(0, SLAB_LEN);
        Some(base)
    }

    unsafe fn install_realloc(result: *mut u8) -> DbMemOps {
        REALLOC_RESULT = result;
        REALLOC_CALL = (core::ptr::null_mut(), 0);
        let old = core::ptr::read_volatile(core::ptr::addr_of!(DB_MEM_OPS));
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(DB_MEM_OPS),
            DbMemOps { malloc: unused_malloc, realloc: recording_realloc },
        );
        old
    }

    unsafe fn restore_realloc(old: DbMemOps) {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), old);
    }

    #[test]
    fn duplicate_vtable_does_not_reallocate_or_change_the_list() {
        let _guard = LOCK.lock();
        let Some(parse) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/vtab_lock"));
            return;
        };
        unsafe {
            let locks = parse.add(LOCKS_OFFSET);
            write_word(parse, 0, parse.add(DB_OFFSET) as usize as u32);
            write_word(parse, N_VTAB_LOCK_OFFSET, 2);
            write_word(parse, AP_VTAB_LOCK_OFFSET, locks as usize as u32);
            (locks as *mut u32).write(0x1111_1111);
            (locks as *mut u32).add(1).write(0x2222_2222);
            let old = install_realloc(core::ptr::null_mut());
            vtab_lock(parse, 0x2222_2222usize as *mut u8);
            assert_eq!(REALLOC_CALL.1, 0);
            assert_eq!(read_word(parse, N_VTAB_LOCK_OFFSET), 2);
            assert_eq!(read_word(parse, AP_VTAB_LOCK_OFFSET), locks as usize as u32);
            restore_realloc(old);
        }
    }

    #[test]
    fn absent_vtable_grows_by_one_word_and_appends() {
        let _guard = LOCK.lock();
        let Some(parse) = (unsafe { fixture() }) else { return; };
        unsafe {
            let locks = parse.add(LOCKS_OFFSET);
            let grown = parse.add(GROWN_OFFSET);
            write_word(parse, 0, parse.add(DB_OFFSET) as usize as u32);
            write_word(parse, N_VTAB_LOCK_OFFSET, 2);
            write_word(parse, AP_VTAB_LOCK_OFFSET, locks as usize as u32);
            (locks as *mut u32).write(0x1111_1111);
            (locks as *mut u32).add(1).write(0x2222_2222);
            let old = install_realloc(grown);
            vtab_lock(parse, 0x3333_3333usize as *mut u8);
            assert_eq!(REALLOC_CALL, (locks, 12));
            assert_eq!(read_word(parse, N_VTAB_LOCK_OFFSET), 3);
            assert_eq!(read_word(parse, AP_VTAB_LOCK_OFFSET), grown as usize as u32);
            assert_eq!((grown as *const u32).add(2).read(), 0x3333_3333);
            restore_realloc(old);
        }
    }

    #[test]
    fn failed_growth_latches_malloc_failed_without_incrementing_count() {
        let _guard = LOCK.lock();
        let Some(parse) = (unsafe { fixture() }) else { return; };
        unsafe {
            let db = parse.add(DB_OFFSET);
            let locks = parse.add(LOCKS_OFFSET);
            write_word(parse, 0, db as usize as u32);
            write_word(parse, N_VTAB_LOCK_OFFSET, 1);
            write_word(parse, AP_VTAB_LOCK_OFFSET, locks as usize as u32);
            let old = install_realloc(core::ptr::null_mut());
            vtab_lock(parse, 0x3333_3333usize as *mut u8);
            assert_eq!(REALLOC_CALL, (locks, 8));
            assert_eq!(read_word(parse, AP_VTAB_LOCK_OFFSET), 0);
            assert_eq!(read_word(parse, N_VTAB_LOCK_OFFSET), 1);
            assert_eq!(db.add(MALLOC_FAILED_OFFSET).read(), 1);
            restore_realloc(old);
        }
    }
}
