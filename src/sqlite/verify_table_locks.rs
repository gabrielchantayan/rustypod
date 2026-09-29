//! Verify schema state and emit table locks for selected tables.
//!
//! `verify_table_locks` — original: `FUN_0836751c` @ `0x0836751c`.
//! Raw ARM words establish a 164-byte extent (`0x0836751c..0x083675c0`;
//! `release_mem_array` starts next), four unconditional plain `bl` instructions
//! and no predicated `bl`. It walks the `Table` list, selects every table when
//! `name` is NULL or one whose `Index` names case-insensitively match, then
//! maps its schema to a database index, begins a read operation, and emits its
//! table locks. Deliberate deviation: direct ARM calls use volatile hook slots;
//! the three ported defaults are behaviorally identical and the unported table-
//! lock emitter resolves to its stock load address on target.

use super::begin_write_operation::begin_write_operation;
use super::schema_to_index::schema_to_index;
use super::stricmp::str_icmp;

const TABLE_N_INDEX_OFFSET: usize = 0x04;
const TABLE_NEXT_OFFSET: usize = 0x20;
const TABLE_INDEXES_OFFSET: usize = 0x2c;
const TABLE_SCHEMA_OFFSET: usize = 0x4c;

#[derive(Clone, Copy)]
pub struct VerifyTableLocksHooks {
    pub schema_to_index: unsafe extern "C" fn(*const u8, *const u8) -> i32,
    pub begin_write_operation: unsafe extern "C" fn(*mut u8, i32, i32),
    pub code_table_locks: unsafe extern "C" fn(*mut u8, *mut u8, i32),
    pub icmp: unsafe extern "C" fn(*const u8, *const u8) -> i32,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn stock_code_table_locks(parse: *mut u8, table: *mut u8, mode: i32) {
    let call: unsafe extern "C" fn(*mut u8, *mut u8, i32) = core::mem::transmute(0x0838_182cusize);
    call(parse, table, mode);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_code_table_locks(_: *mut u8, _: *mut u8, _: i32) {
    panic!("verify_table_locks requires a host code_table_locks hook")
}

unsafe extern "C" fn begin_read_operation(parse: *mut u8, set_statement: i32, db_index: i32) {
    begin_write_operation(parse.cast(), set_statement, db_index);
}
pub const DEFAULT_VERIFY_TABLE_LOCKS_HOOKS: VerifyTableLocksHooks = VerifyTableLocksHooks {

    schema_to_index,
    begin_write_operation: begin_read_operation,
    #[cfg(target_os = "none")]
    code_table_locks: stock_code_table_locks,
    #[cfg(not(target_os = "none"))]
    code_table_locks: unavailable_code_table_locks,
    icmp: str_icmp,
};

pub static mut VERIFY_TABLE_LOCKS_HOOKS: VerifyTableLocksHooks = DEFAULT_VERIFY_TABLE_LOCKS_HOOKS;

#[inline(always)]
unsafe fn hooks() -> VerifyTableLocksHooks {
    core::ptr::read_volatile(core::ptr::addr_of!(VERIFY_TABLE_LOCKS_HOOKS))
}

/// `sqlite3CodeVerifyTableLocks`: process tables matching `name`, or all tables
/// when `name` is NULL.
///
/// # Safety
/// `parse` and every linked `Table`/`Index` record must be readable in the
/// target's 32-bit layout. `name`, when non-NULL, must be NUL-terminated.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn verify_table_locks(parse: *mut u8, mut table: *mut u8, name: *const u8) {
    while !table.is_null() {
        let mut selected = name.is_null();
        if !selected {
            let mut i = 0i32;
            let n_index = table.add(TABLE_N_INDEX_OFFSET).cast::<i32>().read();
            while i < n_index {
                let index = (table.add(TABLE_INDEXES_OFFSET).cast::<u32>().read() as usize)
                    .wrapping_add(i as usize * 4) as *const u32;
                let index = index.read() as *const u8;
                if index == name as *const u8 || (!index.is_null() && (hooks().icmp)(index, name) == 0) {
                    selected = true;
                    break;
                }
                i += 1;
            }
        }
        if selected {
            let h = hooks();
            let db = parse.cast::<u32>().read() as *const u8;
            let schema = table.add(TABLE_SCHEMA_OFFSET).cast::<u32>().read() as *const u8;
            let db_index = (h.schema_to_index)(db, schema);
            (h.begin_write_operation)(parse, 0, db_index);
            (h.code_table_locks)(parse, table, -1);
        }
        table = table.add(TABLE_NEXT_OFFSET).cast::<u32>().read() as *mut u8;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    static LOCK: Mutex<()> = Mutex::new(());
    static SCHEMA_CALLS: AtomicUsize = AtomicUsize::new(0);
    static BEGIN_CALLS: AtomicUsize = AtomicUsize::new(0);
    static LOCK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static LAST_DB_INDEX: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn schema(_: *const u8, _: *const u8) -> i32 { SCHEMA_CALLS.fetch_add(1, Ordering::SeqCst) as i32 + 7 }
    unsafe extern "C" fn begin(_: *mut u8, set: i32, db: i32) { assert_eq!(set, 0); BEGIN_CALLS.fetch_add(1, Ordering::SeqCst); LAST_DB_INDEX.store(db, Ordering::SeqCst); }
    unsafe extern "C" fn code(_: *mut u8, _: *mut u8, mode: i32) { assert_eq!(mode, -1); LOCK_CALLS.fetch_add(1, Ordering::SeqCst); }
    unsafe extern "C" fn icmp(left: *const u8, right: *const u8) -> i32 { if left == right { 0 } else { 1 } }

    #[test]
    fn selects_matching_indexes_and_null_name_selects_all_tables() {
        let _guard = LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::SQLITE_VERIFY_TABLE_LOCKS, 0x1000) else { assert!(note_missing_u32_fixture("sqlite/verify_table_locks")); return; };
        unsafe {
            base.write_bytes(0, 0x1000);
            let parse = base;
            let first = base.add(0x100);
            let second = base.add(0x200);
            let index_ptrs = base.add(0x300).cast::<u32>();
            let target = base.add(0x380);
            first.add(TABLE_N_INDEX_OFFSET).cast::<i32>().write(1);
            first.add(TABLE_INDEXES_OFFSET).cast::<u32>().write(index_ptrs as usize as u32);
            index_ptrs.write(target as usize as u32);
            first.add(TABLE_NEXT_OFFSET).cast::<u32>().write(second as usize as u32);
            VERIFY_TABLE_LOCKS_HOOKS = VerifyTableLocksHooks { schema_to_index: schema, begin_write_operation: begin, code_table_locks: code, icmp };
            SCHEMA_CALLS.store(0, Ordering::SeqCst); BEGIN_CALLS.store(0, Ordering::SeqCst); LOCK_CALLS.store(0, Ordering::SeqCst);
            verify_table_locks(parse, first, target);
            assert_eq!(SCHEMA_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(BEGIN_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(LOCK_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(LAST_DB_INDEX.load(Ordering::SeqCst), 7);
            verify_table_locks(parse, first, core::ptr::null());
            assert_eq!(LOCK_CALLS.load(Ordering::SeqCst), 3);
            VERIFY_TABLE_LOCKS_HOOKS = DEFAULT_VERIFY_TABLE_LOCKS_HOOKS;
        }
    }
}
