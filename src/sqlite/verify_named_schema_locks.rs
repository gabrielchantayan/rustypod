//! Verify table locks across every schema.
//!
//! `verify_named_schema_locks` — original: `FUN_083674c0` @ `0x083674c0`.
//! Raw ARM words establish a 92-byte extent (`0x083674c0..0x0836751c`;
//! `verify_table_locks` starts next), one unconditional plain internal `bl`
//! (`verify_table_locks` @ `0x0836751c`) and no predicated `bl`. Two direct,
//! unconditional incoming `bl` sites are at `0x08381e2c` and `0x08381e8c`.
//! It walks `db->aDb` entries (24 bytes), each schema's table-hash chain, and
//! asks `verify_table_locks` to process each table with `name`. Deliberate
//! deviation: none; the direct ARM call maps to the ported Rust callee.

use super::verify_table_locks::verify_table_locks;

const DB_N_DB_OFFSET: usize = 0x04;
const DB_A_DB_OFFSET: usize = 0x08;
const DB_ENTRY_SIZE: usize = 0x18;
const DB_ENTRY_SCHEMA_OFFSET: usize = 0x14;
const SCHEMA_TABLE_HASH_FIRST_OFFSET: usize = 0x10;
const HASH_ELEMENT_NEXT_OFFSET: usize = 0x00;
const HASH_ELEMENT_DATA_OFFSET: usize = 0x08;

/// `sqlite3CodeVerifyNamedSchema`: visit every table in every database schema.
///
/// # Safety
/// `parse` must identify a readable target-layout `Parse` and its linked
/// database, schema, hash-element, and table records. `name`, when non-NULL,
/// must be NUL-terminated.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn verify_named_schema_locks(parse: *mut u8, name: *const u8) {
    let db = parse.cast::<u32>().read() as *mut u8;
    let db_count = db.add(DB_N_DB_OFFSET).cast::<i32>().read();
    let mut db_entry = db.add(DB_A_DB_OFFSET).cast::<u32>().read() as *mut u8;
    let mut i = 0;
    while i < db_count {
        let schema = db_entry.add(DB_ENTRY_SCHEMA_OFFSET).cast::<u32>().read() as *mut u8;
        let mut hash_element = schema.add(SCHEMA_TABLE_HASH_FIRST_OFFSET).cast::<u32>().read() as *mut u8;
        while !hash_element.is_null() {
            let table = hash_element.add(HASH_ELEMENT_DATA_OFFSET).cast::<u32>().read() as *mut u8;
            verify_table_locks(parse, table, name);
            hash_element = hash_element.add(HASH_ELEMENT_NEXT_OFFSET).cast::<u32>().read() as *mut u8;
        }
        i += 1;
        db_entry = db_entry.add(DB_ENTRY_SIZE);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::verify_table_locks::{VerifyTableLocksHooks, DEFAULT_VERIFY_TABLE_LOCKS_HOOKS, VERIFY_TABLE_LOCKS_HOOKS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static LOCK: Mutex<()> = Mutex::new(());
    static LOCK_CALLS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn schema(_: *const u8, _: *const u8) -> i32 { 0 }
    unsafe extern "C" fn begin(_: *mut u8, _: i32, _: i32) {}
    unsafe extern "C" fn code(_: *mut u8, _: *mut u8, mode: i32) {
        assert_eq!(mode, -1);
        LOCK_CALLS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "C" fn icmp(_: *const u8, _: *const u8) -> i32 { 0 }

    #[test]
    fn visits_each_table_hash_element_in_every_schema() {
        let _guard = LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::SQLITE_VERIFY_NAMED_SCHEMA_LOCKS, 0x1000) else {
            assert!(note_missing_u32_fixture("sqlite/verify_named_schema_locks"));
            return;
        };
        unsafe {
            base.write_bytes(0, 0x1000);
            let parse = base;
            let db = base.add(0x40);
            let entries = base.add(0x100);
            let first_schema = base.add(0x180);
            let second_schema = base.add(0x200);
            let first_element = base.add(0x280);
            let second_element = base.add(0x2c0);
            let third_element = base.add(0x300);
            let first_table = base.add(0x400);
            let second_table = base.add(0x500);
            let third_table = base.add(0x600);
            parse.cast::<u32>().write(db as usize as u32);
            db.add(DB_N_DB_OFFSET).cast::<i32>().write(2);
            db.add(DB_A_DB_OFFSET).cast::<u32>().write(entries as usize as u32);
            entries.add(DB_ENTRY_SCHEMA_OFFSET).cast::<u32>().write(first_schema as usize as u32);
            entries.add(DB_ENTRY_SIZE + DB_ENTRY_SCHEMA_OFFSET).cast::<u32>().write(second_schema as usize as u32);
            first_schema.add(SCHEMA_TABLE_HASH_FIRST_OFFSET).cast::<u32>().write(first_element as usize as u32);
            second_schema.add(SCHEMA_TABLE_HASH_FIRST_OFFSET).cast::<u32>().write(third_element as usize as u32);
            first_element.add(HASH_ELEMENT_NEXT_OFFSET).cast::<u32>().write(second_element as usize as u32);
            first_element.add(HASH_ELEMENT_DATA_OFFSET).cast::<u32>().write(first_table as usize as u32);
            second_element.add(HASH_ELEMENT_DATA_OFFSET).cast::<u32>().write(second_table as usize as u32);
            third_element.add(HASH_ELEMENT_DATA_OFFSET).cast::<u32>().write(third_table as usize as u32);
            VERIFY_TABLE_LOCKS_HOOKS = VerifyTableLocksHooks { schema_to_index: schema, begin_write_operation: begin, code_table_locks: code, icmp };
            LOCK_CALLS.store(0, Ordering::SeqCst);
            verify_named_schema_locks(parse, core::ptr::null());
            assert_eq!(LOCK_CALLS.load(Ordering::SeqCst), 3);
            VERIFY_TABLE_LOCKS_HOOKS = DEFAULT_VERIFY_TABLE_LOCKS_HOOKS;
        }
    }
}
