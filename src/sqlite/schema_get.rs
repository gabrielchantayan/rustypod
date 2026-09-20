//! Obtaining SQLite's per-shared-cache schema object.
//!
//! `sqlite3_schema_get` — original: `FUN_08382d18` @ `0x08382d18`, 192
//! bytes (`0x08382d18..0x08382dd8`; the next real function starts at
//! `0x08382ddc`). Raw osos.dec contains seven unconditional plain `bl`
//! instructions and no predicated `bl`: `btree_enter`, `sqlite3_malloc_zero`,
//! `btree_leave`, and four `hash_init` calls. It is SQLite 3.5's
//! `sqlite3SchemaGet`: reuse a shared Btree's schema when present; otherwise
//! allocate its 100-byte schema, install the schema-free callback, and finish
//! its four Hash members once. A NULL Btree receives an unshared schema.
//!
//! Deliberate deviations: the original literal callback target (`0x08377d80`)
//! is retained as a target-width word rather than a host function pointer, and
//! the already-ported `sqlite3_malloc_zero` uses its established allocator
//! dispatch seam. These preserve target layout and observable allocation
//! behavior without host pointer-width leakage.

use super::btree_lock::{btree_enter, btree_leave};
use super::hash_init::hash_init;
use super::mem::sqlite3_malloc_zero;

const SCHEMA_SIZE: i32 = 100;
const MALLOC_FAILED_OFFSET: usize = 0x1e;
const BTREE_SHARED_OFFSET: usize = 0x04;
const SHARED_SCHEMA_OFFSET: usize = 0x38;
const SHARED_FREE_SCHEMA_OFFSET: usize = 0x3c;
const SCHEMA_TBL_HASH_OFFSET: usize = 0x04;
const SCHEMA_IDX_HASH_OFFSET: usize = 0x18;
const SCHEMA_TRIG_HASH_OFFSET: usize = 0x2c;
const SCHEMA_FKEY_HASH_OFFSET: usize = 0x40;
const SCHEMA_FILE_FORMAT_OFFSET: usize = 0x58;
const SCHEMA_ENCODING_OFFSET: usize = 0x59;
const SQLITE_HASH_STRING: u8 = 3;
const SCHEMA_FREE_CALLBACK: u32 = 0x0837_7d80;

/// sqlite3_schema_get — original: `FUN_08382d18` @ `0x08382d18` (192 bytes;
/// seven plain `bl`, zero predicated `bl`).
///
/// Returns the Btree shared schema or an unshared, zero-allocated Schema. A
/// failed allocation latches `db->mallocFailed` at `+0x1e`; an uninitialized
/// Schema stamps all four string-key Hashes and marks its encoding byte as 1.
///
/// # Safety
/// `db` must be writable through `+0x1e`. When non-NULL, `btree` must name a
/// target-layout Btree whose +0x04 word points to writable shared-Btree data.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_schema_get(db: *mut u8, btree: *mut u8) -> *mut u8 {
    let schema = if btree.is_null() {
        sqlite3_malloc_zero(SCHEMA_SIZE)
    } else {
        let shared = (btree.add(BTREE_SHARED_OFFSET) as *const u32).read() as usize as *mut u8;
        btree_enter(btree);
        if (shared.add(SHARED_SCHEMA_OFFSET) as *const u32).read() == 0 {
            let allocated = sqlite3_malloc_zero(SCHEMA_SIZE);
            (shared.add(SHARED_SCHEMA_OFFSET) as *mut u32).write(allocated as u32);
            (shared.add(SHARED_FREE_SCHEMA_OFFSET) as *mut u32).write(SCHEMA_FREE_CALLBACK);
        }
        btree_leave(btree);
        (shared.add(SHARED_SCHEMA_OFFSET) as *const u32).read() as usize as *mut u8
    };

    if schema.is_null() {
        db.add(MALLOC_FAILED_OFFSET).write(1);
    } else if schema.add(SCHEMA_FILE_FORMAT_OFFSET).read() == 0 {
        hash_init(schema.add(SCHEMA_TBL_HASH_OFFSET), SQLITE_HASH_STRING, 0);
        hash_init(schema.add(SCHEMA_IDX_HASH_OFFSET), SQLITE_HASH_STRING, 0);
        hash_init(schema.add(SCHEMA_TRIG_HASH_OFFSET), SQLITE_HASH_STRING, 0);
        hash_init(schema.add(SCHEMA_FKEY_HASH_OFFSET), SQLITE_HASH_STRING, 1);
        schema.add(SCHEMA_ENCODING_OFFSET).write(1);
    }
    schema
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::{tests::install_recorder, DEFAULT_DB_MEM_OPS, DB_MEM_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const DB_OFFSET: usize = 0x000;
    const BTREE_OFFSET: usize = 0x100;
    const SHARED_OFFSET: usize = 0x200;
    const SCHEMA_OFFSET: usize = 0x400;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_SCHEMA_GET, SLAB_LEN).map(|pointer| pointer as usize)
    });

    unsafe fn fixture() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8)> {
        let base = (*SLAB)? as *mut u8;
        base.write_bytes(0xa5, SLAB_LEN);
        let db = base.add(DB_OFFSET);
        let btree = base.add(BTREE_OFFSET);
        let shared = base.add(SHARED_OFFSET);
        let schema = base.add(SCHEMA_OFFSET);
        shared.write_bytes(0, 0x40);
        btree.add(BTREE_SHARED_OFFSET).cast::<u32>().write(shared as u32);
        btree.add(9).write(1); // sharable: exercise btree_enter/leave.
        (btree.add(0x0c) as *mut i32).write(0);
        Some((db, btree, shared, schema))
    }

    unsafe fn restore_allocator() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
    }

    #[test]
    fn creates_and_initializes_a_shared_schema_once() {
        let Some((db, btree, shared, schema)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/schema_get"));
            return;
        };
        let guard = install_recorder(schema);
        unsafe {
            let result = sqlite3_schema_get(db, btree);
            assert_eq!(result, schema);
            assert_eq!((shared.add(SHARED_SCHEMA_OFFSET) as *const u32).read(), schema as u32);
            assert_eq!((shared.add(SHARED_FREE_SCHEMA_OFFSET) as *const u32).read(), SCHEMA_FREE_CALLBACK);
            assert_eq!((btree.add(0x0c) as *const i32).read(), 0, "Btree lock is released");
            for offset in [SCHEMA_TBL_HASH_OFFSET, SCHEMA_IDX_HASH_OFFSET, SCHEMA_TRIG_HASH_OFFSET, SCHEMA_FKEY_HASH_OFFSET] {
                assert_eq!(schema.add(offset).read(), SQLITE_HASH_STRING);
                assert_eq!(schema.add(offset + 4).cast::<u32>().read(), 0);
            }
            assert_eq!(schema.add(SCHEMA_FKEY_HASH_OFFSET + 1).read(), 1);
            assert_eq!(schema.add(SCHEMA_ENCODING_OFFSET).read(), 1);
            assert_eq!(sqlite3_schema_get(db, btree), schema, "existing schema is reused");
            restore_allocator();
        }
        drop(guard);
    }

    #[test]
    fn allocation_failure_latches_db_and_returns_null() {
        let Some((db, _, _, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("sqlite/schema_get"));
            return;
        };
        let guard = install_recorder(core::ptr::null_mut());
        unsafe {
            assert!(sqlite3_schema_get(db, core::ptr::null_mut()).is_null());
            assert_eq!(db.add(MALLOC_FAILED_OFFSET).read(), 1);
            restore_allocator();
        }
        drop(guard);
    }
}
