//! Construct a SQLite `KeyInfo` from an index descriptor.
//!
//! - `index_key_info` — original: `FUN_0837b2f4` @ `0x0837b2f4`
//!   (160 bytes; **8 direct `bl` call sites**, binary-scanned from
//!   `osos.dec`, all unconditional).
//!
//! The function first loads `db` from `parse + 0x00`, allocates
//! `5 * index.nColumn + 16` zeroed bytes through `sqlite3DbMallocZero`, then
//! lays out the target-width `KeyInfo`: `db` at +0x00, `nField` at +0x08, its
//! byte `aSortOrder` array immediately after its `nField` `aColl` words, and
//! the collations at +0x10. For every index column it resolves `azColl[i]`
//! with `sqlite3LocateCollSeq(parse, name, -1)` and copies `aSortOrder[i]`.
//! A nonzero `parse->nErr` word at +0x40 after the walk frees the new block
//! and returns NULL.
//!
//! The raw body has no early exit when collation lookup records an error: it
//! completes the entire signed `i < nColumn` walk before the one final error
//! check. The target helper at 0x0837d18c is not ported, so its observed
//! three-argument ABI is a volatile dispatch seam. The target default calls
//! retailOS; host tests install a recorder.

use crate::heap::tracked::tracked_free;
use crate::sqlite::mem::db_malloc_zero;

/// RetailOS address of the unresolved `sqlite3LocateCollSeq` helper.
pub const LOCATE_COLLATION_ADDRESS: usize = 0x0837_d18c;

/// Observed ABI of `sqlite3LocateCollSeq(parse, name, -1)`.
pub type LocateCollation = unsafe extern "C" fn(
    parse: *mut u8,
    name: *const u8,
    encoding: i32,
) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_locate_collation(
    parse: *mut u8,
    name: *const u8,
    encoding: i32,
) -> *mut u8 {
    let locate: LocateCollation = core::mem::transmute(LOCATE_COLLATION_ADDRESS);
    locate(parse, name, encoding)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_locate_collation(
    _parse: *mut u8,
    _name: *const u8,
    _encoding: i32,
) -> *mut u8 {
    panic!("index_key_info requires retail helper @ 0x0837d18c")
}

/// Replaceable unresolved-collation operation.
#[derive(Clone, Copy)]
pub struct IndexKeyInfoHooks {
    pub locate_collation: LocateCollation,
}

#[cfg(target_os = "none")]
pub const DEFAULT_INDEX_KEY_INFO_HOOKS: IndexKeyInfoHooks = IndexKeyInfoHooks {
    locate_collation: retail_locate_collation,
};

#[cfg(not(target_os = "none"))]
pub const DEFAULT_INDEX_KEY_INFO_HOOKS: IndexKeyInfoHooks = IndexKeyInfoHooks {
    locate_collation: missing_locate_collation,
};

/// The active unported-helper dispatch. A volatile read preserves the target
/// call instead of allowing LLVM to constant-fold the retail default.
pub static mut INDEX_KEY_INFO_HOOKS: IndexKeyInfoHooks = DEFAULT_INDEX_KEY_INFO_HOOKS;

#[inline(always)]
unsafe fn locate_collation_op() -> LocateCollation {
    core::ptr::read_volatile(core::ptr::addr_of!(INDEX_KEY_INFO_HOOKS.locate_collation))
}

const INDEX_N_COLUMN_OFFSET: usize = 0x04;
const INDEX_SORT_ORDER_OFFSET: usize = 0x28;
const INDEX_COLLATION_NAMES_OFFSET: usize = 0x2c;
const KEY_INFO_N_FIELD_OFFSET: usize = 0x08;
const KEY_INFO_SORT_ORDER_OFFSET: usize = 0x0c;
const KEY_INFO_COLLATIONS_OFFSET: usize = 0x10;

/// `sqlite3IndexKeyinfo`: allocate and populate a target-layout `KeyInfo`.
///
/// # Safety
/// `parse` must name a retail `Parse` with a target-width `db` word at +0x00
/// and an error word at +0x40. `index` must contain the retail `Index` fields
/// read at +0x04, +0x28 and +0x2c. Its two pointer fields and the returned
/// `KeyInfo` use 32-bit target words; all pointed-to index arrays must be
/// readable for signed-positive `nColumn` entries. The returned block is owned
/// by the caller and must be released with `tracked_free`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn index_key_info(parse: *mut u8, index: *const u8) -> *mut u8 {
    let db = (parse as *const u32).read() as usize as *mut u8;
    let n_column = (index.add(INDEX_N_COLUMN_OFFSET) as *const i32).read();
    let bytes = n_column.wrapping_mul(5).wrapping_add(KEY_INFO_COLLATIONS_OFFSET as i32);
    let mut key_info = db_malloc_zero(db, bytes);

    if !key_info.is_null() {
        (key_info as *mut u32).write(db as usize as u32);
        (key_info.add(KEY_INFO_N_FIELD_OFFSET) as *mut i32).write(n_column);

        let sort_order = key_info
            .add(KEY_INFO_COLLATIONS_OFFSET)
            .wrapping_offset(n_column as isize * core::mem::size_of::<u32>() as isize);
        (key_info.add(KEY_INFO_SORT_ORDER_OFFSET) as *mut u32).write(sort_order as usize as u32);

        let index_sort_order = (index.add(INDEX_SORT_ORDER_OFFSET) as *const u32).read() as usize
            as *const u8;
        let collation_names =
            (index.add(INDEX_COLLATION_NAMES_OFFSET) as *const u32).read() as usize as *const u32;

        let mut i = 0i32;
        while i < n_column {
            let column = i as usize;
            let name = collation_names.add(column).read() as usize as *const u8;
            let collation = locate_collation_op()(parse, name, -1);
            (key_info.add(KEY_INFO_COLLATIONS_OFFSET + column * 4) as *mut u32)
                .write(collation as usize as u32);
            sort_order.add(column).write(index_sort_order.add(column).read());
            i = i.wrapping_add(1);
        }

        if (parse.add(0x40) as *const u32).read() != 0 {
            tracked_free(key_info);
            key_info = core::ptr::null_mut();
        }
    }

    key_info
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::sqlite::mem::{DEFAULT_DB_MEM_OPS, MALLOC_FAILED_OFFSET, DB_MEM_OPS};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_INDEX_KEY_INFO, 0x2000).map(|p| p as usize)
    });
    static mut LOOKUP_CALLS: [(usize, usize, i32); 8] = [(0, 0, 0); 8];
    static mut LOOKUP_COUNT: usize = 0;
    static mut LOOKUP_RESULTS: [*mut u8; 8] = [core::ptr::null_mut(); 8];
    static mut FAIL_LOOKUP: Option<usize> = None;

    unsafe extern "C" fn recording_locate_collation(
        parse: *mut u8,
        name: *const u8,
        encoding: i32,
    ) -> *mut u8 {
        let count = *core::ptr::addr_of!(LOOKUP_COUNT);
        (*core::ptr::addr_of_mut!(LOOKUP_CALLS))[count] = (parse as usize, name as usize, encoding);
        *core::ptr::addr_of_mut!(LOOKUP_COUNT) = count + 1;
        if *core::ptr::addr_of!(FAIL_LOOKUP) == Some(count) {
            (parse.add(0x40) as *mut u32).write(1);
        }
        (*core::ptr::addr_of!(LOOKUP_RESULTS))[count]
    }

    struct HooksGuard;
    impl Drop for HooksGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(INDEX_KEY_INFO_HOOKS),
                    DEFAULT_INDEX_KEY_INFO_HOOKS,
                );
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
            }
        }
    }

    unsafe fn install_lookup(results: &[*mut u8], fail_lookup: Option<usize>) -> HooksGuard {
        LOOKUP_CALLS = [(0, 0, 0); 8];
        LOOKUP_COUNT = 0;
        LOOKUP_RESULTS = [core::ptr::null_mut(); 8];
        for (i, result) in results.iter().enumerate() {
            LOOKUP_RESULTS[i] = *result;
        }
        FAIL_LOOKUP = fail_lookup;
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(INDEX_KEY_INFO_HOOKS),
            IndexKeyInfoHooks { locate_collation: recording_locate_collation },
        );
        HooksGuard
    }

    fn try_slab() -> Option<*mut u8> {
        (*SLAB).map(|address| address as *mut u8)
    }

    unsafe fn u32_at(base: *mut u8, offset: usize) -> u32 {
        (base.add(offset) as *const u32).read()
    }

    unsafe fn make_tracked_payload(slab: *mut u8, raw_offset: usize, size: i32) -> (*mut u8, *mut u8) {
        let raw = slab.add(raw_offset);
        (raw as *mut i32).write(size);
        (raw.add(4) as *mut i32).write(size >> 31);
        let base = raw.add(8);
        let payload = ((base as usize + 36) & !31) as *mut u8;
        (payload.sub(4) as *mut u32).write((payload as usize - base as usize) as u32);
        (raw, payload)
    }

    unsafe fn set_index(slab: *mut u8, n_column: i32, sort_order: *const u8, names: *const u32) -> *mut u8 {
        let index = slab.add(0x800);
        (index.add(INDEX_N_COLUMN_OFFSET) as *mut i32).write(n_column);
        (index.add(INDEX_SORT_ORDER_OFFSET) as *mut u32).write(sort_order as usize as u32);
        (index.add(INDEX_COLLATION_NAMES_OFFSET) as *mut u32).write(names as usize as u32);
        index
    }

    #[test]
    fn builds_target_layout_and_resolves_every_column() {
        let _test = TEST_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let _heap = mock_heap();
        unsafe {
            let (_raw, payload) = make_tracked_payload(slab, 0x100, 26);
            let parse = slab.add(0x600);
            let db = slab.add(0x680);
            (parse as *mut u32).write(db as u32);
            (parse.add(0x40) as *mut u32).write(0);
            db.add(MALLOC_FAILED_OFFSET).write(0);
            let sort_order = slab.add(0x900);
            sort_order.copy_from_nonoverlapping([1u8, 0].as_ptr(), 2);
            let names = slab.add(0xa00) as *mut u32;
            let first_name = slab.add(0xb00);
            let second_name = slab.add(0xb20);
            first_name.copy_from_nonoverlapping(b"NOCASE\0".as_ptr(), 7);
            second_name.copy_from_nonoverlapping(b"RTRIM\0".as_ptr(), 6);
            names.write(first_name as u32);
            names.add(1).write(second_name as u32);
            let index = set_index(slab, 2, sort_order, names);
            let _hooks = install_lookup(&[slab.add(0xc00), slab.add(0xc20)], None);
            let _allocator = install_recorder(payload);

            let key_info = index_key_info(parse, index);
            assert_eq!(key_info, payload);
            assert_eq!(realloc_log(), std::vec![(0, 26)]);
            assert_eq!(u32_at(key_info, 0), db as u32);
            assert_eq!((key_info.add(KEY_INFO_N_FIELD_OFFSET) as *const i32).read(), 2);
            assert_eq!(u32_at(key_info, KEY_INFO_SORT_ORDER_OFFSET), key_info.add(24) as u32);
            assert_eq!(u32_at(key_info, 0x10), slab.add(0xc00) as u32);
            assert_eq!(u32_at(key_info, 0x14), slab.add(0xc20) as u32);
            assert_eq!([key_info.add(24).read(), key_info.add(25).read()], [1, 0]);
            assert_eq!(LOOKUP_COUNT, 2);
            assert_eq!(LOOKUP_CALLS[..2], [(parse as usize, first_name as usize, -1), (parse as usize, second_name as usize, -1)]);
        }
    }

    #[test]
    fn allocation_failure_bypasses_collation_lookup() {
        let _test = TEST_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        unsafe {
            let parse = slab.add(0x600);
            let db = slab.add(0x680);
            (parse as *mut u32).write(db as u32);
            (parse.add(0x40) as *mut u32).write(0);
            db.add(MALLOC_FAILED_OFFSET).write(0);
            let index = set_index(slab, 3, slab.add(0x900), slab.add(0xa00).cast());
            let _hooks = install_lookup(&[], None);
            let _allocator = install_recorder(core::ptr::null_mut());

            assert!(index_key_info(parse, index).is_null());
            assert_eq!(realloc_log(), std::vec![(0, 31)]);
            assert_eq!(LOOKUP_COUNT, 0);
            assert_eq!(db.add(MALLOC_FAILED_OFFSET).read(), 1);
        }
    }

    #[test]
    fn failed_lookup_finishes_walk_then_frees_keyinfo() {
        let _test = TEST_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let _heap = mock_heap();
        unsafe {
            let (raw, payload) = make_tracked_payload(slab, 0x100, 31);
            let parse = slab.add(0x600);
            let db = slab.add(0x680);
            (parse as *mut u32).write(db as u32);
            (parse.add(0x40) as *mut u32).write(0);
            db.add(MALLOC_FAILED_OFFSET).write(0);
            let sort_order = slab.add(0x900);
            sort_order.copy_from_nonoverlapping([0u8, 1, 1].as_ptr(), 3);
            let names = slab.add(0xa00) as *mut u32;
            for i in 0..3 {
                let name = slab.add(0xb00 + i * 0x20);
                name.write(b'A' + i as u8);
                name.add(1).write(0);
                names.add(i).write(name as u32);
            }
            let index = set_index(slab, 3, sort_order, names);
            let _hooks = install_lookup(&[slab.add(0xc00), slab.add(0xc20), slab.add(0xc40)], Some(0));
            let _allocator = install_recorder(payload);

            assert!(index_key_info(parse, index).is_null());
            assert_eq!(LOOKUP_COUNT, 3, "the raw loop does not stop on a failed lookup");
            assert_eq!(free_log(), (1, raw, 57));
        }
    }

    #[test]
    fn zero_column_index_has_inline_empty_arrays() {
        let _test = TEST_LOCK.lock();
        let Some(slab) = try_slab() else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        let _heap = mock_heap();
        unsafe {
            let (_raw, payload) = make_tracked_payload(slab, 0x100, 16);
            let parse = slab.add(0x600);
            let db = slab.add(0x680);
            (parse as *mut u32).write(db as u32);
            (parse.add(0x40) as *mut u32).write(0);
            db.add(MALLOC_FAILED_OFFSET).write(0);
            let index = set_index(slab, 0, core::ptr::null(), core::ptr::null());
            let _hooks = install_lookup(&[], None);
            let _allocator = install_recorder(payload);

            let key_info = index_key_info(parse, index);
            assert_eq!(key_info, payload);
            assert_eq!(realloc_log(), std::vec![(0, 16)]);
            assert_eq!(u32_at(key_info, KEY_INFO_SORT_ORDER_OFFSET), key_info.add(16) as u32);
            assert_eq!(LOOKUP_COUNT, 0);
        }
    }
}
