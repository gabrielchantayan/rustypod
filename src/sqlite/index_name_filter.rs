//! Build the `sqlite_master` name filter for table-owned indexes.
//!
//! - `sqlite_build_index_name_filter` — original: `FUN_08398954` @
//!   0x08398954 (140 bytes, `0x08398954..0x083989e0`; three outbound plain
//!   `bl`, no predicated `bl`; two inbound plain-`bl` call sites).
//!
//! Algorithm: if the table's root-page word (+0x4c) differs from the owning
//! database schema root (+0x2c), walk the table's index chain (+0x20). For
//! each index whose root-page word (+0x1c) matches the schema root, format
//! `name=%Q` for the first name and append each later name as
//! `%s OR name=%Q`; after every append, free the old formatted string. The
//! result is NULL when no index matches or when the formatter allocation
//! fails.
//!
//! Deliberate deviations: the two C-variadic calls to `sqlite3MPrintf` @
//! 0x0837d358 use its established Rust seam
//! [`sqlite_set_string_formatted`], with explicit `VaList` word arrays. The
//! target's pointer fields stay `u32` words, indexed rather than modeled as
//! host pointer fields, so the ARM offsets remain exact on 64-bit tests.

use crate::heap::tracked::tracked_free;
use crate::sqlite::error_msg::{Parse, VaList};
use crate::sqlite::set_string_formatted::sqlite_set_string_formatted;

const FIRST_FORMAT: &[u8] = b"name=%Q\0";
const APPEND_FORMAT: &[u8] = b"%s OR name=%Q\0";

/// sqlite_build_index_name_filter — original: `FUN_08398954` @ 0x08398954.
///
/// Returns a freshly formatted `sqlite_master` name predicate for indexes in
/// `table` sharing the database schema root. `table` and every chain link use
/// target-width words: +0x20 first index, +0x4c table root, +0x00 index name,
/// +0x1c index root, and +0x28 next index.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_build_index_name_filter(parse: *const Parse, table: *const u32) -> *mut u8 {
    let db = (*parse).db;
    let schema = (db as *const u32).add(8).read() as usize as *const u32;
    let schema_root = schema.add(11).read();
    if table.add(19).read() == schema_root {
        return core::ptr::null_mut();
    }

    let mut result: *mut u8 = core::ptr::null_mut();
    let mut index = table.add(8).read() as usize as *const u32;
    while !index.is_null() {
        if index.add(7).read() == schema_root {
            let name = index.read();
            if result.is_null() {
                let args = [name];
                result = sqlite_set_string_formatted(db, FIRST_FORMAT.as_ptr(), args.as_ptr() as VaList);
            } else {
                let old = result;
                let args = [old as usize as u32, name];
                result = sqlite_set_string_formatted(db, APPEND_FORMAT.as_ptr(), args.as_ptr() as VaList);
                tracked_free(old);
            }
        }
        index = index.add(10).read() as usize as *const u32;
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests as heap_tests;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::sqlite::error_msg::{missing_vm_printf, SQLITE_VM_PRINTF};
    use parking_lot::Mutex;

    static FORMATTER_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(usize, [u32; 2], usize); 2] = [(0, [0; 2], 0); 2];
    static mut CALL_COUNT: usize = 0;
    static mut RESULTS: [*mut u8; 2] = [core::ptr::null_mut(); 2];

    unsafe extern "C" fn recording_formatter(db: *mut u8, format: *const u8, args: VaList) -> *mut u8 {
        let n = CALL_COUNT;
        CALLS[n] = (db as usize, [args.read(), if n == 0 { 0 } else { args.add(1).read() }], format as usize);
        CALL_COUNT += 1;
        RESULTS[n]
    }

    #[repr(C)]
    struct FakeBlock {
        size: i32,
        sign: i32,
        _pad_bytes: [u8; 20],
        pad: u32,
        payload: [u8; 16],
    }

    impl FakeBlock {
        fn new() -> Self { Self { size: 16, sign: 0, _pad_bytes: [0; 20], pad: 24, payload: [0; 16] } }
        fn payload(&mut self) -> *mut u8 { self.payload.as_mut_ptr() }
    }

    unsafe fn with_formatter<T>(results: [*mut u8; 2], body: impl FnOnce() -> T) -> T {
        let _lock = FORMATTER_LOCK.lock();
        CALL_COUNT = 0;
        RESULTS = results;
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), recording_formatter);
        let value = body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_VM_PRINTF), missing_vm_printf);
        value
    }

    #[test]
    fn skips_the_chain_when_table_and_schema_roots_match() {
        let Some(slab) = try_map_u32_slab(hints::INDEX_NAME_FILTER, 0x1000) else {
            assert!(note_missing_u32_fixture("sqlite::index_name_filter"));
            return;
        };
        unsafe {
            let words = slab.cast::<u32>();
            let db = slab.add(0x100);
            let schema = slab.add(0x200);
            words.add(0x100 / 4 + 8).write(schema as usize as u32);
            schema.cast::<u32>().add(11).write(7);
            words.add(19).write(7);
            let parse = Parse { db, rc: 0, z_err_msg: core::ptr::null_mut(), _gap_0c: [0; 6], check_schema: 0, _gap_13: [0; 45], n_err: 0 };
            let result = with_formatter([core::ptr::null_mut(); 2], || sqlite_build_index_name_filter(&parse, words));
            assert!(result.is_null());
            assert_eq!(CALL_COUNT, 0);
        }
    }

    #[test]
    fn joins_matching_index_names_and_frees_the_replaced_result() {
        let Some(slab) = try_map_u32_slab(hints::INDEX_NAME_FILTER, 0x1000) else {
            assert!(note_missing_u32_fixture("sqlite::index_name_filter"));
            return;
        };
        let _heap = heap_tests::mock_heap();
        let mut first = FakeBlock::new();
        let mut second = FakeBlock::new();
        unsafe {
            let table = slab.cast::<u32>();
            let db = slab.add(0x100);
            let schema = slab.add(0x200);
            let first_index = slab.add(0x300).cast::<u32>();
            let ignored_index = slab.add(0x340).cast::<u32>();
            let second_index = slab.add(0x380).cast::<u32>();
            db.cast::<u32>().add(8).write(schema as usize as u32);
            schema.cast::<u32>().add(11).write(9);
            table.add(19).write(1);
            table.add(8).write(first_index as usize as u32);
            first_index.write(slab.add(0x500) as usize as u32);
            first_index.add(7).write(9);
            first_index.add(10).write(ignored_index as usize as u32);
            ignored_index.add(7).write(4);
            ignored_index.add(10).write(second_index as usize as u32);
            second_index.write(slab.add(0x510) as usize as u32);
            second_index.add(7).write(9);
            core::ptr::copy_nonoverlapping(b"first\0".as_ptr(), slab.add(0x500), 6);
            core::ptr::copy_nonoverlapping(b"second\0".as_ptr(), slab.add(0x510), 7);
            let parse = Parse { db, rc: 0, z_err_msg: core::ptr::null_mut(), _gap_0c: [0; 6], check_schema: 0, _gap_13: [0; 45], n_err: 0 };
            let result = with_formatter([first.payload(), second.payload()], || sqlite_build_index_name_filter(&parse, table));
            assert_eq!(result, second.payload());
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS[0].1[0], slab.add(0x500) as usize as u32);
            assert_eq!(CALLS[1].1, [first.payload() as usize as u32, slab.add(0x510) as usize as u32]);
            assert_eq!(CALLS[0].2, FIRST_FORMAT.as_ptr() as usize);
            assert_eq!(CALLS[1].2, APPEND_FORMAT.as_ptr() as usize);
            let (calls, raw, tag) = heap_tests::free_log();
            assert_eq!((calls, raw, tag), (1, &mut first as *mut FakeBlock as *mut u8, 57));
        }
    }
}
