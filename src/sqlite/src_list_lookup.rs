//! Resolving SQLite FROM-clause source-list tables.
//!
//! - `src_list_lookup` — original: `FUN_08384570` @ `0x08384570` (104
//!   bytes, `0x08384570..0x083845d8`; the next separately linked function
//!   begins at `0x083845dc`). Raw ARM decoding finds **six direct `bl` call
//!   sites**, all unconditional, and no branch targets or aligned data words
//!   at this address.
//!
//! SQLite's `sqlite3SrcListLookup` walks the signed `SrcList.n_src` count,
//! starting at the inline `SrcListItem` array at +0x08. For each entry it
//! resolves `(z_name, z_database)` through `sqlite_locate_table`, releases
//! the old `p_table`, stores the new table, and increments its word +0x1c
//! reference count when non-NULL. The return value is the last lookup result
//! (or NULL for an empty/nonpositive list), which all six stock callers use.
//!
//! `sqlite_locate_table` @ 0x0837d250 is already ported and called directly.
//! The table release target @ 0x0837521c remains the established volatile
//! dispatch seam in `src_list_delete`; this routine deliberately shares that
//! seam rather than creating a duplicate stub.

use super::error_msg::Parse;
use super::locate_table::sqlite_locate_table;
use super::src_list_delete::{table_release_op, SrcList, SrcListItem};

/// `src_list_lookup` — original: `FUN_08384570` @ `0x08384570` (104 bytes;
/// 6 unconditional direct `bl` call sites).
///
/// Re-resolves every source-list entry in ascending order, dropping its prior
/// table reference before installing and retaining the newly resolved table.
/// The signed count is reloaded for every loop condition, matching the ARM
/// `ldrsh` / `cmp` / `bgt` sequence.
///
/// # Safety
/// `parse` must satisfy [`sqlite_locate_table`]'s requirements. `source_list`
/// must be a non-NULL writable [`SrcList`] followed by at least its current
/// signed-positive `n_src` inline [`SrcListItem`] records. Every entry's names
/// and previous table must meet the original resolver/releaser contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn src_list_lookup(
    parse: *mut Parse,
    source_list: *mut SrcList,
) -> *mut u8 {
    let list = source_list as *const SrcList;
    let mut item = source_list.add(1).cast::<SrcListItem>();
    let mut index = 0i32;
    let mut table = core::ptr::null_mut();

    while i32::from((*list).n_src) > index {
        table = sqlite_locate_table(parse, 0, (*item).z_name, (*item).z_database);
        (table_release_op())((*item).p_table);
        (*item).p_table = table;
        if !table.is_null() {
            let references = table.cast::<u32>().add(7);
            references.write(references.read().wrapping_add(1));
        }
        item = item.add(1);
        index = index.wrapping_add(1);
    }

    table
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::find_table::{FindTableHooks, DEFAULT_FIND_TABLE_HOOKS, FIND_TABLE_HOOKS, FIND_TABLE_HOOKS_TEST_LOCK};
    use crate::sqlite::src_list_delete::{SQLITE_TABLE_RELEASE, SQLITE_TABLE_RELEASE_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut, null_mut};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    const DB_AT: usize = 0x000;
    const DATABASES_AT: usize = 0x100;
    const SCHEMA_AT: usize = 0x200;
    const TABLE_AT: usize = 0x300;
    const TABLE_REFCOUNT_WORD: usize = 7;
    const DATABASE_STRIDE: usize = 0x18;
    const DATABASE_SCHEMA_OFFSET: usize = 0x14;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_SRC_LIST_LOOKUP, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASED_TABLE: *mut u8 = null_mut();
    static mut RESOLVED_TABLE: *mut u8 = null_mut();

    unsafe extern "C" fn record_release(table: *mut u8) {
        addr_of_mut!(RELEASED_TABLE).write(table);
    }

    unsafe extern "C" fn resolve_to_recorded_table(
        _hash: *const crate::sqlite::hash_clear::Hash,
        _key: *const u8,
        _key_len: i32,
    ) -> *mut u8 {
        addr_of!(RESOLVED_TABLE).read()
    }

    struct HookRestore {
        find: FindTableHooks,
        release: super::super::src_list_delete::TableReleaseFn,
    }

    impl Drop for HookRestore {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(FIND_TABLE_HOOKS).write(self.find);
                addr_of_mut!(SQLITE_TABLE_RELEASE).write(self.release);
            }
        }
    }

    unsafe fn install_recorders(table: *mut u8) -> HookRestore {
        let restore = HookRestore {
            find: addr_of!(FIND_TABLE_HOOKS).read(),
            release: addr_of!(SQLITE_TABLE_RELEASE).read(),
        };
        addr_of_mut!(RESOLVED_TABLE).write(table);
        addr_of_mut!(RELEASED_TABLE).write(null_mut());
        addr_of_mut!(FIND_TABLE_HOOKS).write(FindTableHooks {
            icmp: DEFAULT_FIND_TABLE_HOOKS.icmp,
            find: resolve_to_recorded_table,
        });
        addr_of_mut!(SQLITE_TABLE_RELEASE).write(record_release);
        restore
    }

    unsafe fn source_list(items: &mut [SrcListItem]) -> (*mut SrcList, std::alloc::Layout) {
        let layout = std::alloc::Layout::from_size_align(
            core::mem::size_of::<SrcList>() + core::mem::size_of_val(items),
            core::mem::align_of::<SrcListItem>(),
        ).unwrap();
        let list = std::alloc::alloc_zeroed(layout).cast::<SrcList>();
        list.write(SrcList { n_src: items.len() as i16, n_alloc: items.len() as i16, _reserved: [0; 4] });
        let destination = list.add(1).cast::<SrcListItem>();
        for (index, item) in items.iter().enumerate() {
            destination.add(index).write(*item);
        }
        (list, layout)
    }

    unsafe fn parse_for_slab(slab: *mut u8) -> Parse {
        Parse {
            db: slab.add(DB_AT),
            rc: 0,
            z_err_msg: null_mut(),
            _gap_0c: [0; 6],
            check_schema: 0,
            _gap_13: [0; 0x40 - 0x13],
            n_err: 0,
        }
    }

    #[test]
    fn nonpositive_count_returns_null_without_touching_parse() {
        let mut list = SrcList { n_src: -1, n_alloc: 0, _reserved: [0; 4] };
        let result = unsafe { src_list_lookup(null_mut(), &mut list) };
        assert!(result.is_null());
    }

    #[test]
    fn replaces_releases_and_retains_every_source_table() {
        let _fixture_guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _find_guard = FIND_TABLE_HOOKS_TEST_LOCK.lock();
        let _release_guard = SQLITE_TABLE_RELEASE_TEST_LOCK.lock();
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite::src_list_lookup"));
            return;
        };
        let slab = base as *mut u8;

        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let databases = slab.add(DATABASES_AT);
            slab.add(DB_AT + 4).cast::<i32>().write(2);
            slab.add(DB_AT + 8).cast::<u32>().write(databases as usize as u32);
            databases
                .add(DATABASE_STRIDE + DATABASE_SCHEMA_OFFSET)
                .cast::<u32>()
                .write(slab.add(SCHEMA_AT) as usize as u32);
            let table = slab.add(TABLE_AT);
            table.cast::<u32>().add(TABLE_REFCOUNT_WORD).write(u32::MAX);
            let old_table = 0x1234_5000usize as *mut u8;
            let mut items = [SrcListItem {
                z_database: null_mut(),
                z_name: b"tracks\0".as_ptr() as *mut u8,
                z_alias: null_mut(),
                p_table: old_table,
                p_select: null_mut(),
                p_index: null_mut(),
                join_flags: 0,
                p_on: null_mut(),
                p_using: null_mut(),
                _tail: [0; 0x30 - 0x24],
            }];
            let (list, layout) = source_list(&mut items);
            let _restore = install_recorders(table);
            let mut parse = parse_for_slab(slab);

            let result = src_list_lookup(&mut parse, list);

            assert_eq!(result, table, "returns the final lookup result");
            assert_eq!((*list.add(1).cast::<SrcListItem>()).p_table, table, "stores the new table after release");
            assert_eq!(addr_of!(RELEASED_TABLE).read(), old_table, "releases the old table first");
            assert_eq!(table.cast::<u32>().add(TABLE_REFCOUNT_WORD).read(), 0, "the ARM reference increment wraps");
            std::alloc::dealloc(list.cast(), layout);
        }
    }
}
