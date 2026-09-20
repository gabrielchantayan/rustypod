//! SQLite source-list reference validation.
//!
//! `sqlite_fix_src_list` — original: `FUN_08379710` at load address
//! `0x08379710`, 188 bytes (`0x08379710..0x083797cc`; the following bytes
//! are the `"%s: cannot reference objects in other databases"` literal).
//! Decoding aligned ARM branch words finds three unconditional inbound `bl`
//! call sites (`0x0836fe44`, `0x08373de8`, and `0x083796c0`) and no
//! predicated forms. Its body has five unconditional `bl` instructions
//! (`sqlite3DbStrDup`, `sqlite3StrICmp`, `sqlite3ErrorMsg`, `sqlite3FixSelect`,
//! and `sqlite3FixExpr`) and none predicated.
//!
//! SQLite 3.5.x's `sqlite3FixSrcList` walks the `nSrc` source entries. It
//! duplicates an unqualified database name into each empty `zDatabase` field;
//! a pre-existing name must compare case-insensitively. A mismatch reports the
//! SQLite diagnostic and stops. Each entry's nested SELECT and ON/USING
//! expression trees are then recursively fixed, stopping at the first error.
//!
//! Deliberate deviation: the diagnostic's variadic table-name argument is
//! represented as a pointer to its target-width word. The current formatter
//! seam does not inspect it on host; on ARM this is exactly the fifth AAPCS
//! argument word passed by the retail call.

use super::error_msg::{sqlite_error_msg, Parse, VaList};
use super::fix_expr::sqlite_fix_expr;
use super::fix_select::sqlite_fix_select;
use super::strdup::db_str_dup;
use super::stricmp::str_icmp;

const SRC_DATABASE: usize = 0x08;
const SRC_SELECT: usize = 0x10;
const SRC_EXPR: usize = 0x1c;
const SRC_ENTRY_SIZE: usize = 0x30;
const CROSS_DATABASE_MESSAGE: *const u8 = 0x0837_97cc as *const u8;

#[inline(always)]
unsafe fn word(pointer: *const u8, offset: usize) -> *mut u8 {
    core::ptr::read(pointer.add(offset).cast::<u32>()) as usize as *mut u8
}

#[inline(always)]
unsafe fn set_word(pointer: *mut u8, offset: usize, value: *mut u8) {
    core::ptr::write(pointer.add(offset).cast::<u32>(), value as usize as u32);
}

/// `sqlite3FixSrcList` — original: `FUN_08379710` @ `0x08379710` (188 bytes;
/// three direct, unconditional inbound `bl` call sites).
///
/// Validate and qualify every source entry in `sources` for `fixer`; returns
/// one after the first rejected nested reference or database-name mismatch.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_fix_src_list")]
#[inline(never)]
pub unsafe extern "C" fn sqlite_fix_src_list(fixer: *mut u8, sources: *mut u8) -> u32 {
    if sources.is_null() {
        return 0;
    }
    let schema = word(fixer, 4);
    let count = core::ptr::read(sources.cast::<i16>());
    let mut entry = sources.add(8);
    for _ in 0..count {
        let database = word(entry, SRC_DATABASE);
        if database.is_null() {
            let parse = word(fixer, 0).cast::<Parse>();
            set_word(entry, SRC_DATABASE, db_str_dup((*parse).db, schema));
        } else if str_icmp(database, schema) != 0 {
            let parse = word(fixer, 0).cast::<Parse>();
            sqlite_error_msg(parse, CROSS_DATABASE_MESSAGE, entry.add(SRC_DATABASE).cast::<u32>() as VaList);
            return 1;
        }
        if sqlite_fix_select(fixer, word(entry, SRC_SELECT).cast()) != 0
            || sqlite_fix_expr(fixer, word(entry, SRC_EXPR).cast()) != 0
        {
            return 1;
        }
        entry = entry.add(SRC_ENTRY_SIZE);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_FIX_SRC_LIST, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    unsafe fn slab() -> Option<*mut u8> {
        (*SLAB).map(|pointer| pointer as *mut u8)
    }

    #[test]
    fn null_source_list_succeeds_without_reading_fixer() {
        unsafe { assert_eq!(sqlite_fix_src_list(core::ptr::null_mut(), core::ptr::null_mut()), 0) };
    }

    #[test]
    fn zero_and_negative_source_counts_leave_entries_untouched() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = (unsafe { slab() }) else {
            note_missing_u32_fixture("sqlite_fix_src_list");
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let fixer = slab;
            let sources = slab.add(0x100);
            core::ptr::write_unaligned(sources.cast::<i16>(), 0);
            assert_eq!(sqlite_fix_src_list(fixer, sources), 0);
            core::ptr::write_unaligned(sources.cast::<i16>(), -1);
            assert_eq!(sqlite_fix_src_list(fixer, sources), 0);
        }
    }

    #[test]
    fn null_database_and_children_are_accepted_for_each_entry() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = (unsafe { slab() }) else {
            note_missing_u32_fixture("sqlite_fix_src_list");
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let parse = slab.add(0x20).cast::<Parse>();
            (*parse).db = slab.add(0x300);
            let fixer = slab;
            set_word(fixer, 0, parse.cast());
            set_word(fixer, 4, core::ptr::null_mut());
            let sources = slab.add(0x100);
            core::ptr::write_unaligned(sources.cast::<i16>(), 2);
            assert_eq!(sqlite_fix_src_list(fixer, sources), 0);
            assert!(word(sources.add(8), SRC_DATABASE).is_null());
            assert!(word(sources.add(8 + SRC_ENTRY_SIZE), SRC_DATABASE).is_null());
        }
    }
}
