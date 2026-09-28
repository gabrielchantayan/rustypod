//! Appending SQLite FROM-clause terms.
//!
//! - `src_list_append_from_term` — original: `FUN_083842fc` @ 0x083842fc
//!   (132 bytes; 2 plain inbound `bl` call sites, binary-scanned).
//!
//! Raw ARM spans 0x083842fc..0x0838437f; the next separately linked function
//! begins at 0x08384380. It has five outbound direct `bl` instructions, all
//! unconditional: `sqlite3SrcListAppend` @ 0x083841ec, then (only when the
//! append did not produce an item) `expr_delete`, `id_list_delete`, and
//! `select_delete`, or (when the alias token has a nonzero length) one
//! `name_from_token`. There are no predicated `bl` instructions.
//!
//! `sqlite3SrcListAppendFromTerm` calls the unported append helper with
//! `parse->db`, then adopts the trailing source-list item. An absent/empty
//! alias leaves its existing alias field intact; a nonempty alias is copied
//! into owned storage. The ON expression, subquery, and USING list are stored
//! in that order. On allocation failure or an empty returned list, ownership
//! of those three payloads is released in retail order: expression, USING
//! list, subquery. Deliberate deviation: the unported append helper remains
//! the existing volatile `SQLITE_SRC_LIST_APPEND` seam.

use super::expr_delete::expr_delete;
use super::id_list_delete::id_list_delete;
use super::name_from_token::name_from_token;
use super::select_delete::select_delete;
use super::src_list_delete::{SrcList, SrcListItem};
use super::src_list_from_table::{SrcListAppendFn, SQLITE_SRC_LIST_APPEND};

#[inline(always)]
unsafe fn src_list_append_op() -> SrcListAppendFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_SRC_LIST_APPEND))
}

/// `src_list_append_from_term` — original: `FUN_083842fc` @ 0x083842fc
/// (132 bytes; five outbound unconditional direct `bl` instructions, no
/// predicated `bl`).
///
/// SQLite's `sqlite3SrcListAppendFromTerm`: appends a table/database term and
/// transfers ownership of its alias, subquery, ON expression, and USING list
/// to the new trailing `SrcListItem`. If no item exists, releases the latter
/// three payloads and returns the append result unchanged. The target's
/// 32-bit item layout is preserved by `SrcList` and `SrcListItem`; their
/// pointer fields deliberately widen on host tests.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn src_list_append_from_term(
    parse: *mut u8,
    source_list: *mut u8,
    table: *const u8,
    database: *const u8,
    alias: *const u8,
    select: *mut u8,
    on: *mut u8,
    using: *mut u8,
) -> *mut u8 {
    let db = (parse as *const *mut u8).read();
    let list = src_list_append_op()(db, source_list, table, database);
    if list.is_null() || (*(list as *const SrcList)).n_src == 0 {
        expr_delete(on);
        id_list_delete(using);
        select_delete(select);
        return list;
    }

    let source = list as *mut SrcList;
    let item = source.add(1).cast::<SrcListItem>().add(((*source).n_src - 1) as usize);
    if !alias.is_null() && ((alias.add(core::mem::size_of::<*const u8>()) as *const u32).read() & !1) != 0 {
        (*item).z_alias = name_from_token(db, alias);
    }
    (*item).p_on = on;
    (*item).p_select = select;
    (*item).p_using = using;
    list
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut APPEND_RESULT: *mut u8 = core::ptr::null_mut();
    static mut SEEN_DB: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_append(
        db: *mut u8,
        _: *mut u8,
        _: *const u8,
        _: *const u8,
    ) -> *mut u8 {
        SEEN_DB = db;
        APPEND_RESULT
    }

    unsafe fn with_append_result(body: impl FnOnce()) {
        let saved = core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_SRC_LIST_APPEND));
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_SRC_LIST_APPEND), record_append);
        body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_SRC_LIST_APPEND), saved);
    }

    #[test]
    fn transfers_payloads_to_last_item_without_an_alias() {
        let _guard = LOCK.lock();
        unsafe {
            let mut parse = [0x1234usize];
            let mut list = [0u8; core::mem::size_of::<SrcList>() + 2 * core::mem::size_of::<SrcListItem>()];
            let header = list.as_mut_ptr().cast::<SrcList>();
            (*header).n_src = 2;
            let item = header.add(1).cast::<SrcListItem>().add(1);
            (*item).z_alias = 0xfeedusize as *mut u8;
            APPEND_RESULT = list.as_mut_ptr();
            with_append_result(|| {
                assert_eq!(src_list_append_from_term(parse.as_mut_ptr().cast(), core::ptr::null_mut(), core::ptr::null(), core::ptr::null(), core::ptr::null(), 0x11usize as *mut u8, 0x22usize as *mut u8, 0x33usize as *mut u8), list.as_mut_ptr());
            });
            assert_eq!(SEEN_DB, 0x1234usize as *mut u8);
            assert_eq!((*item).z_alias, 0xfeedusize as *mut u8);
            assert_eq!((*item).p_on, 0x22usize as *mut u8);
            assert_eq!((*item).p_select, 0x11usize as *mut u8);
            assert_eq!((*item).p_using, 0x33usize as *mut u8);
        }
    }

    #[test]
    fn null_append_result_releases_null_payloads_and_propagates_null() {
        let _guard = LOCK.lock();
        unsafe {
            let mut parse = [0usize];
            APPEND_RESULT = core::ptr::null_mut();
            with_append_result(|| {
                assert!(src_list_append_from_term(parse.as_mut_ptr().cast(), core::ptr::null_mut(), core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()).is_null());
            });
        }
    }
}
