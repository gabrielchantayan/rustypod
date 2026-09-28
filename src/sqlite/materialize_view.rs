//! Materializing a SQLite view into an ephemeral table.
//!
//! `materialize_view` is `FUN_0837d3b0` at load address `0x0837d3b0`.
//! Raw `osos.dec` fixes its extent at 204 bytes (`0x0837d3b0..0x0837d47b`);
//! `push {r4-r8,lr}` at `0x0837d47c` begins the next function. A whole-image
//! ARM B/BL decode finds two inbound direct calls, both predicated `blne`
//! (`0x08374d54` and `0x08385968`), and no plain `bl` calls. The body has
//! seven unconditional outbound `bl` instructions and no predicated calls.
//!
//! It duplicates the view SELECT, optionally wraps it in a new SELECT whose
//! sole FROM item is that duplicate and whose WHERE clause is duplicated,
//! executes it into `SRT_EphemTab` (destination kind 9), then releases the
//! resulting SELECT. Deliberate deviations: `sqlite3SelectDup`,
//! `sqlite3SelectNew`, and `sqlite3Select` are not yet ported. Target builds
//! invoke their verified retail entries; host builds expose replaceable seams.

use super::expr_dup::select_dup_op;
use super::expr_dup::expr_dup;
use super::select_delete::select_delete;
use super::select_dest_init::{select_dest_init, SelectDest};
use super::src_list_append_from_term::src_list_append_from_term;

pub type SelectNewFn = unsafe extern "C" fn(
    *mut u8, *mut u8, *mut u8, *mut u8, *mut u8, *mut u8, *mut u8, i32, *mut u8, *mut u8,
) -> *mut u8;
pub type SelectFn = unsafe extern "C" fn(*mut u8, *mut u8, *mut SelectDest, i32, i32, i32, i32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_select_new(
    parse: *mut u8, elist: *mut u8, src: *mut u8, where_clause: *mut u8, group_by: *mut u8,
    having: *mut u8, order_by: *mut u8, distinct: i32, limit: *mut u8, offset: *mut u8,
) -> *mut u8 {
    core::mem::transmute::<usize, SelectNewFn>(0x0838_3dec)(parse, elist, src, where_clause, group_by, having, order_by, distinct, limit, offset)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_select_new(_: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8, _: i32, _: *mut u8, _: *mut u8) -> *mut u8 {
    panic!("materialize_view requires sqlite3SelectNew @ 0x08383dec")
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_select(parse: *mut u8, select: *mut u8, destination: *mut SelectDest, a: i32, b: i32, c: i32, d: i32) -> i32 {
    core::mem::transmute::<usize, SelectFn>(0x0838_2e28)(parse, select, destination, a, b, c, d)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_select(_: *mut u8, _: *mut u8, _: *mut SelectDest, _: i32, _: i32, _: i32, _: i32) -> i32 {
    panic!("materialize_view requires sqlite3Select @ 0x08382e28")
}

#[cfg(target_os = "none")]
pub static mut SQLITE_SELECT_NEW: SelectNewFn = retail_select_new;
#[cfg(not(target_os = "none"))]
pub static mut SQLITE_SELECT_NEW: SelectNewFn = missing_select_new;
#[cfg(target_os = "none")]
pub static mut SQLITE_SELECT: SelectFn = retail_select;
#[cfg(not(target_os = "none"))]
pub static mut SQLITE_SELECT: SelectFn = missing_select;

#[inline(always)]
unsafe fn select_new_op() -> SelectNewFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_SELECT_NEW))
}
#[inline(always)]
unsafe fn select_op() -> SelectFn {
    core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_SELECT))
}

/// `materialize_view` — original: `FUN_0837d3b0` @ `0x0837d3b0` (204 bytes;
/// two inbound predicated `blne` calls, seven outbound unconditional `bl`s).
///
/// Duplicates and executes `view_select` into ephemeral cursor `cursor`. If a
/// WHERE clause is supplied, it builds the equivalent outer SELECT first.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn materialize_view(parse: *mut u8, view_select: *mut u8, where_clause: *mut u8, cursor: i32) {
    let db = (parse as *const *mut u8).read();
    let mut select = select_dup_op()(db, view_select);
    if !where_clause.is_null() {
        let where_copy = expr_dup(db, where_clause.cast()).cast();
        let source_list = src_list_append_from_term(parse, core::ptr::null_mut(), core::ptr::null(), core::ptr::null(), core::ptr::null(), select, core::ptr::null_mut(), core::ptr::null_mut());
        select = select_new_op()(parse, core::ptr::null_mut(), source_list, where_copy, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 0, core::ptr::null_mut(), core::ptr::null_mut());
    }
    let mut destination = core::mem::zeroed::<SelectDest>();
    select_dest_init(&mut destination, 9, cursor);
    select_op()(parse, select, &mut destination, 0, 0, 0, 0);
    select_delete(select);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::expr_delete::Expr;
    use crate::sqlite::expr_dup::{SelectDupFn, SQLITE_SELECT_DUP};
    use crate::sqlite::mem::tests::install_recorder;
    use crate::sqlite::src_list_delete::{SrcList, SrcListItem};
    use crate::sqlite::src_list_from_table::{SrcListAppendFn, SQLITE_SRC_LIST_APPEND};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut DUP_RESULT: *mut u8 = core::ptr::null_mut();
    static mut APPEND_RESULT: *mut u8 = core::ptr::null_mut();
    static mut NEW_ARGS: (*mut u8, *mut u8, *mut u8) = (core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut());
    static mut EXECUTE: (*mut u8, u8, i32, [i32; 4]) = (core::ptr::null_mut(), 0, 0, [1; 4]);

    unsafe extern "C" fn duplicate(_: *mut u8, _: *mut u8) -> *mut u8 { DUP_RESULT }
    unsafe extern "C" fn append(_: *mut u8, _: *mut u8, _: *const u8, _: *const u8) -> *mut u8 { APPEND_RESULT }
    unsafe extern "C" fn select_new(parse: *mut u8, _: *mut u8, src: *mut u8, where_clause: *mut u8, _: *mut u8, _: *mut u8, _: *mut u8, _: i32, _: *mut u8, _: *mut u8) -> *mut u8 { NEW_ARGS = (parse, src, where_clause); core::ptr::null_mut() }
    unsafe extern "C" fn execute(_: *mut u8, select: *mut u8, destination: *mut SelectDest, a: i32, b: i32, c: i32, d: i32) -> i32 { EXECUTE = (select, (*destination).e_dest, (*destination).i_sd_parm, [a, b, c, d]); 0 }

    unsafe fn with_slots(body: impl FnOnce()) {
        let saved_dup: SelectDupFn = SQLITE_SELECT_DUP;
        let saved_append: SrcListAppendFn = SQLITE_SRC_LIST_APPEND;
        let saved_new = SQLITE_SELECT_NEW;
        let saved_select = SQLITE_SELECT;
        SQLITE_SELECT_DUP = duplicate;
        SQLITE_SRC_LIST_APPEND = append;
        SQLITE_SELECT_NEW = select_new;
        SQLITE_SELECT = execute;
        body();
        SQLITE_SELECT_DUP = saved_dup;
        SQLITE_SRC_LIST_APPEND = saved_append;
        SQLITE_SELECT_NEW = saved_new;
        SQLITE_SELECT = saved_select;
    }

    #[test]
    fn executes_duplicate_directly_without_a_where_clause() {
        let _guard = LOCK.lock();
        unsafe {
            DUP_RESULT = core::ptr::null_mut();
            EXECUTE = (1usize as *mut u8, 0, 0, [1; 4]);
            let mut parse = [0x1234usize];
            with_slots(|| materialize_view(parse.as_mut_ptr().cast(), 0xaaaausize as *mut u8, core::ptr::null_mut(), -7));
            assert_eq!(EXECUTE, (core::ptr::null_mut(), 9, -7, [0; 4]));
        }
    }

    #[test]
    fn wraps_where_clause_in_a_new_select_before_execution() {
        let _guard = LOCK.lock();
        unsafe {
            let mut source = core::mem::zeroed::<Expr>();
            let mut where_copy = core::mem::zeroed::<Expr>();
            let mut list = [0u8; core::mem::size_of::<SrcList>() + core::mem::size_of::<SrcListItem>()];
            let header = list.as_mut_ptr().cast::<SrcList>();
            (*header).n_src = 1;
            DUP_RESULT = 0x4444usize as *mut u8;
            APPEND_RESULT = list.as_mut_ptr();
            NEW_ARGS = (core::ptr::null_mut(), core::ptr::null_mut(), 1usize as *mut u8);
            EXECUTE = (1usize as *mut u8, 0, 0, [1; 4]);
            let mut db = [0u8; 0x40];
            let mut parse = [db.as_mut_ptr() as usize];
            let _allocator_guard = install_recorder((&mut where_copy as *mut Expr).cast());
            with_slots(|| materialize_view(parse.as_mut_ptr().cast(), 0xaaaausize as *mut u8, (&mut source as *mut Expr).cast(), 42));
            let item = header.add(1).cast::<SrcListItem>();
            assert_eq!((*item).p_select, 0x4444usize as *mut u8);
            assert_eq!(NEW_ARGS, (parse.as_mut_ptr().cast(), list.as_mut_ptr(), (&mut where_copy as *mut Expr).cast()));
            assert_eq!(EXECUTE, (core::ptr::null_mut(), 9, 42, [0; 4]));
        }
    }
}
