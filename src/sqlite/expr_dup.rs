//! SQLite expression-tree cloning.
//!
//! - `expr_dup` — original: `FUN_08377e58` @ 0x08377e58 (184 bytes;
//!   34 `bl` call sites, all unconditional, binary-scanned).
//!
//! Algorithm: NULL passes through without allocating. Otherwise allocate
//! a 0x44-byte `Expr`, copy it, duplicate non-NULL token text (+0x14) by
//! its packed length (+0x18 >> 1), set that token's ownership bit, and
//! clear only `span.z` (+0x1c). Recursively clone `p_left` (+0x08) and
//! `p_right` (+0x0c), then clone `p_list` (+0x10) and `p_select` (+0x38).
//! A failed text clone is retained as NULL with the ownership bit set;
//! the original does not unwind the partially cloned tree.
//!
//! Deliberate deviations: `sqlite3ExprListDup` @ 0x083786c0 and
//! `sqlite3SelectDup` @ 0x08383cc4 are not ported. Their volatile
//! dispatch slots therefore default to NULL-returning stubs; they are
//! exact for NULL fields and are replaceable when those ports land. On a
//! 64-bit host, the typed `Expr` has widened pointers, so its full typed
//! value is copied rather than the target's literal 0x44-byte span.

use super::expr_delete::Expr;
use super::mem::db_malloc_raw;
use super::strdup::db_str_ndup;

/// The original allocation request (`mov r1,#0x44`).
const EXPR_SIZE: i32 = 0x44;

/// `sqlite3ExprListDup(db, list)` @ 0x083786c0.
pub type ExprListDupFn = unsafe extern "C" fn(db: *mut u8, list: *mut u8) -> *mut u8;

/// `sqlite3SelectDup(db, select)` @ 0x08383cc4.
pub type SelectDupFn = unsafe extern "C" fn(db: *mut u8, select: *mut u8) -> *mut u8;

/// Placeholder until `sqlite3ExprListDup` is ported. It preserves the
/// original result for a NULL list and prevents an invented dependency
/// from being shipped for a non-NULL list.
pub(crate) unsafe extern "C" fn missing_expr_list_dup(_db: *mut u8, _list: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Placeholder until `sqlite3SelectDup` is ported. It preserves the
/// original result for a NULL select and prevents an invented dependency
/// from being shipped for a non-NULL select.
pub(crate) unsafe extern "C" fn missing_select_dup(_db: *mut u8, _select: *mut u8) -> *mut u8 {
    core::ptr::null_mut()
}

/// Active `sqlite3ExprListDup` operation. The stock callee has no Rust
/// port yet, so the default faithfully handles only its NULL input case.
pub static mut SQLITE_EXPR_LIST_DUP: ExprListDupFn = missing_expr_list_dup;

/// Active `sqlite3SelectDup` operation. The stock callee has no Rust
/// port yet, so the default faithfully handles only its NULL input case.
pub static mut SQLITE_SELECT_DUP: SelectDupFn = missing_select_dup;

#[inline(always)]
fn expr_list_dup_op() -> ExprListDupFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_EXPR_LIST_DUP)) }
}

#[inline(always)]
fn select_dup_op() -> SelectDupFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_SELECT_DUP)) }
}

/// expr_dup — original: `FUN_08377e58` @ 0x08377e58 (184 bytes; 34 `bl`
/// call sites, all unconditional, binary-scanned).
///
/// SQLite 3.5.x's `sqlite3ExprDup`: clone one expression tree. A NULL
/// source returns NULL. A successful top-level allocation copies the
/// node, gives a non-NULL token text independent storage and ownership,
/// clears the copied span's text pointer, then overwrites all four child
/// pointers with clones. Only a failed top-level allocation aborts; child
/// and token clone failures remain NULL in the returned partial tree.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_dup(db: *mut u8, source: *const Expr) -> *mut Expr {
    if source.is_null() {
        return core::ptr::null_mut();
    }

    let node = db_malloc_raw(db, EXPR_SIZE) as *mut Expr;
    if node.is_null() {
        return core::ptr::null_mut();
    }

    #[cfg(target_pointer_width = "32")]
    crate::libc::memcpy::memcpy_forward_words(node.cast(), source.cast(), EXPR_SIZE as usize);
    #[cfg(not(target_pointer_width = "32"))]
    core::ptr::copy_nonoverlapping(source, node, 1);

    if !(*source).token.z.is_null() {
        (*node).token.z = db_str_ndup(db, (*source).token.z, ((*source).token.n_dyn >> 1) as i32);
        (*node).token.n_dyn |= 1;
    }
    (*node).span.z = core::ptr::null();
    (*node).p_left = expr_dup(db, (*source).p_left as *const Expr).cast();
    (*node).p_right = expr_dup(db, (*source).p_right as *const Expr).cast();
    (*node).p_list = (expr_list_dup_op())(db, (*source).p_list);
    (*node).p_select = (select_dup_op())(db, (*source).p_select);
    node
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log, OPS_LOCK};
    use crate::sqlite::mem::{DbMemOps, DB_MEM_OPS, DEFAULT_DB_MEM_OPS};
    use std::sync::Mutex;
    use std::vec::Vec;

    /// Serializes the clone dispatch slots and fixture allocator.
    static CLONE_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATIONS: [*mut u8; 4] = [core::ptr::null_mut(); 4];
    static mut ALLOCATION_COUNT: usize = 0;
    static mut ALLOCATION_INDEX: usize = 0;
    static mut ALLOCATION_REQUESTS: Vec<i32> = Vec::new();
    static mut LIST_INPUTS: Vec<usize> = Vec::new();
    static mut SELECT_INPUTS: Vec<usize> = Vec::new();
    static mut LIST_RESULT: *mut u8 = core::ptr::null_mut();
    static mut SELECT_RESULT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn fixture_malloc(n: i32) -> *mut u8 {
        (*core::ptr::addr_of_mut!(ALLOCATION_REQUESTS)).push(n);
        let index = core::ptr::read(core::ptr::addr_of!(ALLOCATION_INDEX));
        if index == core::ptr::read(core::ptr::addr_of!(ALLOCATION_COUNT)) {
            return core::ptr::null_mut();
        }
        let block = (*core::ptr::addr_of!(ALLOCATIONS))[index];
        core::ptr::write(core::ptr::addr_of_mut!(ALLOCATION_INDEX), index + 1);
        block
    }

    unsafe extern "C" fn fixture_realloc(_p: *mut u8, _n: i32) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe extern "C" fn fixture_expr_list_dup(_db: *mut u8, list: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(LIST_INPUTS)).push(list as usize);
        core::ptr::read(core::ptr::addr_of!(LIST_RESULT))
    }

    unsafe extern "C" fn fixture_select_dup(_db: *mut u8, select: *mut u8) -> *mut u8 {
        (*core::ptr::addr_of_mut!(SELECT_INPUTS)).push(select as usize);
        core::ptr::read(core::ptr::addr_of!(SELECT_RESULT))
    }

    unsafe fn reset_slots() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_LIST_DUP), missing_expr_list_dup);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_SELECT_DUP), missing_select_dup);
    }

    unsafe fn with_clone_slots<R>(list_result: *mut u8, select_result: *mut u8, body: impl FnOnce() -> R) -> R {
        (*core::ptr::addr_of_mut!(LIST_INPUTS)).clear();
        (*core::ptr::addr_of_mut!(SELECT_INPUTS)).clear();
        core::ptr::write(core::ptr::addr_of_mut!(LIST_RESULT), list_result);
        core::ptr::write(core::ptr::addr_of_mut!(SELECT_RESULT), select_result);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_LIST_DUP), fixture_expr_list_dup);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_SELECT_DUP), fixture_select_dup);
        let result = body();
        reset_slots();
        result
    }

    unsafe fn with_allocations<R>(blocks: &[*mut u8], body: impl FnOnce() -> R) -> R {
        for (index, block) in blocks.iter().enumerate() {
            (*core::ptr::addr_of_mut!(ALLOCATIONS))[index] = *block;
        }
        core::ptr::write(core::ptr::addr_of_mut!(ALLOCATION_COUNT), blocks.len());
        core::ptr::write(core::ptr::addr_of_mut!(ALLOCATION_INDEX), 0);
        (*core::ptr::addr_of_mut!(ALLOCATION_REQUESTS)).clear();
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(DB_MEM_OPS),
            DbMemOps { malloc: fixture_malloc, realloc: fixture_realloc },
        );
        let result = body();
        core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
        result
    }

    unsafe fn blank_expr() -> Expr {
        core::mem::zeroed()
    }

    #[test]
    fn null_source_returns_without_allocating() {
        let _clone_guard = CLONE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _allocator_guard = install_recorder(core::ptr::null_mut());

        assert!(unsafe { expr_dup(core::ptr::null_mut(), core::ptr::null()) }.is_null());
        assert!(realloc_log().is_empty(), "NULL source must not reach the allocator");
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS) };
    }

    #[test]
    fn root_allocation_failure_sets_the_connection_flag() {
        let _clone_guard = CLONE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _allocator_guard = install_recorder(core::ptr::null_mut());
        let mut db = [0u8; 0x20];
        let source = unsafe { blank_expr() };

        assert!(unsafe { expr_dup(db.as_mut_ptr(), &source) }.is_null());
        assert_eq!(db[0x1e], 1, "db_malloc_raw records the failed allocation");
        assert_eq!(realloc_log(), std::vec![(0, EXPR_SIZE)]);
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS) };
    }

    #[test]
    fn clones_tokens_children_lists_and_selects_in_stock_order() {
        let _clone_guard = CLONE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _allocator_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut db = [0u8; 0x20];
        let text = *b"token!";
        let mut source = unsafe { blank_expr() };
        let child = unsafe { blank_expr() };
        let mut root_copy = unsafe { blank_expr() };
        let mut child_copy = unsafe { blank_expr() };
        let mut text_copy = [0xa5u8; 16];
        let mut list = 0u8;
        let mut select = 0u8;
        let mut list_copy = 0u8;
        let mut select_copy = 0u8;

        source._gap_00 = [0xa5, 0, 0x34, 0x12, 0xef, 0xff, 0xff, 0xff];
        source.p_left = (&child as *const Expr).cast_mut().cast();
        source.p_list = core::ptr::addr_of_mut!(list);
        source.p_select = core::ptr::addr_of_mut!(select);
        source.token.z = text.as_ptr();
        source.token.n_dyn = (text.len() as u32) << 1;
        source.span.z = text.as_ptr();
        source.span.n_dyn = 0xfeed_cafe;

        unsafe {
            with_allocations(
                &[
                    (&mut root_copy as *mut Expr).cast(),
                    text_copy.as_mut_ptr(),
                    (&mut child_copy as *mut Expr).cast(),
                ],
                || with_clone_slots(core::ptr::addr_of_mut!(list_copy), core::ptr::addr_of_mut!(select_copy), || {
                    let duplicate = expr_dup(db.as_mut_ptr(), &source);
                    assert_eq!(duplicate, core::ptr::addr_of_mut!(root_copy));
                    assert_eq!((*duplicate)._gap_00, source._gap_00);
                    assert_eq!((*duplicate).token.z, text_copy.as_ptr());
                    assert_eq!((*duplicate).token.n_dyn, source.token.n_dyn | 1);
                    assert_eq!(&text_copy[..text.len()], &text);
                    assert_eq!(text_copy[text.len()], 0, "the duplicated token is NUL-terminated");
                    assert!((*duplicate).span.z.is_null(), "only span.z is cleared");
                    assert_eq!((*duplicate).span.n_dyn, source.span.n_dyn);
                    assert_eq!((*duplicate).p_left, (&mut child_copy as *mut Expr).cast());
                    assert!((*duplicate).p_right.is_null());
                    assert_eq!((*duplicate).p_list, core::ptr::addr_of_mut!(list_copy));
                    assert_eq!((*duplicate).p_select, core::ptr::addr_of_mut!(select_copy));
                    assert_eq!(
                        (*core::ptr::addr_of!(ALLOCATION_REQUESTS)).as_slice(),
                        &[EXPR_SIZE, text.len() as i32 + 1, EXPR_SIZE],
                    );
                    assert_eq!(
                        (*core::ptr::addr_of!(LIST_INPUTS)).as_slice(),
                        &[0, core::ptr::addr_of_mut!(list) as usize],
                        "the cloned leaf reaches sqlite3ExprListDup before its parent",
                    );
                    assert_eq!(
                        (*core::ptr::addr_of!(SELECT_INPUTS)).as_slice(),
                        &[0, core::ptr::addr_of_mut!(select) as usize],
                        "the cloned leaf reaches sqlite3SelectDup before its parent",
                    );
                }),
            );
        }
        assert!(db.iter().all(|&byte| byte == 0), "successful clone leaves mallocFailed clear");
    }
}
