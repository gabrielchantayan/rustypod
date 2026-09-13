//! SQLite expression-reference validation.
//!
//! - `sqlite_fix_expr` — original: `FUN_08379598` @ `0x08379598` (104
//!   bytes, `0x08379598..0x08379600`; the independent next prologue begins
//!   at `0x08379600`). Decoding every aligned ARM `B`/`BL` immediate in
//!   `osos.dec` finds six direct inbound `bl` calls, all unconditional:
//!   `0x08379398`, `0x083795d8`, `0x08379624`, `0x083796d4`, `0x083796e8`,
//!   and `0x0837979c`. There are no predicated call forms or tail `b`
//!   transfers. This is SQLite 3.5.x's `sqlite3FixExpr`.
//!
//! Algorithm: an absent expression succeeds. For each expression, validate
//! its sub-select (+0x38) through `sqlite3FixSelect`, its argument / `IN`
//! list (+0x10) through `sqlite3FixExprList`, then recursively validate the
//! right child (+0x0c). A nonzero child result stops immediately with one;
//! otherwise the left child (+0x08) becomes the next loop iteration. This
//! turns the left spine into a tail loop exactly as the raw ARM does.
//!
//! Deliberate host-only deviation: the two still-stock callees are absolute
//! calls to `0x08379694` and `0x08379600` on the target. Host tests replace
//! those boundaries through `FIX_EXPR_OPS`; its default no-ops reproduce
//! their NULL-input result but cannot model a non-NULL unported subtree.

use super::expr_height::Expr;

/// ABI of `sqlite3FixSelect` @ 0x08379694.
type FixSelectFn = unsafe extern "C" fn(fixer: *mut u8, select: *mut u8) -> u32;
/// ABI of `sqlite3FixExprList` @ 0x08379600.
type FixExprListFn = unsafe extern "C" fn(fixer: *mut u8, list: *mut u8) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn fix_select(fixer: *mut u8, select: *mut u8) -> u32 {
    let fix: FixSelectFn = core::mem::transmute(0x0837_9694usize);
    fix(fixer, select)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn fix_expr_list(fixer: *mut u8, list: *mut u8) -> u32 {
    let fix: FixExprListFn = core::mem::transmute(0x0837_9600usize);
    fix(fixer, list)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_fix_select(_fixer: *mut u8, _select: *mut u8) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_fix_expr_list(_fixer: *mut u8, _list: *mut u8) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct FixExprOps {
    fix_select: FixSelectFn,
    fix_expr_list: FixExprListFn,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_FIX_EXPR_OPS: FixExprOps = FixExprOps {
    fix_select: missing_fix_select,
    fix_expr_list: missing_fix_expr_list,
};

#[cfg(not(target_os = "none"))]
static mut FIX_EXPR_OPS: FixExprOps = DEFAULT_FIX_EXPR_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn fix_select(fixer: *mut u8, select: *mut u8) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(FIX_EXPR_OPS)).fix_select)(fixer, select)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn fix_expr_list(fixer: *mut u8, list: *mut u8) -> u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(FIX_EXPR_OPS)).fix_expr_list)(fixer, list)
}

/// `sqlite3FixExpr` — original: `FUN_08379598` @ `0x08379598` (104 bytes;
/// 6 unconditional direct `bl` call sites).
///
/// Validates all sub-selects, expression lists, and operands below `expr` for
/// the supplied SQLite database-fixer context. It returns one at the first
/// invalid nested reference and zero when the whole expression tree is valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.sqlite_fix_expr")]
#[inline(never)]
pub unsafe extern "C" fn sqlite_fix_expr(fixer: *mut u8, mut expr: *mut Expr) -> u32 {
    while !expr.is_null() {
        if fix_select(fixer, (*expr).p_select) != 0 {
            return 1;
        }
        if fix_expr_list(fixer, (*expr).p_list) != 0 {
            return 1;
        }
        if sqlite_fix_expr(fixer, (*expr).p_right.cast()) != 0 {
            return 1;
        }
        expr = (*expr).p_left.cast();
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(&'static str, usize)> = Vec::new();
    static mut SELECT_FAILURE: usize = 0;
    static mut LIST_FAILURE: usize = 0;

    fn lock() -> MutexGuard<'static, ()> {
        OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    unsafe fn restore_defaults() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(FIX_EXPR_OPS), DEFAULT_FIX_EXPR_OPS);
        (*core::ptr::addr_of_mut!(CALLS)).clear();
        core::ptr::write(core::ptr::addr_of_mut!(SELECT_FAILURE), 0);
        core::ptr::write(core::ptr::addr_of_mut!(LIST_FAILURE), 0);
    }

    unsafe fn calls() -> Vec<(&'static str, usize)> {
        (*core::ptr::addr_of!(CALLS)).clone()
    }

    unsafe extern "C" fn recording_fix_select(_fixer: *mut u8, select: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(CALLS)).push(("select", select as usize));
        (select as usize == core::ptr::read(core::ptr::addr_of!(SELECT_FAILURE))) as u32
    }

    unsafe extern "C" fn recording_fix_expr_list(_fixer: *mut u8, list: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(CALLS)).push(("list", list as usize));
        (list as usize == core::ptr::read(core::ptr::addr_of!(LIST_FAILURE))) as u32
    }

    unsafe fn install_recorders() {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(FIX_EXPR_OPS),
            FixExprOps {
                fix_select: recording_fix_select,
                fix_expr_list: recording_fix_expr_list,
            },
        );
    }

    fn expr(left: *mut Expr, right: *mut Expr, list: usize, select: usize) -> Expr {
        Expr {
            _gap_00: [0; 0x08],
            p_left: left.cast(),
            p_right: right.cast(),
            p_list: list as *mut u8,
            _gap_14: [0; 0x38 - 0x14],
            p_select: select as *mut u8,
            _gap_3c: [0; 0x40 - 0x3c],
            n_height: 0,
        }
    }

    #[test]
    fn null_expression_skips_both_child_fixers() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            install_recorders();
            assert_eq!(sqlite_fix_expr(0x1111usize as *mut u8, core::ptr::null_mut()), 0);
            assert!(calls().is_empty());
            restore_defaults();
        }
    }

    #[test]
    fn traverses_select_list_right_then_left_spine() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            install_recorders();
            let mut left = expr(core::ptr::null_mut(), core::ptr::null_mut(), 0x2001, 0x1001);
            let mut right = expr(core::ptr::null_mut(), core::ptr::null_mut(), 0x2002, 0x1002);
            let mut root = expr(&mut left, &mut right, 0x2003, 0x1003);

            assert_eq!(sqlite_fix_expr(0x1111usize as *mut u8, &mut root), 0);
            assert_eq!(
                calls(),
                [
                    ("select", 0x1003), ("list", 0x2003),
                    ("select", 0x1002), ("list", 0x2002),
                    ("select", 0x1001), ("list", 0x2001),
                ],
            );
            restore_defaults();
        }
    }

    #[test]
    fn first_failed_child_short_circuits_remaining_tree() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            install_recorders();
            let mut left = expr(core::ptr::null_mut(), core::ptr::null_mut(), 0x2001, 0x1001);
            let mut right = expr(core::ptr::null_mut(), core::ptr::null_mut(), 0x2002, 0x1002);
            let mut root = expr(&mut left, &mut right, 0x2003, 0x1003);
            core::ptr::write(core::ptr::addr_of_mut!(LIST_FAILURE), 0x2002);

            assert_eq!(sqlite_fix_expr(0x1111usize as *mut u8, &mut root), 1);
            assert_eq!(
                calls(),
                [
                    ("select", 0x1003), ("list", 0x2003),
                    ("select", 0x1002), ("list", 0x2002),
                ],
            );
            restore_defaults();
        }
    }
}
