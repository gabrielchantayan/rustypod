//! `sqlite_expr_list_walk` — original: `FUN_08398614` @ `0x08398614` (88
//! bytes, `0x08398614..0x0839866c`; the next real function is the ported
//! `sqlite_expr_walk` at `0x0839866c`, matching Ghidra's 88-byte extent).
//!
//! Raw ARM decoding of the 22 words finds exactly **one** branch-link in the
//! body — the unconditional `bl 0x0839866c` (`sqlite_expr_walk`) at
//! `0x08398640` — and no predicated calls. Four unconditional `bl` call
//! sites target this entry: `0x083986d0` (`sqlite_expr_walk`'s own list
//! descent), plus `0x0839870c`, `0x0839872c` and `0x0839874c` in the sibling
//! walker at `0x083986f8`.
//!
//! This is SQLite expr.c's `walkExprList`: given an `ExprList`, run the
//! expression walker over each item's `p_expr`. The original NULL-guards the
//! list, loads the signed entry count `n_expr` (+0x00) once and snapshots
//! the item-array pointer (+0x0c) once, then loops while the count is
//! greater than zero (`bgt`); each iteration walks the current item's
//! expression and — only when that walk reports success (zero) — decrements
//! the count and advances to the next 12-byte item. Any walk abort (nonzero)
//! returns one immediately; a full sweep returns zero. A NULL list succeeds
//! without touching the visitor.
//!
//! Deliberate deviation: the per-item recursion calls the ported
//! [`sqlite_expr_walk`] directly, mirroring the original's `bl 0x0839866c`
//! (the same direct-call convention as [`super::expr_list_delete`]). Field
//! reads are volatile, matching [`super::walk_expr`]. This port is the
//! shipped default of [`super::walk_expr::SQLITE_EXPR_LIST_WALK`], replacing
//! the documented stock-address seam there.

use core::ptr;

use super::expr_height::Expr;
use super::expr_list_delete::ExprList;
use super::walk_expr::{sqlite_expr_walk, ExprVisit};

/// `sqlite_expr_list_walk` — original: `FUN_08398614` @ `0x08398614` (88
/// bytes; one direct `bl`, four `bl` callers). See the module header for the
/// recovered algorithm.
///
/// Returns one as soon as any item's walk aborts; returns zero after a full
/// sweep or for a NULL list.
///
/// # Safety
///
/// `visit` must be callable. When non-NULL, `list` must be a readable
/// [`ExprList`] whose `items` pointer addresses at least `max(n_expr, 0)`
/// readable entries, and every item's `p_expr` must satisfy
/// [`sqlite_expr_walk`]'s requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_expr_list_walk(
    list: *mut u8,
    visit: ExprVisit,
    context: *mut u8,
) -> i32 {
    if list.is_null() {
        return 0;
    }

    let list = list.cast::<ExprList>();
    let mut remaining = ptr::read_volatile(ptr::addr_of!((*list).n_expr));
    let mut item = ptr::read_volatile(ptr::addr_of!((*list).items));
    while remaining > 0 {
        let expr = ptr::read_volatile(ptr::addr_of!((*item).p_expr)).cast::<Expr>();
        if sqlite_expr_walk(expr, visit, context) != 0 {
            return 1;
        }
        remaining -= 1;
        item = item.add(1);
    }

    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::expr_list_delete::ExprListItem;
    use crate::testing::SQLITE_EXPR_WALK_TEST_LOCK;

    static mut VISITS: [u8; 8] = [0; 8];
    static mut VISIT_COUNT: usize = 0;
    static mut LAST_CONTEXT: *mut u8 = ptr::null_mut();

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                VISITS = [0; 8];
                VISIT_COUNT = 0;
                LAST_CONTEXT = ptr::null_mut();
            }
        }
    }

    /// A leaf expression: NULL operands and list, carrying a recording id
    /// (+0x00) and the visitor status to return (+0x01), exactly the
    /// encoding `walk_expr`'s own tests use.
    fn leaf(id: u8, status: i8) -> Expr {
        let mut value = Expr {
            _gap_00: [0; 0x08],
            p_left: ptr::null_mut(),
            p_right: ptr::null_mut(),
            p_list: ptr::null_mut(),
            _gap_14: [0; 0x38 - 0x14],
            p_select: ptr::null_mut(),
            _gap_3c: [0; 0x40 - 0x3c],
            n_height: 0,
        };
        value._gap_00[0] = id;
        value._gap_00[1] = status as u8;
        value
    }

    unsafe extern "C" fn record_visit(context: *mut u8, node: *mut Expr) -> i32 {
        LAST_CONTEXT = context;
        VISITS[VISIT_COUNT] = (*node)._gap_00[0];
        VISIT_COUNT += 1;
        (*node)._gap_00[1] as i8 as i32
    }

    fn item(expr: *mut Expr) -> ExprListItem {
        ExprListItem { p_expr: expr.cast(), p_name: ptr::null_mut(), sort_agg_state: 0 }
    }

    fn list(n_expr: i32, items: *mut ExprListItem) -> ExprList {
        ExprList { n_expr, n_alloc: n_expr, _gap_08: [0; 0x0c - 0x08], items }
    }

    #[test]
    fn null_list_succeeds_without_calling_the_visitor() {
        let _guard = SQLITE_EXPR_WALK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _reset = Reset;

        let result = unsafe { sqlite_expr_list_walk(ptr::null_mut(), record_visit, 0x4d as *mut u8) };

        assert_eq!(result, 0);
        unsafe {
            assert_eq!(VISIT_COUNT, 0);
            assert!(LAST_CONTEXT.is_null());
        }
    }

    #[test]
    fn zero_and_negative_counts_succeed_without_walking() {
        let _guard = SQLITE_EXPR_WALK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _reset = Reset;
        let mut dangling = item(0x1 as *mut Expr);

        for count in [0, -3] {
            let mut header = list(count, ptr::addr_of_mut!(dangling));
            let result = unsafe {
                sqlite_expr_list_walk(ptr::addr_of_mut!(header).cast(), record_visit, ptr::null_mut())
            };
            assert_eq!(result, 0, "count {count} must not walk");
        }
        unsafe { assert_eq!(VISIT_COUNT, 0) };
    }

    #[test]
    fn walks_every_item_in_order_and_forwards_the_context() {
        let _guard = SQLITE_EXPR_WALK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _reset = Reset;
        let context = 0x5a as *mut u8;
        let mut a = leaf(1, 0);
        let mut b = leaf(2, 0);
        let mut c = leaf(3, 0);
        let mut items = [item(ptr::addr_of_mut!(a)), item(ptr::addr_of_mut!(b)), item(ptr::addr_of_mut!(c))];
        let mut header = list(3, items.as_mut_ptr());

        let result = unsafe {
            sqlite_expr_list_walk(ptr::addr_of_mut!(header).cast(), record_visit, context)
        };

        assert_eq!(result, 0);
        unsafe {
            assert_eq!(&VISITS[..VISIT_COUNT], &[1, 2, 3]);
            assert_eq!(LAST_CONTEXT, context);
        }
    }

    #[test]
    fn an_item_abort_stops_the_sweep_and_returns_one() {
        let _guard = SQLITE_EXPR_WALK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _reset = Reset;
        let mut a = leaf(1, 0);
        let mut b = leaf(2, 2);
        let mut c = leaf(3, 0);
        let mut items = [item(ptr::addr_of_mut!(a)), item(ptr::addr_of_mut!(b)), item(ptr::addr_of_mut!(c))];
        let mut header = list(3, items.as_mut_ptr());

        let result = unsafe {
            sqlite_expr_list_walk(ptr::addr_of_mut!(header).cast(), record_visit, ptr::null_mut())
        };

        assert_eq!(result, 1);
        unsafe { assert_eq!(&VISITS[..VISIT_COUNT], &[1, 2]) };
    }

    #[test]
    fn pruned_and_null_items_do_not_stop_the_sweep() {
        let _guard = SQLITE_EXPR_WALK_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _reset = Reset;
        let mut a = leaf(1, 1);
        let mut c = leaf(3, 0);
        let mut items = [item(ptr::addr_of_mut!(a)), item(ptr::null_mut()), item(ptr::addr_of_mut!(c))];
        let mut header = list(3, items.as_mut_ptr());

        let result = unsafe {
            sqlite_expr_list_walk(ptr::addr_of_mut!(header).cast(), record_visit, ptr::null_mut())
        };

        assert_eq!(result, 0);
        unsafe { assert_eq!(&VISITS[..VISIT_COUNT], &[1, 3]) };
    }
}
