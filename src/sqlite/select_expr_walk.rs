//! `sqlite_select_expr_walk` — original: `FUN_083986f8` @ `0x083986f8` (116
//! bytes, `0x083986f8..0x0839876c`; the next separately linked function begins
//! at `0x0839876c`).
//!
//! Raw ARM decoding finds six outbound branch-link instructions: five plain
//! `bl` calls (three to `sqlite_expr_list_walk` and two to `sqlite_expr_walk`)
//! and one predicated `blne` recursive call. This is SQLite 3.5.x's
//! select-expression walk: it walks a SELECT's result, WHERE, GROUP BY,
//! HAVING, and ORDER BY expressions in that order, then recursively processes
//! `p_prior` when present. The retail code deliberately discards every child
//! walk's return value and always returns zero.
//!
//! Deliberate deviation: typed target-layout views keep host pointer fields
//! disjoint; the raw function accesses the same fields at +0x00, +0x10,
//! +0x14, +0x18, +0x1c, and +0x20. Child calls directly target the two ported
//! siblings, preserving the original's direct-call seams.

use core::ptr;

use super::select_height::Select;
use super::walk_expr::{sqlite_expr_walk, ExprVisit};
use super::expr_list_walk::sqlite_expr_list_walk;

/// `sqlite_select_expr_walk` — original: `FUN_083986f8` @ `0x083986f8` (116
/// bytes; five plain and one predicated direct `bl`). See the module header for
/// the recovered algorithm.
///
/// # Safety
///
/// `visit` must be callable. `select` must name a readable `Select` chain;
/// every non-NULL clause pointer inherits the safety requirements of its child
/// walker.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_select_expr_walk(
    select: *mut Select,
    visit: ExprVisit,
    context: *mut u8,
) -> i32 {
    let select = &*select;
    sqlite_expr_list_walk(ptr::read_volatile(ptr::addr_of!(select.p_elist)), visit, context);
    sqlite_expr_walk(ptr::read_volatile(ptr::addr_of!(select.p_where)).cast(), visit, context);
    sqlite_expr_list_walk(ptr::read_volatile(ptr::addr_of!(select.p_group_by)), visit, context);
    sqlite_expr_walk(ptr::read_volatile(ptr::addr_of!(select.p_having)).cast(), visit, context);
    sqlite_expr_list_walk(ptr::read_volatile(ptr::addr_of!(select.p_order_by)), visit, context);

    let prior = ptr::read_volatile(ptr::addr_of!(select.p_prior));
    if !prior.is_null() {
        sqlite_select_expr_walk(prior, visit, context);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::expr_height::Expr;
    use crate::sqlite::expr_list_delete::{ExprList, ExprListItem};

    unsafe extern "C" fn record_visit(context: *mut u8, expr: *mut Expr) -> i32 {
        let visits = &mut *(context as *mut [usize; 8]);
        let index = visits[0];
        visits[index + 1] = expr as usize;
        visits[0] = index + 1;
        2
    }

    unsafe fn list(expr: *mut Expr) -> (ExprList, ExprListItem) {
        let mut item = ExprListItem { p_expr: expr.cast(), p_name: ptr::null_mut(), sort_agg_state: 0 };
        let list = ExprList { n_expr: 1, n_alloc: 1, _gap_08: [0; 4], items: &mut item };
        (list, item)
    }

    #[test]
    fn visits_every_clause_in_field_order_despite_child_abort_results() {
        unsafe {
            let mut expressions: [Expr; 6] = core::mem::zeroed();
            let (mut result_list, mut result_item) = list(&mut expressions[0]);
            result_list.items = &mut result_item;
            let (mut group_list, mut group_item) = list(&mut expressions[2]);
            group_list.items = &mut group_item;
            let (mut order_list, mut order_item) = list(&mut expressions[4]);
            order_list.items = &mut order_item;
            let mut prior = Select {
                p_elist: ptr::null_mut(), _gap_04: [0; 12], p_where: &mut expressions[5] as *mut Expr as *mut u8,
                p_group_by: ptr::null_mut(), p_having: ptr::null_mut(), p_order_by: ptr::null_mut(),
                p_prior: ptr::null_mut(), _gap_24: [0; 8], p_limit: ptr::null_mut(), p_offset: ptr::null_mut(),
            };
            let mut select = Select {
                p_elist: (&mut result_list as *mut ExprList).cast(), _gap_04: [0; 12],
                p_where: &mut expressions[1] as *mut Expr as *mut u8, p_group_by: (&mut group_list as *mut ExprList).cast(),
                p_having: &mut expressions[3] as *mut Expr as *mut u8, p_order_by: (&mut order_list as *mut ExprList).cast(),
                p_prior: &mut prior, _gap_24: [0; 8], p_limit: ptr::null_mut(), p_offset: ptr::null_mut(),
            };
            let mut visits = [0_usize; 8];

            assert_eq!(sqlite_select_expr_walk(&mut select, record_visit, visits.as_mut_ptr().cast()), 0);
            assert_eq!(visits[0], 6);
            for index in 0..6 {
                assert_eq!(visits[index + 1], &mut expressions[index] as *mut Expr as usize);
            }
        }
    }

    #[test]
    fn null_clause_pointers_and_empty_prior_return_zero_without_visits() {
        unsafe {
            let mut select: Select = core::mem::zeroed();
            let mut visits = [0_usize; 8];
            assert_eq!(sqlite_select_expr_walk(&mut select, record_visit, visits.as_mut_ptr().cast()), 0);
            assert_eq!(visits[0], 0);
        }
    }
}
