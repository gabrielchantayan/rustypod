//! Folding a `SELECT` statement's cached expression heights into a
//! running maximum — the per-sub-select helper `expr_set_height` runs
//! on a node's `p_select`.
//!
//! - `select_height` — original: `FUN_082d2a8c` @ 0x082d2a8c (112
//!   bytes; called from `expr_set_height` @ 0x083788fc once and
//!   `sqlite3SelectExprHeight` @ 0x08383dd0 once). SQLite 3.5.x's
//!   `heightOfSelect`.
//!
//! Algorithm: a NULL-safe fold over a compound-select chain. While the
//! select is non-NULL, fold its four clause expressions — p_where
//! (+0x10), p_having (+0x18), p_limit (+0x2c), p_offset (+0x30) —
//! through `exprHeight` @ 0x082d2a34 (ported as
//! [`crate::sqlite::expr_height_of::expr_height_of`]) and its three
//! expression lists — p_elist (+0x00), p_group_by (+0x14), p_order_by
//! (+0x1c) — through `heightOfExprList` @ 0x082d2a4c (ported as
//! [`crate::sqlite::expr_list_height::expr_list_height`]), then step
//! onto p_prior (+0x20). The recursion over the compound-select chain
//! is a tail loop in the original:
//!
//! ```text
//! 082d2a8c:  stmdb sp!,{r4,r5,r6,lr}
//! 082d2a90:  movs r4,r0               ; r4 = select; flags on NULL test
//! 082d2a94:  mov  r5,r1               ; r5 = height
//! 082d2a98:  ldmiaeq sp!,{r4,r5,r6,pc}  ; if (select == NULL) return
//! 082d2a9c:  ldr  r0,[r4,#0x10]      ; select->p_where
//! 082d2aa4:  bl   0x082d2a34         ; exprHeight(p_where, height)
//! 082d2aa8:  ldr  r0,[r4,#0x18]      ; select->p_having
//! 082d2ab0:  bl   0x082d2a34         ; exprHeight(p_having, height)
//! 082d2ab4:  ldr  r0,[r4,#0x2c]      ; select->p_limit
//! 082d2abc:  bl   0x082d2a34         ; exprHeight(p_limit, height)
//! 082d2ac0:  ldr  r0,[r4,#0x30]      ; select->p_offset
//! 082d2ac8:  bl   0x082d2a34         ; exprHeight(p_offset, height)
//! 082d2acc:  ldr  r0,[r4,#0x0]       ; select->p_elist
//! 082d2ad4:  bl   0x082d2a4c         ; heightOfExprList(p_elist, height)
//! 082d2ad8:  ldr  r0,[r4,#0x14]      ; select->p_group_by
//! 082d2ae0:  bl   0x082d2a4c         ; heightOfExprList(p_group_by, height)
//! 082d2ae4:  ldr  r0,[r4,#0x1c]      ; select->p_order_by
//! 082d2aec:  bl   0x082d2a4c         ; heightOfExprList(p_order_by, height)
//! 082d2af0:  ldr  r0,[r4,#0x20]      ; select->p_prior
//! 082d2af4:  mov  r1,r5
//! 082d2af8:  b    0x082d2a90         ; tail loop onto p_prior
//! ```
//!
//! i.e. `while (select) { ...folds...; select = select->pPrior; }` —
//! exactly the field order of the SQLite 3.5.x source (`pWhere`,
//! `pHaving`, `pLimit`, `pOffset`, `pEList`, `pGroupBy`, `pOrderBy`).
//! The folds inherit the signed-maximum, NULL-safe semantics of the two
//! helpers: a NULL clause folds nothing and a negative cached height
//! never lowers the accumulator.
//!
//! `Select` fields used (pinned by this function's `ldr [r4,#off]`
//! sequence and cross-checked against the SQLite 3.5.x sources):
//!
//! ```text
//! +0x00 p_elist    (ExprList *)  result column list
//! +0x10 p_where    (Expr *)      WHERE clause
//! +0x14 p_group_by (ExprList *)  GROUP BY clause
//! +0x18 p_having   (Expr *)      HAVING clause
//! +0x1c p_order_by (ExprList *)  ORDER BY clause
//! +0x20 p_prior    (Select *)    prior select of a compound
//! +0x2c p_limit    (Expr *)      LIMIT expression
//! +0x30 p_offset   (Expr *)      OFFSET expression
//! ```
//!
//! Register usage: r0 = select, r1 = height accumulator pointer;
//! r4 = select, r5 = height.
//!
//! Deviations:
//! - The select is read through a typed [`Select`] struct rather than
//!   raw byte offsets, so the code is layout-correct on the 64-bit test
//!   host; on the 32-bit target the field offsets are statically
//!   asserted (`_SELECT_*_OFFSET`).
//! - The clause and list folds call the ported
//!   [`crate::sqlite::expr_height_of::expr_height_of`] and
//!   [`crate::sqlite::expr_list_height::expr_list_height`] directly,
//!   the same direct `bl`s the original makes.

use super::expr_height_of::expr_height_of;
use super::expr_list_height::expr_list_height;

/// A select statement (`sqlite3Select`), only the fields this fold
/// touches. The full layout is documented in the module header.
#[repr(C)]
pub struct Select {
    /// +0x00: result column list (`ExprList *`, may be NULL).
    pub p_elist: *mut u8,
    /// +0x04..+0x10: the op/distinct bytes (+0x04) and the FROM source
    /// list (+0x08) — unmodeled.
    pub _gap_04: [u8; 0x10 - 0x04],
    /// +0x10: WHERE clause (`Expr *`, may be NULL).
    pub p_where: *mut u8,
    /// +0x14: GROUP BY clause (`ExprList *`, may be NULL).
    pub p_group_by: *mut u8,
    /// +0x18: HAVING clause (`Expr *`, may be NULL).
    pub p_having: *mut u8,
    /// +0x1c: ORDER BY clause (`ExprList *`, may be NULL).
    pub p_order_by: *mut u8,
    /// +0x20: prior select of a compound select (`Select *`, may be
    /// NULL) — the fold tail-loops down this chain.
    pub p_prior: *mut Select,
    /// +0x24..+0x2c: the next-select pointer (+0x24) and one more word
    /// — unmodeled.
    pub _gap_24: [u8; 0x2c - 0x24],
    /// +0x2c: LIMIT expression (`Expr *`, may be NULL).
    pub p_limit: *mut u8,
    /// +0x30: OFFSET expression (`Expr *`, may be NULL).
    pub p_offset: *mut u8,
}

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed struct.
#[cfg(target_pointer_width = "32")]
const _SELECT_P_ELIST_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(Select, p_elist)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_WHERE_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(Select, p_where)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_GROUP_BY_OFFSET: [u8; 0x14] = [0; core::mem::offset_of!(Select, p_group_by)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_HAVING_OFFSET: [u8; 0x18] = [0; core::mem::offset_of!(Select, p_having)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_ORDER_BY_OFFSET: [u8; 0x1c] = [0; core::mem::offset_of!(Select, p_order_by)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_PRIOR_OFFSET: [u8; 0x20] = [0; core::mem::offset_of!(Select, p_prior)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_LIMIT_OFFSET: [u8; 0x2c] = [0; core::mem::offset_of!(Select, p_limit)];
#[cfg(target_pointer_width = "32")]
const _SELECT_P_OFFSET_OFFSET: [u8; 0x30] = [0; core::mem::offset_of!(Select, p_offset)];

/// select_height — original: `FUN_082d2a8c` @ 0x082d2a8c (112 bytes).
///
/// `heightOfSelect`: while `select` is non-NULL, fold the cached
/// heights of its WHERE/HAVING/LIMIT/OFFSET expressions into `*height`
/// through [`expr_height_of`] and of its result/GROUP BY/ORDER BY
/// lists through [`expr_list_height`], keeping the running signed
/// maximum, then tail-loop onto the compound-select `p_prior` chain. A
/// NULL select leaves the accumulator untouched.
///
/// Takes the select as `*mut u8` (casting to [`Select`] internally) so
/// it drops straight into the `HeightFoldFn` shape of the
/// `SQLITE_SELECT_HEIGHT_FOLD` dispatch slot in `sqlite/expr_height.rs`,
/// where it is the default.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn select_height(select: *mut u8, height: *mut i32) {
    let mut select = select as *const Select;
    // Original: pre-tested loop; the compound-select recursion is a
    // tail loop (`b 0x082d2a90` back to the NULL check).
    while !select.is_null() {
        expr_height_of((*select).p_where, height);
        expr_height_of((*select).p_having, height);
        expr_height_of((*select).p_limit, height);
        expr_height_of((*select).p_offset, height);
        expr_list_height((*select).p_elist, height);
        expr_list_height((*select).p_group_by, height);
        expr_list_height((*select).p_order_by, height);
        select = (*select).p_prior;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::expr_height::Expr;
    use super::super::expr_list_height::{ExprList, ExprListItem};
    use std::vec::Vec;

    /// A child expression node with the given cached height.
    fn child_node(height: i32) -> Expr {
        Expr {
            _gap_00: [0xa5; 0x08],
            p_left: core::ptr::null_mut(),
            p_right: core::ptr::null_mut(),
            p_list: core::ptr::null_mut(),
            _gap_14: [0xa5; 0x38 - 0x14],
            p_select: core::ptr::null_mut(),
            _gap_3c: [0xa5; 0x40 - 0x3c],
            n_height: height,
        }
    }

    /// A one-item expression list over `expr` (NULL `expr` for an
    /// empty-fold list); the gap bytes carry a 0xa5 canary.
    fn list_of(items: &mut Vec<ExprListItem>, exprs: &mut [Expr]) -> ExprList {
        for (item, expr) in items.iter_mut().zip(exprs.iter_mut()) {
            item.p_expr = expr as *mut Expr as *mut u8;
        }
        ExprList {
            n_expr: items.len() as i32,
            _gap_04: [0xa5; 0x0c - 0x04],
            items: items.as_mut_ptr(),
        }
    }

    fn list_item() -> ExprListItem {
        ExprListItem { p_expr: core::ptr::null_mut(), _gap_04: [0xa5; 0x0c - 0x04] }
    }

    /// A select with every clause NULL; the gap bytes carry a 0xa5
    /// canary for the "select is only read" test.
    fn bare_select() -> Select {
        Select {
            p_elist: core::ptr::null_mut(),
            _gap_04: [0xa5; 0x10 - 0x04],
            p_where: core::ptr::null_mut(),
            p_group_by: core::ptr::null_mut(),
            p_having: core::ptr::null_mut(),
            p_order_by: core::ptr::null_mut(),
            p_prior: core::ptr::null_mut(),
            _gap_24: [0xa5; 0x2c - 0x24],
            p_limit: core::ptr::null_mut(),
            p_offset: core::ptr::null_mut(),
        }
    }

    #[test]
    fn a_null_select_folds_nothing() {
        let mut height: i32 = 0;
        unsafe {
            select_height(core::ptr::null_mut(), &mut height);
        }
        assert_eq!(height, 0, "NULL folds as 0 into the 0 seed");

        let mut height: i32 = -7;
        unsafe {
            select_height(core::ptr::null_mut(), &mut height);
        }
        assert_eq!(height, -7, "movs/ldmiaeq: NULL never touches the accumulator");

        let mut height: i32 = 42;
        unsafe {
            select_height(core::ptr::null_mut(), &mut height);
        }
        assert_eq!(height, 42, "movs/ldmiaeq: NULL never touches the accumulator");
    }

    #[test]
    fn a_bare_select_folds_nothing() {
        let mut select = bare_select();
        let mut height: i32 = 5;
        unsafe {
            select_height(&mut select as *mut Select as *mut u8, &mut height);
        }
        assert_eq!(height, 5, "every clause NULL: the accumulator never moves");
    }

    #[test]
    fn each_clause_expression_folds_its_height() {
        // Pin +0x10/+0x18/+0x2c/+0x30 one at a time: with exactly one
        // clause set, only that clause's height can land in the
        // accumulator.
        for (slot, offset) in [("+0x10 p_where", 0), ("+0x18 p_having", 1), ("+0x2c p_limit", 2), ("+0x30 p_offset", 3)] {
            let mut clause = child_node(9);
            let mut select = bare_select();
            let clause_ptr = &mut clause as *mut Expr as *mut u8;
            match offset {
                0 => select.p_where = clause_ptr,
                1 => select.p_having = clause_ptr,
                2 => select.p_limit = clause_ptr,
                _ => select.p_offset = clause_ptr,
            }
            let mut height: i32 = 3;
            unsafe {
                select_height(&mut select as *mut Select as *mut u8, &mut height);
            }
            assert_eq!(height, 9, "{slot} folds through exprHeight");
        }
    }

    #[test]
    fn each_expression_list_folds_its_items() {
        // Pin +0x00/+0x14/+0x1c one at a time with a two-item list.
        for (slot, offset) in [("+0x00 p_elist", 0), ("+0x14 p_group_by", 1), ("+0x1c p_order_by", 2)] {
            let mut exprs = std::vec![child_node(4), child_node(8)];
            let mut items = std::vec![list_item(), list_item()];
            let mut list = list_of(&mut items, &mut exprs);
            let mut select = bare_select();
            let list_ptr = &mut list as *mut ExprList as *mut u8;
            match offset {
                0 => select.p_elist = list_ptr,
                1 => select.p_group_by = list_ptr,
                _ => select.p_order_by = list_ptr,
            }
            let mut height: i32 = 0;
            unsafe {
                select_height(&mut select as *mut Select as *mut u8, &mut height);
            }
            assert_eq!(height, 8, "{slot} folds through heightOfExprList: max(4, 8)");
        }
    }

    #[test]
    fn all_seven_clauses_share_one_running_signed_maximum() {
        let mut where_ = child_node(2);
        let mut having = child_node(11);
        let mut limit = child_node(-3);
        let mut offset = child_node(5);
        let mut elist_exprs = std::vec![child_node(7)];
        let mut elist_items = std::vec![list_item()];
        let mut elist = list_of(&mut elist_items, &mut elist_exprs);
        let mut group_exprs = std::vec![child_node(1)];
        let mut group_items = std::vec![list_item()];
        let mut group_by = list_of(&mut group_items, &mut group_exprs);
        let mut order_exprs = std::vec![child_node(6)];
        let mut order_items = std::vec![list_item()];
        let mut order_by = list_of(&mut order_items, &mut order_exprs);

        let mut select = bare_select();
        select.p_where = &mut where_ as *mut Expr as *mut u8;
        select.p_having = &mut having as *mut Expr as *mut u8;
        select.p_limit = &mut limit as *mut Expr as *mut u8;
        select.p_offset = &mut offset as *mut Expr as *mut u8;
        select.p_elist = &mut elist as *mut ExprList as *mut u8;
        select.p_group_by = &mut group_by as *mut ExprList as *mut u8;
        select.p_order_by = &mut order_by as *mut ExprList as *mut u8;

        let mut height: i32 = 0;
        unsafe {
            select_height(&mut select as *mut Select as *mut u8, &mut height);
        }
        assert_eq!(height, 11, "max(2, 11, -3, 5, 7, 1, 6): HAVING wins, the negative LIMIT folds nothing");

        // A seed above every clause is never lowered.
        let mut height: i32 = 40;
        unsafe {
            select_height(&mut select as *mut Select as *mut u8, &mut height);
        }
        assert_eq!(height, 40, "strgt: no clause beats the seed");
    }

    #[test]
    fn the_fold_tail_loops_down_the_prior_chain() {
        let mut first_where = child_node(3);
        let mut prior_where = child_node(9);
        let mut grand_where = child_node(6);

        let mut grand = bare_select();
        grand.p_where = &mut grand_where as *mut Expr as *mut u8;
        let mut prior = bare_select();
        prior.p_where = &mut prior_where as *mut Expr as *mut u8;
        prior.p_prior = &mut grand;
        let mut select = bare_select();
        select.p_where = &mut first_where as *mut Expr as *mut u8;
        select.p_prior = &mut prior;

        let mut height: i32 = 0;
        unsafe {
            select_height(&mut select as *mut Select as *mut u8, &mut height);
        }
        assert_eq!(height, 9, "max over the whole compound chain: 3, 9, 6");

        // A NULL p_prior ends the walk.
        let mut lone = bare_select();
        lone.p_where = &mut first_where as *mut Expr as *mut u8;
        let mut height: i32 = 0;
        unsafe {
            select_height(&mut lone as *mut Select as *mut u8, &mut height);
        }
        assert_eq!(height, 3, "ldmiaeq: a NULL prior terminates the loop");
    }

    #[test]
    fn the_select_is_only_read() {
        let mut where_ = child_node(4);
        let mut prior = bare_select();
        let mut select = bare_select();
        select.p_where = &mut where_ as *mut Expr as *mut u8;
        select.p_prior = &mut prior;

        let mut height: i32 = 0;
        unsafe {
            select_height(&mut select as *mut Select as *mut u8, &mut height);
        }
        assert_eq!(height, 4);
        assert!(select._gap_04.iter().all(|b| *b == 0xa5), "op/FROM gap clobbered");
        assert!(select._gap_24.iter().all(|b| *b == 0xa5), "pNext gap clobbered");
        assert_eq!(select.p_where, &mut where_ as *mut Expr as *mut u8, "clauses only read");
        assert!(core::ptr::eq(select.p_prior, &prior), "p_prior is read, not written");
        assert!(select.p_elist.is_null() && select.p_group_by.is_null());
        assert!(select.p_having.is_null() && select.p_order_by.is_null());
        assert!(select.p_limit.is_null() && select.p_offset.is_null());
        assert!(prior._gap_04.iter().all(|b| *b == 0xa5), "prior gap clobbered");
        assert!(prior.p_prior.is_null(), "the prior's own chain is untouched");
        assert_eq!(where_.n_height, 4, "the clause's height word is read, not written");
    }
}
