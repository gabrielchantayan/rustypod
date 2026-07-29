//! Folding an expression list's cached heights into a running maximum —
//! the per-argument helper `expr_set_height` runs on a node's `ExprList`.
//!
//! - `expr_list_height` — original: `FUN_082d2a4c` @ 0x082d2a4c (64
//!   bytes; called from `expr_set_height` @ 0x083788fc once and
//!   `heightOfSelect` @ 0x082d2a8c three times). SQLite 3.5.x's
//!   `heightOfExprList`.
//!
//! Algorithm: a NULL-safe counted fold. If the list is non-NULL, walk
//! its `n_expr` (+0x00) entries — a 12-byte-stride item array at +0x0c
//! whose first word is the `Expr *` — and fold each item's expression
//! into the caller's accumulator through `exprHeight` @ 0x082d2a34
//! (ported as [`crate::sqlite::expr_height_of::expr_height_of`]):
//!
//! ```text
//! 082d2a4c:  stmdb sp!,{r4,r5,lr}
//! 082d2a50:  movs r4,r0               ; r4 = list; flags on NULL test
//! 082d2a54:  mov  r5,r1               ; r5 = height
//! 082d2a58:  ldmiaeq sp!,{r4,r5,pc}  ; if (list == NULL) return
//! 082d2a5c:  mov  r3,#0x0            ; i = 0
//! 082d2a60:  b    0x082d2a7c         ; pre-tested loop
//! 082d2a64:  ldr  r0,[r4,#0xc]       ; items = list->items
//! 082d2a68:  add  r1,r3,r3, lsl #0x1 ; r1 = i * 3
//! 082d2a6c:  ldr  r0,[r0,r1,lsl #0x2]; r0 = items[i*12] = item.p_expr
//! 082d2a70:  mov  r1,r5
//! 082d2a74:  bl   0x082d2a34         ; exprHeight(item.p_expr, height)
//! 082d2a78:  add  r3,r3,#0x1         ; i++
//! 082d2a7c:  ldr  r0,[r4,#0x0]       ; list->n_expr
//! 082d2a80:  cmp  r0,r3
//! 082d2a84:  bgt  0x082d2a64         ; while (n_expr > i) — signed
//! 082d2a88:  ldmia sp!,{r4,r5,pc}
//! ```
//!
//! i.e. `if (list) for (i = 0; i < list->nExpr; i++)
//! exprHeight(list->a[i].pExpr, height);`. The loop guard is a signed
//! `bgt`, so a zero or negative `n_expr` folds nothing, and the fold
//! itself inherits `exprHeight`'s signed-maximum semantics (a NULL
//! `p_expr` item contributes nothing, a negative cached height never
//! lowers the accumulator).
//!
//! Register usage: r0 = list, r1 = height accumulator pointer;
//! r4 = list, r5 = height, r3 = i.
//!
//! Deviations:
//! - The list and its items are read through typed [`ExprList`] /
//!   [`ExprListItem`] structs rather than raw byte offsets, so the code
//!   is layout-correct on the 64-bit test host; on the 32-bit target
//!   the field offsets (+0x00/+0x0c, +0x00) and the 12-byte item stride
//!   are statically asserted (`_EXPR_LIST_*`).
//! - The per-item fold calls the ported
//!   [`crate::sqlite::expr_height_of::expr_height_of`] directly, the
//!   same direct `bl 0x082d2a34` the original makes.

use super::expr_height_of::expr_height_of;

/// An expression list (`sqlite3ExprList`), only the fields this fold
/// touches.
#[repr(C)]
pub struct ExprList {
    /// +0x00: number of entries in the item array (signed — the loop
    /// guard is `bgt`).
    pub n_expr: i32,
    /// +0x04..+0x0c: allocation bookkeeping — unmodeled.
    pub _gap_04: [u8; 0x0c - 0x04],
    /// +0x0c: the item array, `n_expr` entries of 12 bytes each.
    pub items: *mut ExprListItem,
}

/// One expression-list entry (`ExprList_item`), 12 bytes in the
/// original.
#[repr(C)]
pub struct ExprListItem {
    /// +0x00: the expression (`Expr *`, may be NULL).
    pub p_expr: *mut u8,
    /// +0x04..+0x0c: the item's alias token span — unmodeled.
    pub _gap_04: [u8; 0x0c - 0x04],
}

// The original's byte offsets and item stride, asserted on the 32-bit
// target. On a 64-bit host the pointer fields widen and these shift —
// harmless, because all access goes through the typed structs.
#[cfg(target_pointer_width = "32")]
const _EXPR_LIST_N_EXPR_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(ExprList, n_expr)];
#[cfg(target_pointer_width = "32")]
const _EXPR_LIST_ITEMS_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(ExprList, items)];
#[cfg(target_pointer_width = "32")]
const _EXPR_LIST_ITEM_P_EXPR_OFFSET: [u8; 0x00] = [0; core::mem::offset_of!(ExprListItem, p_expr)];
#[cfg(target_pointer_width = "32")]
const _EXPR_LIST_ITEM_STRIDE: [u8; 0x0c] = [0; core::mem::size_of::<ExprListItem>()];

/// expr_list_height — original: `FUN_082d2a4c` @ 0x082d2a4c (64 bytes).
///
/// `heightOfExprList`: if `list` is non-NULL, fold every item's
/// expression height into `*height` through [`expr_height_of`]
/// (`sqlite/expr_height_of.rs`), keeping the running signed maximum. A
/// NULL list, a NULL `items` array with no entries, or a zero/negative
/// `n_expr` leaves the accumulator untouched.
///
/// Takes the list as `*mut u8` (casting to [`ExprList`] internally) so
/// it drops straight into the `HeightFoldFn` shape of the
/// `SQLITE_EXPR_LIST_HEIGHT_FOLD` dispatch slot in
/// `sqlite/expr_height.rs`, where it is the default.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_list_height(list: *mut u8, height: *mut i32) {
    if !list.is_null() {
        let list = list as *const ExprList;
        let mut i: i32 = 0;
        // Original: pre-tested loop, signed `bgt` guard.
        while (*list).n_expr > i {
            let item = (*list).items.add(i as usize);
            expr_height_of((*item).p_expr, height);
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use super::super::expr_height::Expr;
    use std::vec::Vec;

    /// An item whose expression pointer is set; the gap bytes carry a
    /// 0xa5 canary for the "list is only read" test.
    fn item(expr: *mut u8) -> ExprListItem {
        ExprListItem { p_expr: expr, _gap_04: [0xa5; 0x0c - 0x04] }
    }

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

    /// A list header over `items`; the gap bytes carry a 0xa5 canary.
    fn list_header(n_expr: i32, items: *mut ExprListItem) -> ExprList {
        ExprList { n_expr, _gap_04: [0xa5; 0x0c - 0x04], items }
    }

    #[test]
    fn a_null_list_folds_nothing() {
        let mut height: i32 = 0;
        unsafe {
            expr_list_height(core::ptr::null_mut(), &mut height);
        }
        assert_eq!(height, 0, "NULL folds as 0 into the 0 seed");

        let mut height: i32 = -7;
        unsafe {
            expr_list_height(core::ptr::null_mut(), &mut height);
        }
        assert_eq!(height, -7, "movs/ldmiaeq: NULL never touches the accumulator");

        let mut height: i32 = 42;
        unsafe {
            expr_list_height(core::ptr::null_mut(), &mut height);
        }
        assert_eq!(height, 42, "movs/ldmiaeq: NULL never touches the accumulator");
    }

    #[test]
    fn an_empty_or_negative_list_folds_nothing() {
        // n_expr = 0 with a valid items pointer: the pre-tested loop
        // body never runs.
        let mut items = std::vec![item(core::ptr::null_mut())];
        let mut list = list_header(0, items.as_mut_ptr());
        let mut height: i32 = 5;
        unsafe {
            expr_list_height(&mut list as *mut ExprList as *mut u8, &mut height);
        }
        assert_eq!(height, 5, "bgt: 0 > 0 is false, body skipped");

        // n_expr = 0 with a NULL items pointer: the array is never
        // dereferenced.
        let mut list = list_header(0, core::ptr::null_mut());
        let mut height: i32 = 5;
        unsafe {
            expr_list_height(&mut list as *mut ExprList as *mut u8, &mut height);
        }
        assert_eq!(height, 5, "an empty list never reads its items pointer");

        // A negative n_expr is not greater than i = 0 either.
        let mut list = list_header(-3, core::ptr::null_mut());
        let mut height: i32 = 5;
        unsafe {
            expr_list_height(&mut list as *mut ExprList as *mut u8, &mut height);
        }
        assert_eq!(height, 5, "signed bgt: -3 > 0 is false");
    }

    #[test]
    fn a_single_item_folds_through_expr_height_of() {
        let mut child = child_node(9);
        let mut items = std::vec![item(&mut child as *mut Expr as *mut u8)];
        let mut list = list_header(1, items.as_mut_ptr());

        let mut height: i32 = 3;
        unsafe {
            expr_list_height(&mut list as *mut ExprList as *mut u8, &mut height);
        }
        assert_eq!(height, 9, "a taller item raises the accumulator");

        let mut height: i32 = 12;
        unsafe {
            expr_list_height(&mut list as *mut ExprList as *mut u8, &mut height);
        }
        assert_eq!(height, 12, "a shorter item never lowers the accumulator");
    }

    #[test]
    fn a_multi_item_list_folds_the_signed_maximum_in_order() {
        let mut a = child_node(3);
        let mut b = child_node(7);
        let mut c = child_node(2);
        let mut items = std::vec![
            item(&mut a as *mut Expr as *mut u8),
            item(&mut b as *mut Expr as *mut u8),
            item(&mut c as *mut Expr as *mut u8),
        ];
        let mut list = list_header(3, items.as_mut_ptr());
        let mut height: i32 = 0;
        unsafe {
            expr_list_height(&mut list as *mut ExprList as *mut u8, &mut height);
        }
        assert_eq!(height, 7, "max(3, 7, 2)");

        // NULL items fold nothing mid-list; negative heights neither.
        let mut d = child_node(-4);
        let mut items = std::vec![
            item(&mut d as *mut Expr as *mut u8),
            item(core::ptr::null_mut()),
            item(&mut a as *mut Expr as *mut u8),
        ];
        let mut list = list_header(3, items.as_mut_ptr());
        let mut height: i32 = 0;
        unsafe {
            expr_list_height(&mut list as *mut ExprList as *mut u8, &mut height);
        }
        assert_eq!(height, 3, "max(-4, NULL, 3): signed, NULL-safe");
    }

    #[test]
    fn items_are_read_at_the_twelve_byte_stride() {
        // The second item must be found one whole ExprListItem past the
        // first, not at a packed pointer stride: interleave two real
        // items with a poisoned slot by building the array as raw
        // triples and only counting the first two.
        let mut low = child_node(1);
        let mut high = child_node(11);
        let mut poison = child_node(i32::MAX);
        let mut items: Vec<ExprListItem> = std::vec![
            item(&mut low as *mut Expr as *mut u8),
            item(&mut high as *mut Expr as *mut u8),
            item(&mut poison as *mut Expr as *mut u8),
        ];
        // n_expr = 2: the poisoned third slot is never read. If the
        // port walked with a wrong stride it would land in the gap
        // bytes (0xa5a5a5a5 as a pointer) and crash.
        let mut list = list_header(2, items.as_mut_ptr());
        let mut height: i32 = 0;
        unsafe {
            expr_list_height(&mut list as *mut ExprList as *mut u8, &mut height);
        }
        assert_eq!(height, 11, "item[i].p_expr at stride 12, n_expr items only");
    }

    #[test]
    fn the_list_and_items_are_only_read() {
        let mut child = child_node(6);
        let mut items = std::vec![item(&mut child as *mut Expr as *mut u8)];
        let items_ptr = items.as_mut_ptr();
        let mut list = list_header(1, items_ptr);
        let mut height: i32 = 0;
        unsafe {
            expr_list_height(&mut list as *mut ExprList as *mut u8, &mut height);
        }
        assert_eq!(height, 6);
        assert_eq!(list.n_expr, 1, "n_expr is read, not written");
        assert!(list._gap_04.iter().all(|b| *b == 0xa5), "header gap clobbered");
        assert_eq!(list.items, items_ptr, "items pointer is read, not written");
        assert!(items[0]._gap_04.iter().all(|b| *b == 0xa5), "item gap clobbered");
        assert_eq!(items[0].p_expr, &mut child as *mut Expr as *mut u8);
        assert_eq!(child.n_height, 6, "the child's height word is read, not written");
    }
}
