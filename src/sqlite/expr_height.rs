//! Recomputing the cached height of an expression tree — the fix-up
//! SQLite's expression constructor runs on every new node.
//!
//! - `expr_set_height` — original: `FUN_083788fc` @ 0x083788fc (80
//!   bytes; 7 `bl` call sites, binary-scanned). SQLite 3.5.x's
//!   `sqlite3ExprSetHeight`.
//!
//! Algorithm: seed a running signed maximum at 0, fold the cached
//! subtree heights of the node's four child slots into it through
//! three tiny static helpers, then store max + 1 into the node's own
//! height word:
//!
//! ```text
//! 083788fc:  stmdb sp!,{r3,r4,r5,lr}  ; r3 spill = the accumulator
//! 08378904:  mov  r4,r0               ; r4 = expr
//! 08378908:  str  r0,[sp,#0x0]        ; height = 0
//! 0837890c:  ldr  r0,[r4,#0x8]        ; expr->p_left
//! 08378914:  bl   0x082d2a34          ; exprHeight(child, &height)
//! 08378918:  ldr  r0,[r4,#0xc]        ; expr->p_right
//! 08378920:  bl   0x082d2a34          ; exprHeight(child, &height)
//! 08378924:  ldr  r0,[r4,#0x10]       ; expr->p_list
//! 0837892c:  bl   0x082d2a4c          ; heightOfExprList(list, &height)
//! 08378930:  ldr  r0,[r4,#0x38]       ; expr->p_select
//! 08378938:  bl   0x082d2a8c          ; heightOfSelect(select, &height)
//! 0837893c:  ldr  r0,[sp,#0x0]
//! 08378940:  add  r0,r0,#0x1          ; plain add — wraps
//! 08378944:  str  r0,[r4,#0x40]       ; expr->n_height = height + 1
//! ```
//!
//! The three fold helpers (all confirmed against the SQLite 3.5.x
//! sources):
//!
//! - `exprHeight` @ 0x082d2a34 (24 bytes), a leaf — **ported** as
//!   [`crate::sqlite::expr_height_of::expr_height_of`] and wired as the
//!   default of [`SQLITE_EXPR_HEIGHT_FOLD`]:
//!   `if (child && child->nHeight > *height) *height = child->nHeight;`
//!   — a signed `strgt` maximum fold.
//! - `heightOfExprList` @ 0x082d2a4c (64 bytes): walks the list's
//!   `nExpr` items (+0x00), a 12-byte-stride array at +0x0c whose first
//!   word is the `Expr *`, folding each through `exprHeight` — **ported**
//!   as [`crate::sqlite::expr_list_height::expr_list_height`] and wired
//!   as the default of [`SQLITE_EXPR_LIST_HEIGHT_FOLD`].
//! - `heightOfSelect` @ 0x082d2a8c (112 bytes): folds p_where (+0x10),
//!   p_having (+0x18), p_limit (+0x2c) and p_offset (+0x30) through
//!   `exprHeight`, p_elist (+0x00), p_group_by (+0x14) and p_order_by
//!   (+0x1c) through `heightOfExprList`, then loops onto p_prior
//!   (+0x20) — the recursion over compound-select chains is a tail
//!   loop in the original.
//!
//! `Expr` fields used (all pinned by this function's `ldr/str [r4,
//! #off]` sequence and cross-checked against the SQLite 3.5.x sources;
//! the node is the 0x44-byte allocation made by `sqlite3Expr` @
//! 0x08376808 — see `sqlite/parse_expr.rs`):
//!
//! ```text
//! +0x00 op        (u8)       opcode (TK_*)
//! +0x08 p_left    (*mut u8)  left operand
//! +0x0c p_right   (*mut u8)  right operand
//! +0x10 p_list    (*mut u8)  function arguments / IN list (ExprList *)
//! +0x14..+0x24             token span words
//! +0x38 p_select  (*mut u8)  sub-select (Select *)
//! +0x40 n_height  (i32)      cached tree height, rewritten here
//! ```
//!
//! Deviations:
//! - One of the three fold helpers remains unported, so it is a
//!   dispatch boundary (house pattern — see `sqlite/error_msg.rs`):
//!   [`SQLITE_SELECT_HEIGHT_FOLD`]. Its default slot is a documented
//!   no-op stub — which is *exactly* the behavior the original has for
//!   a NULL child pointer (the `cmp r0,#0` guard), so with no helper
//!   wired that fold never moves the accumulator.
//!   [`SQLITE_EXPR_HEIGHT_FOLD`] and [`SQLITE_EXPR_LIST_HEIGHT_FOLD`]
//!   keep the same dispatch-slot shape (host tests swap them for
//!   recording mocks), but their defaults are now the real ports,
//!   [`crate::sqlite::expr_height_of::expr_height_of`] and
//!   [`crate::sqlite::expr_list_height::expr_list_height`].
//!   The match.py diff is exactly this deviation: indirect calls
//!   through the loaded slots instead of direct `bl`s.
//! - `Expr` is a typed `#[repr(C)]` struct rather than raw byte
//!   offsets, so the pointer fields stay disjoint on a 64-bit test
//!   host. The original byte offsets are statically asserted on 32-bit
//!   targets (`_EXPR_*_OFFSET`).

use super::expr_height_of::expr_height_of;
use super::expr_list_height::expr_list_height;

/// An expression node (`sqlite3Expr`), only the fields this fix-up
/// touches. The full layout is documented in the module header.
#[repr(C)]
pub struct Expr {
    /// +0x00..+0x08: the op byte (+0x00), flags/affinity — unmodeled.
    pub _gap_00: [u8; 0x08],
    /// +0x08: left operand (`Expr *`, may be NULL).
    pub p_left: *mut u8,
    /// +0x0c: right operand (`Expr *`, may be NULL).
    pub p_right: *mut u8,
    /// +0x10: argument / IN-expression list (`ExprList *`, may be NULL).
    pub p_list: *mut u8,
    /// +0x14..+0x38: token span words (+0x14/+0x18/+0x1c/+0x20) and the
    /// rest — unmodeled.
    pub _gap_14: [u8; 0x38 - 0x14],
    /// +0x38: sub-select (`Select *`, may be NULL).
    pub p_select: *mut u8,
    /// +0x3c..+0x40: unmodeled.
    pub _gap_3c: [u8; 0x40 - 0x3c],
    /// +0x40: cached height of the tree headed by this node.
    pub n_height: i32,
}

// The original's byte offsets, asserted on the 32-bit target. On a
// 64-bit host the pointer fields widen and these shift — harmless,
// because all access goes through the typed struct.
#[cfg(target_pointer_width = "32")]
const _EXPR_P_LEFT_OFFSET: [u8; 0x08] = [0; core::mem::offset_of!(Expr, p_left)];
#[cfg(target_pointer_width = "32")]
const _EXPR_P_RIGHT_OFFSET: [u8; 0x0c] = [0; core::mem::offset_of!(Expr, p_right)];
#[cfg(target_pointer_width = "32")]
const _EXPR_P_LIST_OFFSET: [u8; 0x10] = [0; core::mem::offset_of!(Expr, p_list)];
#[cfg(target_pointer_width = "32")]
const _EXPR_P_SELECT_OFFSET: [u8; 0x38] = [0; core::mem::offset_of!(Expr, p_select)];
#[cfg(target_pointer_width = "32")]
const _EXPR_N_HEIGHT_OFFSET: [u8; 0x40] = [0; core::mem::offset_of!(Expr, n_height)];

/// A child-height fold: `(child, &mut height)` where the helper raises
/// `*height` to at most the child's cached subtree height (signed
/// comparison), and does nothing for a NULL child. Covers all three
/// original helpers — `exprHeight` @ 0x082d2a34, `heightOfExprList` @
/// 0x082d2a4c and `heightOfSelect` @ 0x082d2a8c share this shape.
pub type HeightFoldFn = unsafe extern "C" fn(child: *mut u8, height: *mut i32);

/// Default stub of the slot whose original is still unported (the
/// operand and list slots now default to [`expr_height_of`] and
/// [`expr_list_height`]): no fold helper wired, so the accumulator
/// never moves — exactly what the original helpers do for a NULL child
/// (see the module header).
pub(crate) unsafe extern "C" fn missing_height_fold(_child: *mut u8, _height: *mut i32) {}

/// The active operand fold (`exprHeight` @ 0x082d2a34). The default is
/// the real port, [`expr_height_of`]; host tests still install
/// recording mocks through the slot.
pub static mut SQLITE_EXPR_HEIGHT_FOLD: HeightFoldFn = expr_height_of;

/// The active expression-list fold (`heightOfExprList` @ 0x082d2a4c).
/// The default is the real port, [`expr_list_height`]; host tests still
/// install recording mocks through the slot.
pub static mut SQLITE_EXPR_LIST_HEIGHT_FOLD: HeightFoldFn = expr_list_height;

/// The active sub-select fold (`heightOfSelect` @ 0x082d2a8c).
pub static mut SQLITE_SELECT_HEIGHT_FOLD: HeightFoldFn = missing_height_fold;

/// Reads a fold slot (volatile — the slots are meant to be swapped at
/// runtime, and a plain read lets LLVM const-fold the default away).
#[inline(always)]
pub(crate) fn height_fold_op(slot: *mut HeightFoldFn) -> HeightFoldFn {
    unsafe { core::ptr::read_volatile(slot) }
}

/// expr_set_height — original: `FUN_083788fc` @ 0x083788fc (80 bytes;
/// 7 `bl` call sites).
///
/// `sqlite3ExprSetHeight`: recompute the cached height of the
/// expression tree headed by `expr` from its children's cached
/// heights. The running maximum is seeded at 0 and folded over
/// `p_left` and `p_right` (via the [`SQLITE_EXPR_HEIGHT_FOLD`] slot),
/// `p_list` (via [`SQLITE_EXPR_LIST_HEIGHT_FOLD`]) and `p_select` (via
/// [`SQLITE_SELECT_HEIGHT_FOLD`]); the node's own `n_height` becomes
/// max + 1. The final add is a plain ARM `add` — it wraps.
///
/// Register usage: r0 = expr; the accumulator lives in the r3 stack
/// spill of the original's prologue.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_set_height(expr: *mut Expr) {
    let expr = &mut *expr;
    let mut height: i32 = 0;
    (height_fold_op(core::ptr::addr_of_mut!(SQLITE_EXPR_HEIGHT_FOLD)))(expr.p_left, &mut height);
    (height_fold_op(core::ptr::addr_of_mut!(SQLITE_EXPR_HEIGHT_FOLD)))(expr.p_right, &mut height);
    (height_fold_op(core::ptr::addr_of_mut!(SQLITE_EXPR_LIST_HEIGHT_FOLD)))(expr.p_list, &mut height);
    (height_fold_op(core::ptr::addr_of_mut!(SQLITE_SELECT_HEIGHT_FOLD)))(expr.p_select, &mut height);
    // Original: `ldr/add/str` — a plain ARM add, it wraps.
    expr.n_height = height.wrapping_add(1);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes access to the three fold slots across tests.
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    /// Which slot a recording fold was invoked through.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Slot {
        Expr,
        List,
        Select,
    }

    /// (slot, child, incoming accumulator) of every fold invocation.
    static mut LOG: Vec<(Slot, *mut u8, i32)> = Vec::new();

    /// Value the folding mocks raise the accumulator to.
    static mut FOLD_VALUE: i32 = 0;

    fn lock() -> MutexGuard<'static, ()> {
        SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The documented default configuration: the real `exprHeight` and
    /// `heightOfExprList` ports on the operand and list slots, the
    /// no-op stub on the slot whose original is still unported.
    unsafe fn restore_defaults() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_HEIGHT_FOLD), expr_height_of);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_LIST_HEIGHT_FOLD), expr_list_height);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_SELECT_HEIGHT_FOLD), missing_height_fold);
    }

    /// Installs the given folds, runs `body`, then restores the
    /// documented defaults so a failed assertion cannot leak mocks
    /// into the next test.
    unsafe fn with_folds(expr: HeightFoldFn, list: HeightFoldFn, select: HeightFoldFn, body: impl FnOnce()) {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_HEIGHT_FOLD), expr);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_LIST_HEIGHT_FOLD), list);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_SELECT_HEIGHT_FOLD), select);
        body();
        restore_defaults();
    }

    /// A faithful port of `exprHeight` @ 0x082d2a34: NULL is a no-op,
    /// otherwise a signed maximum fold of the child's `n_height`.
    unsafe extern "C" fn faithful_expr_fold(child: *mut u8, height: *mut i32) {
        if !child.is_null() {
            let child_height = (*(child as *const Expr)).n_height;
            if child_height > *height {
                *height = child_height;
            }
        }
    }

    /// Records the invocation and folds [`FOLD_VALUE`] in.
    unsafe extern "C" fn recording_expr_fold(child: *mut u8, height: *mut i32) {
        (*core::ptr::addr_of_mut!(LOG)).push((Slot::Expr, child, *height));
        let value = *core::ptr::addr_of!(FOLD_VALUE);
        if value > *height {
            *height = value;
        }
    }

    unsafe extern "C" fn recording_list_fold(child: *mut u8, height: *mut i32) {
        (*core::ptr::addr_of_mut!(LOG)).push((Slot::List, child, *height));
        let value = *core::ptr::addr_of!(FOLD_VALUE);
        if value > *height {
            *height = value;
        }
    }

    unsafe extern "C" fn recording_select_fold(child: *mut u8, height: *mut i32) {
        (*core::ptr::addr_of_mut!(LOG)).push((Slot::Select, child, *height));
        let value = *core::ptr::addr_of!(FOLD_VALUE);
        if value > *height {
            *height = value;
        }
    }

    fn log() -> Vec<(Slot, *mut u8, i32)> {
        unsafe { (*core::ptr::addr_of!(LOG)).clone() }
    }

    /// A node with the given children and a clobberable height word;
    /// the gap bytes carry a canary for the "nothing else written"
    /// test.
    fn node(left: *mut u8, right: *mut u8, list: *mut u8, select: *mut u8, height: i32) -> Expr {
        Expr {
            _gap_00: [0xa5; 0x08],
            p_left: left,
            p_right: right,
            p_list: list,
            _gap_14: [0xa5; 0x38 - 0x14],
            p_select: select,
            _gap_3c: [0xa5; 0x40 - 0x3c],
            n_height: height,
        }
    }

    #[test]
    fn a_leaf_node_gets_height_one() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            let mut expr = node(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                99,
            );
            expr_set_height(&mut expr);
            assert_eq!(expr.n_height, 1, "0 + 1: a childless node is one level tall");
        }
    }

    #[test]
    fn the_taller_operand_wins() {
        let _guard = lock();
        let mut left = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 3);
        let mut right = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 7);
        let mut expr = node(
            &mut left as *mut Expr as *mut u8,
            &mut right as *mut Expr as *mut u8,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
        );
        unsafe {
            with_folds(faithful_expr_fold, missing_height_fold, missing_height_fold, || {
                expr_set_height(&mut expr);
            });
        }
        assert_eq!(expr.n_height, 8, "max(3, 7) + 1");
    }

    #[test]
    fn the_left_operand_can_win_and_a_null_operand_contributes_nothing() {
        let _guard = lock();
        let mut left = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 9);
        let mut right = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 2);
        let mut expr = node(
            &mut left as *mut Expr as *mut u8,
            &mut right as *mut Expr as *mut u8,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
        );
        unsafe {
            with_folds(faithful_expr_fold, missing_height_fold, missing_height_fold, || {
                expr_set_height(&mut expr);
            });
        }
        assert_eq!(expr.n_height, 10, "max(9, 2) + 1");

        let mut only_right = node(
            core::ptr::null_mut(),
            &mut right as *mut Expr as *mut u8,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
        );
        unsafe {
            with_folds(faithful_expr_fold, missing_height_fold, missing_height_fold, || {
                expr_set_height(&mut only_right);
            });
        }
        assert_eq!(only_right.n_height, 3, "NULL left folds nothing: max(-, 2) + 1");
    }

    #[test]
    fn heights_compare_as_signed() {
        let _guard = lock();
        let mut left = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), -1);
        let mut expr = node(
            &mut left as *mut Expr as *mut u8,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
        );
        unsafe {
            with_folds(faithful_expr_fold, missing_height_fold, missing_height_fold, || {
                expr_set_height(&mut expr);
            });
        }
        assert_eq!(expr.n_height, 1, "strgt: -1 is not greater than the 0 seed");
    }

    #[test]
    fn the_list_and_select_slots_participate_in_the_maximum() {
        let _guard = lock();
        unsafe {
            (*core::ptr::addr_of_mut!(FOLD_VALUE)) = 5;
            let mut expr = node(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0x11111111 as *mut u8,
                0x22222222 as *mut u8,
                0,
            );
            with_folds(missing_height_fold, recording_list_fold, missing_height_fold, || {
                expr_set_height(&mut expr);
            });
            assert_eq!(expr.n_height, 6, "the list's 5 beats the operand seed");

            (*core::ptr::addr_of_mut!(FOLD_VALUE)) = 9;
            let mut expr = node(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0x11111111 as *mut u8,
                0x22222222 as *mut u8,
                0,
            );
            with_folds(missing_height_fold, recording_list_fold, recording_select_fold, || {
                expr_set_height(&mut expr);
            });
            assert_eq!(expr.n_height, 10, "the select's 9 beats the list's 9 -> still 9 + 1");
        }
    }

    #[test]
    fn the_accumulator_is_shared_in_order_across_all_four_slots() {
        let _guard = lock();
        unsafe {
            (*core::ptr::addr_of_mut!(LOG)).clear();
            (*core::ptr::addr_of_mut!(FOLD_VALUE)) = 0;
            let mut left = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 3);
            let mut right = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 1);
            let left_ptr = &mut left as *mut Expr as *mut u8;
            let right_ptr = &mut right as *mut Expr as *mut u8;
            let mut expr = node(left_ptr, right_ptr, 0x11111111 as *mut u8, 0x22222222 as *mut u8, 0);

            // The expr slot folds the real children; list/select only record.
            unsafe extern "C" fn folding_expr_fold(child: *mut u8, height: *mut i32) {
                (*core::ptr::addr_of_mut!(LOG)).push((Slot::Expr, child, *height));
                faithful_expr_fold(child, height);
            }
            with_folds(folding_expr_fold, recording_list_fold, recording_select_fold, || {
                expr_set_height(&mut expr);
            });

            assert_eq!(
                log(),
                std::vec![
                    (Slot::Expr, left_ptr, 0),
                    (Slot::Expr, right_ptr, 3),
                    (Slot::List, 0x11111111 as *mut u8, 3),
                    (Slot::Select, 0x22222222 as *mut u8, 3),
                ],
                "left, right, list, select — each sees the running maximum"
            );
            assert_eq!(expr.n_height, 4);
        }
    }

    #[test]
    fn the_plus_one_wraps_like_the_original() {
        let _guard = lock();
        unsafe {
            (*core::ptr::addr_of_mut!(FOLD_VALUE)) = i32::MAX;
            let mut expr = node(
                0x11111111 as *mut u8,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
            );
            with_folds(recording_expr_fold, missing_height_fold, missing_height_fold, || {
                expr_set_height(&mut expr);
            });
            assert_eq!(expr.n_height, i32::MIN, "plain ARM add, no saturation");
        }
    }

    #[test]
    fn only_the_height_word_is_written() {
        let _guard = lock();
        unsafe {
            // All-stub folds: the default operand fold would
            // dereference these bogus child pointers.
            let mut expr = node(
                0x11111111 as *mut u8,
                0x22222222 as *mut u8,
                0x33333333 as *mut u8,
                0x44444444 as *mut u8,
                0,
            );
            with_folds(missing_height_fold, missing_height_fold, missing_height_fold, || {
                expr_set_height(&mut expr);
            });
            assert!(expr._gap_00.iter().all(|b| *b == 0xa5), "op/flags clobbered");
            assert!(expr._gap_14.iter().all(|b| *b == 0xa5), "token span clobbered");
            assert!(expr._gap_3c.iter().all(|b| *b == 0xa5), "gap clobbered");
            assert_eq!(expr.p_left, 0x11111111 as *mut u8, "operands only read");
            assert_eq!(expr.p_right, 0x22222222 as *mut u8);
            assert_eq!(expr.p_list, 0x33333333 as *mut u8);
            assert_eq!(expr.p_select, 0x44444444 as *mut u8);
        }
    }

    #[test]
    fn the_default_stubs_behave_like_null_children() {
        let _guard = lock();
        unsafe {
            let mut height: i32 = 41;
            missing_height_fold(0x11111111 as *mut u8, &mut height);
            assert_eq!(height, 41, "the no-op stub never moves the accumulator");

            // All-stub folds (the default operand fold would
            // dereference these bogus child pointers): every child
            // folds nothing, so the node reports the leaf answer.
            let mut expr = node(
                0x11111111 as *mut u8,
                0x22222222 as *mut u8,
                0x33333333 as *mut u8,
                0x44444444 as *mut u8,
                0,
            );
            with_folds(missing_height_fold, missing_height_fold, missing_height_fold, || {
                expr_set_height(&mut expr);
            });
            assert_eq!(expr.n_height, 1, "no folds wired: the leaf answer");
        }
    }

    #[test]
    fn the_default_operand_fold_is_the_real_port() {
        let _guard = lock();
        unsafe {
            restore_defaults();
            let mut left = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 3);
            let mut right = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 7);
            let mut expr = node(
                &mut left as *mut Expr as *mut u8,
                &mut right as *mut Expr as *mut u8,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
            );
            expr_set_height(&mut expr);
            assert_eq!(
                expr.n_height, 8,
                "out of the box the operand slot folds real child heights: max(3, 7) + 1"
            );
        }
    }

    #[test]
    fn the_default_list_fold_is_the_real_port() {
        use super::super::expr_list_height::{ExprList, ExprListItem};
        let _guard = lock();
        unsafe {
            restore_defaults();
            let mut a = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 2);
            let mut b = node(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), 6);
            let mut items = std::vec![
                ExprListItem { p_expr: &mut a as *mut Expr as *mut u8, _gap_04: [0xa5; 0x0c - 0x04] },
                ExprListItem { p_expr: &mut b as *mut Expr as *mut u8, _gap_04: [0xa5; 0x0c - 0x04] },
            ];
            let mut list = ExprList { n_expr: 2, _gap_04: [0xa5; 0x0c - 0x04], items: items.as_mut_ptr() };
            let mut expr = node(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut list as *mut ExprList as *mut u8,
                core::ptr::null_mut(),
                0,
            );
            expr_set_height(&mut expr);
            assert_eq!(
                expr.n_height, 7,
                "out of the box the list slot folds real item heights: max(2, 6) + 1"
            );
        }
    }
}
