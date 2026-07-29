//! Folding one expression node's cached height into a running maximum —
//! the per-operand helper `expr_set_height` runs on each child slot.
//!
//! - `expr_height_of` — original: `FUN_082d2a34` @ 0x082d2a34 (24
//!   bytes, leaf; called from `expr_set_height` @ 0x083788fc twice,
//!   `heightOfExprList` @ 0x082d2a4c once and `heightOfSelect` @
//!   0x082d2a8c four times). SQLite 3.5.x's `exprHeight`.
//!
//! Algorithm: a NULL-safe signed maximum fold of the child node's
//! cached height word (`Expr::n_height` at +0x40) into the caller's
//! accumulator. Six instructions, no prologue:
//!
//! ```text
//! 082d2a34:  cmp   r0,#0x0        ; child == NULL?
//! 082d2a38:  ldrne r0,[r0,#0x40]  ; r0 = child->n_height
//! 082d2a3c:  ldrne r2,[r1,#0x0]   ; r2 = *height
//! 082d2a40:  cmpne r0,r2
//! 082d2a44:  strgt r0,[r1,#0x0]   ; if (n_height > *height) *height = n_height
//! 082d2a48:  bx    lr
//! ```
//!
//! i.e. `if (child && child->nHeight > *height) *height = child->nHeight;`.
//! The store is gated on `strgt`, a *signed* greater-than, so a child
//! whose cached height is negative can never lower the accumulator, and
//! a NULL child folds as 0 (contributes nothing).
//!
//! Register usage: r0 = child, r1 = height accumulator pointer.
//!
//! Deviations:
//! - The child is read through the typed [`Expr`] struct (shared with
//!   `sqlite/expr_height.rs`) rather than a raw +0x40 byte offset, so
//!   the code is layout-correct on the 64-bit test host; on the 32-bit
//!   target the field offset is statically asserted to +0x40 there.

use super::expr_height::Expr;

/// expr_height_of — original: `FUN_082d2a34` @ 0x082d2a34 (24 bytes,
/// leaf).
///
/// `exprHeight`: if `child` is non-NULL and its cached `n_height`
/// (+0x40) beats `*height` in a signed comparison, raise `*height` to
/// it. A NULL child or a non-greater height leaves the accumulator
/// untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_height_of(child: *mut u8, height: *mut i32) {
    if !child.is_null() {
        let child_height = (*(child as *const Expr)).n_height;
        if child_height > *height {
            *height = child_height;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// A child node with the given cached height; all pointers NULL,
    /// gap bytes carry a 0xa5 canary for the "child is only read"
    /// test.
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

    #[test]
    fn a_null_child_folds_nothing() {
        let mut height: i32 = 0;
        unsafe {
            expr_height_of(core::ptr::null_mut(), &mut height);
        }
        assert_eq!(height, 0, "NULL folds as 0 into the 0 seed");

        let mut height: i32 = -7;
        unsafe {
            expr_height_of(core::ptr::null_mut(), &mut height);
        }
        assert_eq!(height, -7, "NULL never touches the accumulator");

        let mut height: i32 = 42;
        unsafe {
            expr_height_of(core::ptr::null_mut(), &mut height);
        }
        assert_eq!(height, 42, "NULL never touches the accumulator");
    }

    #[test]
    fn a_taller_child_raises_the_accumulator() {
        let mut child = child_node(9);
        let mut height: i32 = 3;
        unsafe {
            expr_height_of(&mut child as *mut Expr as *mut u8, &mut height);
        }
        assert_eq!(height, 9);
    }

    #[test]
    fn a_shorter_or_equal_child_does_not_lower_the_accumulator() {
        let mut child = child_node(2);
        let mut height: i32 = 9;
        unsafe {
            expr_height_of(&mut child as *mut Expr as *mut u8, &mut height);
        }
        assert_eq!(height, 9, "strgt: 2 is not greater than 9");

        let mut child = child_node(9);
        let mut height: i32 = 9;
        unsafe {
            expr_height_of(&mut child as *mut Expr as *mut u8, &mut height);
        }
        assert_eq!(height, 9, "strgt: equal is not greater");
    }

    #[test]
    fn the_comparison_is_signed() {
        // A negative child height still wins against a more negative
        // accumulator.
        let mut child = child_node(-5);
        let mut height: i32 = -10;
        unsafe {
            expr_height_of(&mut child as *mut Expr as *mut u8, &mut height);
        }
        assert_eq!(height, -5, "-5 > -10 signed");

        // ...but never against the 0 seed expr_set_height uses.
        let mut child = child_node(-5);
        let mut height: i32 = 0;
        unsafe {
            expr_height_of(&mut child as *mut Expr as *mut u8, &mut height);
        }
        assert_eq!(height, 0, "strgt: -5 is not greater than 0");

        // The sign bit is decisive: i32::MIN as a cached height is not
        // "larger than 0x7fffffff" — unsigned it would be.
        let mut child = child_node(i32::MIN);
        let mut height: i32 = i32::MAX;
        unsafe {
            expr_height_of(&mut child as *mut Expr as *mut u8, &mut height);
        }
        assert_eq!(height, i32::MAX, "0x80000000 < 0x7fffffff signed");

        // The largest representable height raises any other accumulator.
        let mut child = child_node(i32::MAX);
        let mut height: i32 = i32::MAX - 1;
        unsafe {
            expr_height_of(&mut child as *mut Expr as *mut u8, &mut height);
        }
        assert_eq!(height, i32::MAX);
    }

    #[test]
    fn the_child_is_only_read() {
        let mut child = child_node(9);
        let mut height: i32 = 0;
        unsafe {
            expr_height_of(&mut child as *mut Expr as *mut u8, &mut height);
        }
        assert_eq!(height, 9);
        assert_eq!(child.n_height, 9, "the height word is read, not written");
        assert!(child._gap_00.iter().all(|b| *b == 0xa5), "op/flags clobbered");
        assert!(child._gap_14.iter().all(|b| *b == 0xa5), "token span clobbered");
        assert!(child._gap_3c.iter().all(|b| *b == 0xa5), "gap clobbered");
        assert!(child.p_left.is_null() && child.p_right.is_null());
        assert!(child.p_list.is_null() && child.p_select.is_null());
    }
}
