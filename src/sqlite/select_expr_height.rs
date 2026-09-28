//! Return a SELECT statement's maximum cached expression height.
//!
//! - `select_expr_height` — original: `FUN_08383dd0` @ `0x08383dd0`
//!   (28 bytes; one unconditional `bl`, zero predicated `bl`s).
//!
//! Algorithm: initialize a stack-local signed height accumulator to zero,
//! call SQLite 3.5.x's `heightOfSelect`, then return the accumulator. The
//! direct callee is `select_height` @ `0x082d2a8c`; raw ARM is
//! `mov r1,#0; push {r3,lr}; str r1,[sp]; mov r1,sp; bl; ldr r0,[sp];
//! pop {r3,pc}`.
//!
//! Deliberate deviations: the local is an `i32` rather than a manually
//! addressed stack word, and the Rust symbol uses snake_case. Both preserve
//! the original zero seed and signed fold semantics.

use super::select_height::select_height;

/// `sqlite3SelectExprHeight` — original: `FUN_08383dd0` @ `0x08383dd0`
/// (28 bytes; one unconditional `bl`, zero predicated `bl`s).
///
/// Starts a zeroed height accumulator, folds `select` and its `p_prior`
/// chain through [`select_height`], and returns the resulting maximum.
/// A NULL select returns zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn select_expr_height(select: *mut u8) -> i32 {
    let mut height = 0;
    select_height(select, &mut height);
    height
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use super::super::expr_height::Expr;
    use super::super::select_height::Select;

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

    fn child(height: i32) -> Expr {
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
    fn null_select_returns_the_zero_seed() {
        assert_eq!(unsafe { select_expr_height(core::ptr::null_mut()) }, 0);
    }

    #[test]
    fn returns_maximum_over_the_compound_select_chain() {
        let mut current_expr = child(4);
        let mut prior_expr = child(13);
        let mut prior = bare_select();
        prior.p_where = &mut prior_expr as *mut Expr as *mut u8;
        let mut select = bare_select();
        select.p_where = &mut current_expr as *mut Expr as *mut u8;
        select.p_prior = &mut prior;

        assert_eq!(unsafe { select_expr_height(&mut select as *mut Select as *mut u8) }, 13);
        assert_eq!(current_expr.n_height, 4, "the fold only reads child heights");
        assert_eq!(prior_expr.n_height, 13, "the prior fold only reads child heights");
    }
}
