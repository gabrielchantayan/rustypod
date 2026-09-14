//! SQLite expression conjunction builder.
//!
//! RetailOS `FUN_08376958` at load address `0x08376958`, 60 bytes
//! (`0x08376958..0x08376994`). Raw `osos.dec` words establish the extent:
//! the function starts with `mov ip,r0` and ends with `ldmia sp!,{ip,pc}` at
//! `0x08376990`; the separately linked next function starts at `0x08376994`.
//! Decoding every aligned ARM immediate B/BL word in `osos.dec` finds exactly
//! five direct inbound calls, all unconditional `bl` at `0x082b2e88`,
//! `0x082ce9a0`, `0x082ce9dc`, `0x0836e4b0`, and `0x08391b38`; there are no
//! predicated direct calls or direct tail-B callers.
//!
//! This is SQLite 3.5's `sqlite3ExprAnd`: return whichever child is present
//! when the other is NULL; otherwise construct a `TK_AND` (61 / `0x3d`)
//! expression by forwarding the connection and both children to `sqlite3Expr`
//! (`expr_new`) with no token. Deliberate deviations: none.

use super::expr_new::expr_new;

/// SQLite's `TK_AND` parser token (retail immediate: `mov r1,#0x3d`).
pub const TK_AND: i32 = 0x3d;

/// `expr_and` — original: `FUN_08376958` @ `0x08376958` (60 bytes; 5 direct
/// inbound `bl` call sites).
///
/// Return `right` if `left` is NULL, return `left` if `right` is NULL, or
/// make a token-less conjunction node when both operands are present.
/// Register usage: `r0 = db`, `r1 = left`, `r2 = right`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_and(
    db: *mut u8,
    left: *mut u8,
    right: *mut u8,
) -> *mut u8 {
    if left.is_null() {
        return right;
    }
    if right.is_null() {
        return left;
    }
    expr_new(db, TK_AND, left, right, core::ptr::null())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::expr_height;
    use crate::sqlite::expr_new::Expr;
    use crate::sqlite::mem::tests::{install_recorder, Connection};

    #[repr(align(16))]
    struct Arena([u8; 0x60]);

    #[test]
    fn one_null_operand_returns_the_other_without_dereferencing_it() {
        let left = 1usize as *mut u8;
        let right = 5usize as *mut u8;

        assert_eq!(unsafe { expr_and(core::ptr::null_mut(), core::ptr::null_mut(), right) }, right);
        assert_eq!(unsafe { expr_and(core::ptr::null_mut(), left, core::ptr::null_mut()) }, left);
        assert!(unsafe { expr_and(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()) }.is_null());
    }

    #[test]
    fn two_operands_become_a_tokenless_and_node() {
        let mut arena = Arena([0xa5; 0x60]);
        // `expr_new` zeroes the retail 0x44-byte allocation. The widened
        // host layout's p_select/n_height tail must begin zeroed as well.
        for byte in &mut arena.0[0x44..] {
            *byte = 0;
        }
        let _allocator = install_recorder(arena.0.as_mut_ptr());
        let mut db = Connection::healthy();
        let mut left: Expr = unsafe { core::mem::zeroed() };
        let mut right: Expr = unsafe { core::mem::zeroed() };

        let raw = unsafe { expr_and(db.ptr(), (&mut left as *mut Expr).cast(), (&mut right as *mut Expr).cast()) };
        assert_eq!(raw, arena.0.as_mut_ptr());

        let node = raw.cast::<Expr>();
        unsafe {
            assert_eq!((*node).op, TK_AND as u8);
            assert_eq!((*node).p_left, (&mut left as *mut Expr).cast());
            assert_eq!((*node).p_right, (&mut right as *mut Expr).cast());
            assert!((*node).token.z.is_null());
            assert_eq!((*node).token.n_dyn, 0);
            assert_eq!((*node).i_agg, -1);
            assert_eq!((raw as *const expr_height::Expr).read().n_height, 1);
        }
    }
}
