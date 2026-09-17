//! Resolve the collation used by a binary expression comparison.
//!
//! `binary_compare_coll_seq` — original: `FUN_08370298` @ `0x08370298`
//! (80 bytes, `0x08370298..0x083702e7`; the following `stmdb` at
//! `0x083702e8` starts the next function). Raw ARM words contain one plain
//! outbound `bl` (`0x083702cc`) and no predicated `bl`; four plain inbound
//! `bl` call sites were independently identified. SQLite 3.5.9's
//! `sqlite3BinaryCompareCollSeq`: an explicitly collated left expression
//! wins, then an explicitly collated right expression; otherwise resolve the
//! left expression and tail-call `sqlite3ExprCollSeq` for the right only when
//! the left resolution returns NULL.
//!
//! Deliberate deviation: the ABI-visible parse argument is an opaque pointer
//! so callers with a narrower typed Parse prefix retain their target layout;
//! it is cast only at the existing `expr_coll_seq` boundary.


use super::error_msg::Parse;
use super::expr_affinity::Expr;
use super::expr_coll_seq::{expr_coll_seq, CollSeq};

const EP_EXPLICIT_COLLATE: u16 = 0x0100;

/// `sqlite3BinaryCompareCollSeq`: select the explicit collation, if any, or
/// resolve the left expression before the right.
///
/// # Safety
/// `parse`, `left`, and a non-NULL `right` must be valid target-layout SQLite
/// objects. Their collation pointers must be valid when `EP_ExpCollate` is set.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn binary_compare_coll_seq(
    parse: *mut u8,
    left: *mut Expr,
    right: *mut Expr,
) -> *mut CollSeq {
    if (*left).flags & EP_EXPLICIT_COLLATE != 0 {
        return (*left).collating_sequence.cast();
    }
    if !right.is_null() && (*right).flags & EP_EXPLICIT_COLLATE != 0 {
        return (*right).collating_sequence.cast();
    }

    let coll = expr_coll_seq(parse.cast::<Parse>(), left);
    if !coll.is_null() {
        return coll;
    }
    expr_coll_seq(parse.cast::<Parse>(), right)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;

    unsafe fn expr(flags: u16, coll: *mut CollSeq) -> Expr {
        let mut expr: Expr = core::mem::zeroed();
        expr.flags = flags;
        expr.collating_sequence = coll.cast();
        expr
    }

    #[test]
    fn left_explicit_collation_wins_over_right() {
        unsafe {
            let mut left_coll = core::mem::zeroed::<CollSeq>();
            let mut right_coll = core::mem::zeroed::<CollSeq>();
            let mut left = expr(EP_EXPLICIT_COLLATE, &mut left_coll);
            let mut right = expr(EP_EXPLICIT_COLLATE, &mut right_coll);
            assert_eq!(binary_compare_coll_seq(ptr::null_mut(), &mut left, &mut right) as usize, &mut left_coll as *mut CollSeq as usize);
        }
    }

    #[test]
    fn right_explicit_collation_is_used_when_left_is_not_explicit() {
        unsafe {
            let mut right_coll = core::mem::zeroed::<CollSeq>();
            let mut left = expr(0, ptr::null_mut());
            let mut right = expr(EP_EXPLICIT_COLLATE, &mut right_coll);
            assert_eq!(binary_compare_coll_seq(ptr::null_mut(), &mut left, &mut right) as usize, &mut right_coll as *mut CollSeq as usize);
        }
    }

    #[test]
    fn no_collation_returns_null_without_a_helper_call() {
        unsafe {
            let mut left = expr(0, ptr::null_mut());
            let mut right = expr(0, ptr::null_mut());
            assert!(binary_compare_coll_seq(ptr::null_mut(), &mut left, &mut right).is_null());
        }
    }
}
