//! Emit a comparison opcode for two expression registers.
//!
//! `expr_code_compare` — original: `FUN_082c3bf0` @ `0x082c3bf0` (168
//! bytes, `0x082c3bf0..0x082c3bf97`; the next independent entry is
//! `0x082c3bf98`). Raw ARM decoding finds six direct, unconditional outbound
//! `bl` instructions and no predicated `bl`; the function has five direct
//! inbound `bl` call sites, all unconditional. SQLite 3.5.9's
//! `sqlite3ExprCodeCompare`: resolve the left expression's collation,
//! combine the two expression affinities, emit the requested comparison with
//! `P4_COLLSEQ`, set P5 to that affinity plus `jump_if_null`, and invalidate
//! both one-register affinity-cache entries when the affinity mask is nonzero.
//!
//! `sqlite3CompareAffinity` at `0x083735b8` and
//! `sqlite3BinaryCompareCollSeq` at `0x08370298` are ported and called
//! directly.

use super::binary_compare_coll_seq::binary_compare_coll_seq;
use super::expr_affinity::{expr_affinity, Expr};
use super::expr_cache_affinity_change::expr_cache_affinity_change;
use super::expr_compare_affinity::expr_compare_affinity;
use super::vdbe::{vdbe_add_op4, vdbe_change_p5, Vdbe};

/// The target-layout prefix of `Parse` used by this helper.
#[repr(C)]
pub struct CodeCompareParse {
    pub db: *mut u8,
    pub _gap_04: [u8; 8],
    pub p_vdbe: *mut Vdbe,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(CodeCompareParse, p_vdbe) == 0x0c);
};


/// `sqlite3ExprCodeCompare`: emit `opcode(left_reg, right_reg, destination)`.
///
/// # Safety
/// `parse`, `left`, and `right` must name valid SQLite objects. `parse.p_vdbe`
/// must be a valid VDBE with capacity for one additional instruction.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_code_compare(
    parse: *mut CodeCompareParse,
    left: *mut Expr,
    right: *mut Expr,
    opcode: i32,
    left_reg: i32,
    right_reg: i32,
    destination: i32,
    jump_if_null: u8,
) -> i32 {
    let coll_seq = binary_compare_coll_seq(parse.cast(), left, right).cast();
    let affinity = expr_compare_affinity(left, expr_affinity(right));
    let flags = affinity | jump_if_null;
    let addr = vdbe_add_op4((*parse).p_vdbe, opcode, left_reg, right_reg, destination, coll_seq, -4);
    vdbe_change_p5((*parse).p_vdbe, flags);
    if flags & 0x67 != 0 {
        expr_cache_affinity_change(parse.cast(), left_reg, 1);
        expr_cache_affinity_change(parse.cast(), right_reg, 1);
    }
    addr
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use super::*;

    unsafe fn expr(affinity: u8) -> Expr {
        let mut expr: Expr = core::mem::zeroed();
        expr.affinity = affinity;
        expr
    }

    #[test]
    fn emits_comparison_with_collation_and_jump_flag() {
        unsafe {
            let mut ops = vec![core::mem::zeroed(); 1];
            let mut vdbe: Vdbe = core::mem::zeroed();
            let mut db = [0_u8; 0x20];
            vdbe.db = db.as_mut_ptr();
            vdbe.a_op = ops.as_mut_ptr();
            vdbe.n_op_alloc = 1;
            let mut parse: CodeCompareParse = core::mem::zeroed();
            parse.p_vdbe = &mut vdbe;
            let mut left = expr(0);
            let mut right = expr(0);
            left.flags = 0x100;
            left.collating_sequence = 0x1234usize as *mut u8;
            let address = expr_code_compare(&mut parse, &mut left, &mut right, 77, 4, 9, 12, 8);
            assert_eq!(address, 0);
            assert_eq!((ops[0].opcode, ops[0].p1, ops[0].p2, ops[0].p3, ops[0].p4, ops[0].p4type, ops[0].p5),
                (77, 4, 9, 12, 0x1234usize as *mut u8, -4, 0x6a));
        }
    }

    #[test]
    fn combines_no_affinity_with_the_null_jump_flag() {
        unsafe {
            let mut ops = vec![core::mem::zeroed(); 1];
            let mut vdbe: Vdbe = core::mem::zeroed();
            let mut db = [0_u8; 0x20];
            vdbe.db = db.as_mut_ptr();
            vdbe.a_op = ops.as_mut_ptr();
            vdbe.n_op_alloc = 1;
            let mut parse: CodeCompareParse = core::mem::zeroed();
            parse.p_vdbe = &mut vdbe;
            let mut left = expr(0);
            let mut right = expr(0);
            left.flags = 0x100;
            left.collating_sequence = 0x2468usize as *mut u8;
            expr_code_compare(&mut parse, &mut left, &mut right, 5, -1, 3, 2, 0x80);
            assert_eq!(ops[0].p5, 0xe2);
        }
    }
}
