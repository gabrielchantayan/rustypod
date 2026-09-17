//! Compile two SQLite expressions with temporary registers.
//!
//! `expr_code_pair` — original: `FUN_082c3c98` @ 0x082c3c98 (116 bytes;
//! 2 unconditional `bl` calls, binary-scanned; no predicated `bl` calls).
//! The next real function starts at 0x082c3d0c.
//!
//! Firmware algorithm (verified against osos.dec 0x082c3c98..0x082c3d0c):
//!
//! ```text
//! for each (expr, out_in_reg, out_temp_reg) triple:
//!     while expr->op == 'V': expr = expr->pLeft
//!     expr->flags |= 0x0200
//!     *out_in_reg = expr_code_temp(parse, expr, out_temp_reg)
//! ```
//! Deliberate deviation: the SQLite source name for this small local helper is
//! not established; `expr_code_pair` names its verified two-expression effect.

const EXPR_OP_OFFSET: usize = 0;
const EXPR_FLAGS_OFFSET: usize = 2;
const EXPR_LEFT_OFFSET: usize = 8;
const TK_VECTOR: u8 = b'V';
const EP_FIXED_DEST: u16 = 0x0200;

unsafe fn unwrap_vector_expr(mut expr: *mut u8) -> *mut u8 {
    while expr.add(EXPR_OP_OFFSET).read() == TK_VECTOR {
        expr = (expr.add(EXPR_LEFT_OFFSET).cast::<u32>().read() as usize) as *mut u8;
    }
    expr
}

/// Compile two expressions after unwrapping vector nodes and mark each final
/// expression as having a fixed destination.
///
/// # Safety
///
/// Each expression must be a target-width SQLite `Expr`: its opcode is at +0,
/// flags at +2, and vector nodes hold a 32-bit left-child pointer at +8.
/// `out_*_temp_reg` and `parse` must meet [`super::expr_code_temp::expr_code_temp`]'s
/// requirements. No pointer receives a NULL guard, matching the firmware.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_code_pair(
    parse: *mut u8,
    first_expr: *mut u8,
    first_out_in_reg: *mut i32,
    first_out_temp_reg: *mut i32,
    second_expr: *mut u8,
    second_out_in_reg: *mut i32,
    second_out_temp_reg: *mut i32,
) {
    let first_expr = unwrap_vector_expr(first_expr);
    let first_flags = first_expr.add(EXPR_FLAGS_OFFSET).cast::<u16>();
    first_flags.write(first_flags.read() | EP_FIXED_DEST);
    first_out_in_reg.write(super::expr_code_temp::expr_code_temp(parse, first_expr, first_out_temp_reg));

    let second_expr = unwrap_vector_expr(second_expr);
    let second_flags = second_expr.add(EXPR_FLAGS_OFFSET).cast::<u16>();
    second_flags.write(second_flags.read() | EP_FIXED_DEST);
    second_out_in_reg.write(super::expr_code_temp::expr_code_temp(parse, second_expr, second_out_temp_reg));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::expr_code::{ExprCodeOps, DEFAULT_EXPR_CODE_OPS, EXPR_CODE_OPS, EXPR_CODE_OPS_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{LazyLock, MutexGuard};
    use std::vec::Vec;

    const SLAB_LEN: usize = 0x1000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SQLITE_EXPR_CODE_PAIR, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static mut CALLS: Vec<(*mut u8, i32)> = Vec::new();

    unsafe extern "C" fn record_expr(_parse: *mut u8, expr: *mut u8, target: i32) -> i32 {
        (*addr_of_mut!(CALLS)).push((expr, target));
        target
    }

    struct ResetExprCodeOps;
    impl Drop for ResetExprCodeOps {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(addr_of_mut!(EXPR_CODE_OPS), DEFAULT_EXPR_CODE_OPS) };
        }
    }

    fn install() -> (MutexGuard<'static, ()>, ResetExprCodeOps) {
        let guard = EXPR_CODE_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            (*addr_of_mut!(CALLS)).clear();
            core::ptr::write_volatile(addr_of_mut!(EXPR_CODE_OPS), ExprCodeOps { expr_code_target: record_expr });
        }
        (guard, ResetExprCodeOps)
    }

    #[repr(align(4))]
    struct Parse([u8; 0x4c]);
    impl Parse {
        fn new() -> Self {
            let mut parse = Parse([0; 0x4c]);
            unsafe { (parse.0.as_mut_ptr().add(super::super::get_temp_reg::N_MEM_OFFSET) as *mut i32).write(10) };
            parse
        }
    }

    #[test]
    fn unwraps_vector_nodes_marks_leaves_and_reports_two_temps() {
        let Some(base) = *SLAB else {
            assert!(note_missing_u32_fixture("sqlite/expr_code_pair"));
            return;
        };
        let (_guard, _reset) = install();
        let base = base as *mut u8;
        unsafe {
            base.write_bytes(0, SLAB_LEN);
            let first_wrapper = base.add(0x00);
            let first_leaf = base.add(0x20);
            let second_leaf = base.add(0x40);
            first_wrapper.write(TK_VECTOR);
            first_wrapper.add(EXPR_LEFT_OFFSET).cast::<u32>().write(first_leaf as usize as u32);
            first_leaf.add(EXPR_FLAGS_OFFSET).cast::<u16>().write(0x0040);
            second_leaf.add(EXPR_FLAGS_OFFSET).cast::<u16>().write(0x0080);
            let mut parse = Parse::new();
            let mut first_in_reg = 0;
            let mut first_temp_reg = 0;
            let mut second_in_reg = 0;
            let mut second_temp_reg = 0;

            expr_code_pair(
                parse.0.as_mut_ptr(),
                first_wrapper,
                &mut first_in_reg,
                &mut first_temp_reg,
                second_leaf,
                &mut second_in_reg,
                &mut second_temp_reg,
            );

            assert_eq!(first_in_reg, 11);
            assert_eq!(first_temp_reg, 11);
            assert_eq!(second_in_reg, 12);
            assert_eq!(second_temp_reg, 12);
            assert_eq!(first_leaf.add(EXPR_FLAGS_OFFSET).cast::<u16>().read(), 0x0240);
            assert_eq!(second_leaf.add(EXPR_FLAGS_OFFSET).cast::<u16>().read(), 0x0280);
            assert_eq!((*addr_of!(CALLS)).as_slice(), &[(first_leaf, 11), (second_leaf, 12)]);
        }
    }
}
