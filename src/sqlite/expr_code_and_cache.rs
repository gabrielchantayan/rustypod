//! Cache an expression's generated VDBE register.
//!
//! - `expr_code_and_cache` — original: `FUN_08376c28` @ `0x08376c28`
//!   (108 bytes; 2 unconditional `bl`, no predicated `bl`, decoded from
//!   `osos.dec`; Ghidra's three-call-site report is incorrect). SQLite
//!   3.5.9's `sqlite3ExprCodeAndCache`.
//!
//! Firmware algorithm:
//!
//! ```text
//! in_reg = expr_code(parse, expr, target)
//! if expr.op != TK_REGISTER:
//!     cache_reg = ++parse.nMem
//!     vdbe_add_op3(parse.pVdbe, OP_MemStore, in_reg, cache_reg, 0)
//!     expr.iTable = cache_reg
//!     expr.op = TK_REGISTER
//! return in_reg
//! ```
//!
//! `Parse.pVdbe` has no NULL guard on the cache-miss path, matching the
//! firmware and SQLite's required caller invariant. No deliberate deviations.

use super::expr_code::expr_code;
use super::vdbe::{vdbe_add_op3, Vdbe};

/// Byte offsets in the target's 32-bit `Parse` and `Expr` layouts.
const P_VDBE_OFFSET: usize = 0x0c;
const N_MEM_OFFSET: usize = 0x48;
const EXPR_I_TABLE_OFFSET: usize = 0x24;
const EXPR_OP_OFFSET: usize = 0;
const TK_REGISTER: u8 = 0x7f;
const OP_MEM_STORE: i32 = 0x13;

/// `sqlite3ExprCodeAndCache`: generate `expr` in `target`; on its first
/// encounter, assign a new cache register, emit `OP_MemStore`, and mark the
/// expression as `TK_REGISTER`. Returns the register chosen by `expr_code`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_code_and_cache(
    parse: *mut u8,
    expr: *mut u8,
    target: i32,
) -> i32 {
    let in_reg = expr_code(parse, expr, target);
    if expr.add(EXPR_OP_OFFSET).read() != TK_REGISTER {
        let cache_reg = (parse.add(N_MEM_OFFSET) as *mut i32).read().wrapping_add(1);
        (parse.add(N_MEM_OFFSET) as *mut i32).write(cache_reg);
        let p_vdbe = (parse.add(P_VDBE_OFFSET) as *const *mut Vdbe).read();
        vdbe_add_op3(p_vdbe, OP_MEM_STORE, in_reg, cache_reg, 0);
        (expr.add(EXPR_I_TABLE_OFFSET) as *mut i32).write(cache_reg);
        expr.add(EXPR_OP_OFFSET).write(TK_REGISTER);
    }
    in_reg
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::expr_code::{ExprCodeOps, EXPR_CODE_OPS, EXPR_CODE_OPS_LOCK};
    use crate::sqlite::vdbe::{Vdbe, VdbeOp};
    use std::sync::MutexGuard;

    static mut IN_REG: i32 = 0;

    unsafe extern "C" fn fixed_expr_code(
        _parse: *mut u8,
        _expr: *mut u8,
        _target: i32,
    ) -> i32 {
        *core::ptr::addr_of!(IN_REG)
    }

    fn install(in_reg: i32) -> MutexGuard<'static, ()> {
        let guard = EXPR_CODE_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            *core::ptr::addr_of_mut!(IN_REG) = in_reg;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(EXPR_CODE_OPS),
                ExprCodeOps { expr_code_target: fixed_expr_code },
            );
        }
        guard
    }

    #[repr(align(4))]
    struct Parse([u8; 0x4c]);

    impl Parse {
        fn new(vdbe: *mut Vdbe, n_mem: i32) -> Self {
            let mut parse = Self([0; 0x4c]);
            unsafe {
                (parse.0.as_mut_ptr().add(P_VDBE_OFFSET) as *mut *mut Vdbe).write(vdbe);
                (parse.0.as_mut_ptr().add(N_MEM_OFFSET) as *mut i32).write(n_mem);
            }
            parse
        }
    }

    #[repr(align(4))]
    struct Expr([u8; 0x2c]);

    impl Expr {
        fn new(op: u8, i_table: i32) -> Self {
            let mut expr = Self([0; 0x2c]);
            expr.0[EXPR_OP_OFFSET] = op;
            unsafe { (expr.0.as_mut_ptr().add(EXPR_I_TABLE_OFFSET) as *mut i32).write(i_table) };
            expr
        }
    }

    fn statement() -> (Vdbe, [VdbeOp; 1]) {
        let vdbe = Vdbe {
            db: core::ptr::null_mut(), p_prev: core::ptr::null_mut(), p_next: core::ptr::null_mut(),
            n_op: 0, n_op_alloc: 1, a_op: core::ptr::null_mut(), n_label: 0, n_label_alloc: 0,
            a_label: core::ptr::null_mut(), _gap_24: [0; 4], a_col_name: core::ptr::null_mut(),
            a_mem: core::ptr::null_mut(), ap_arg: core::ptr::null_mut(), n_var: 0,
            a_var: core::ptr::null_mut(), ap_csr: core::ptr::null_mut(), n_cursor: 0, magic: 0,
            _gap_48: [0; 0x70 - 0x48], pc: 0, _gap_74: [0; 0xec - 0x74], n_res_column: 0,
            _gap_f0: [0; 8], p_result_set: core::ptr::null_mut(), _gap_fc: [0; 3], expired: 1,
        };
        let op = VdbeOp { opcode: 0, p4type: 0, opflags: 0, p5: 0, p1: 0, p2: 0, p3: 0, p4: core::ptr::null_mut() };
        (vdbe, [op])
    }

    #[test]
    fn cache_miss_allocates_register_emits_store_and_marks_expression() {
        let _guard = install(5);
        let (mut vdbe, mut ops) = statement();
        vdbe.a_op = ops.as_mut_ptr();
        let mut parse = Parse::new(&mut vdbe, 7);
        let mut expr = Expr::new(3, -1);
        let result = unsafe { expr_code_and_cache(parse.0.as_mut_ptr(), expr.0.as_mut_ptr(), 5) };
        assert_eq!(result, 5);
        assert_eq!(unsafe { (parse.0.as_ptr().add(N_MEM_OFFSET) as *const i32).read() }, 8);
        assert_eq!(ops[0].opcode, OP_MEM_STORE as u8);
        assert_eq!((ops[0].p1, ops[0].p2, ops[0].p3), (5, 8, 0));
        assert_eq!(unsafe { (expr.0.as_ptr().add(EXPR_I_TABLE_OFFSET) as *const i32).read() }, 8);
        assert_eq!(expr.0[EXPR_OP_OFFSET], TK_REGISTER);
    }

    #[test]
    fn cached_expression_preserves_cache_and_does_not_emit_an_op() {
        let _guard = install(-3);
        let (mut vdbe, mut ops) = statement();
        vdbe.a_op = ops.as_mut_ptr();
        let mut parse = Parse::new(&mut vdbe, 9);
        let mut expr = Expr::new(TK_REGISTER, 4);
        assert_eq!(unsafe { expr_code_and_cache(parse.0.as_mut_ptr(), expr.0.as_mut_ptr(), -3) }, -3);
        assert_eq!(unsafe { (parse.0.as_ptr().add(N_MEM_OFFSET) as *const i32).read() }, 9);
        assert_eq!(vdbe.n_op, 0);
        assert_eq!(unsafe { (expr.0.as_ptr().add(EXPR_I_TABLE_OFFSET) as *const i32).read() }, 4);
    }
}
