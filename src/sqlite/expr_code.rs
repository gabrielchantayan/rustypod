//! The expression code generator's "guaranteed placement" wrapper.
//!
//! - `expr_code` — original: `FUN_08376bf4` @ 0x08376bf4 (52 bytes;
//!   23 `bl` call sites, binary-scanned; no tail `b` sites). SQLite
//!   3.5.9's `sqlite3ExprCode` (expr.c), the entry point every caller
//!   uses when the expression's value MUST land in a specific VDBE
//!   register: it lets the underlying code generator pick any register
//!   it likes, then emits an `OP_SCopy` to move the value into the
//!   requested target when the generator chose differently.
//!
//! Upstream 3.5.9 (expr.c, verbatim):
//!
//! ```c
//! int sqlite3ExprCode(Parse *pParse, Expr *pExpr, int target){
//!   int inReg;
//!   assert( target>0 && target<=pParse->nMem );
//!   inReg = sqlite3ExprCodeTarget(pParse, pExpr, target);
//!   assert( pParse->pVdbe || pParse->db->mallocFailed );
//!   if( inReg!=target && pParse->pVdbe ){
//!     sqlite3VdbeAddOp2(pParse->pVdbe, OP_SCopy, inReg, target);
//!   }
//!   return target;
//! }
//! ```
//!
//! Firmware algorithm (verified against osos.asm
//! 0x08376bf4..0x08376c28, both asserts compiled out by NDEBUG):
//!
//! ```text
//! in_reg = expr_code_target(parse, expr, target)   // @ 0x08376ef0 (UNPORTED)
//! if in_reg != target:
//!     p_vdbe = *(parse + 0x0c)                     // Parse.pVdbe
//!     if p_vdbe != NULL:
//!         vdbe_add_op2(p_vdbe, 8 /* OP_SCopy */, in_reg, target)  // @ 0x08386824
//! return target
//! ```
//!
//! `Parse` fields used (byte offsets, matching `sqlite/mod.rs`):
//!
//! ```text
//! +0x0c pVdbe   (Vdbe *)  statement under construction — loaded ONLY
//!                         when in_reg != target (the original's
//!                         `ldrne r0,[r4,#0xc]`)
//! ```
//!
//! The opcode literal 8 is SQLite 3.5.9's `OP_SCopy` (the original's
//! `movne r1,#0x8`); unlike `OP_Copy` it does not make a deep copy of
//! strings/blobs, which is exactly what a register-to-register move of
//! a value the caller still owns wants.
//!
//! Deviations:
//! - `sqlite3ExprCodeTarget` @ 0x08376ef0 (3168 bytes — the expression
//!   code generator proper) is UNPORTED and rides the
//!   [`EXPR_CODE_OPS`] seam; the shipped default is the
//!   [`missing_expr_code_target`] stand-in, which reports "the value
//!   already sits in `target`" (returns `target`), so no `OP_SCopy` is
//!   emitted and the function reduces to the identity on `target`.
//! - `vdbe_add_op2` @ 0x08386824 is ported ([`crate::sqlite::vdbe`])
//!   and called directly.
//! - The two upstream `assert`s have no firmware counterpart (release
//!   build) and are not modeled.

/// Byte offset of `Parse.pVdbe` (original: `ldrne r0,[r4,#0xc]`).
pub const P_VDBE_OFFSET: usize = 0x0c;

/// `OP_SCopy` in the firmware's opcode numbering (original:
/// `movne r1,#0x8`). A shallow register-to-register move: string/blob
/// payloads are NOT duplicated, unlike `OP_Copy`.
pub const OP_S_COPY: i32 = 8;

/// Indirect dispatch for the unported expression code generator @
/// 0x08376ef0 (`sqlite3ExprCodeTarget`), kept behind the table so host
/// tests can observe the call's arguments and control the register it
/// reports (the house pattern — `sqlite/cell_size.rs`).
#[derive(Clone, Copy)]
pub struct ExprCodeOps {
    /// `sqlite3ExprCodeTarget` @ 0x08376ef0 (UNPORTED): generate code
    /// evaluating `expr`, preferring to leave the result in register
    /// `target`, and return the register the value actually landed in
    /// (which may differ from `target`).
    pub expr_code_target:
        unsafe extern "C" fn(parse: *mut u8, expr: *mut u8, target: i32) -> i32,
}

/// Stand-in for the unported 0x08376ef0 (same reasoning as
/// `sqlite/cell_size.rs`'s stand-ins): report that the value already
/// sits in the requested register. `expr_code` then skips the
/// `OP_SCopy` and returns `target` unchanged — the behaviorally
/// neutral answer.
unsafe extern "C" fn missing_expr_code_target(
    _parse: *mut u8,
    _expr: *mut u8,
    target: i32,
) -> i32 {
    target
}

/// Wired default for [`EXPR_CODE_OPS`]: the 0x08376ef0 stand-in (both
/// target and host) until the code generator is ported.
pub const DEFAULT_EXPR_CODE_OPS: ExprCodeOps = ExprCodeOps {
    expr_code_target: missing_expr_code_target,
};

/// Active model of the `sqlite3ExprCodeTarget` code generator in
/// [`expr_code`]. Host tests replace the slot to observe the exact
/// arguments and choose the reported register.
pub static mut EXPR_CODE_OPS: ExprCodeOps = DEFAULT_EXPR_CODE_OPS;

/// Reads the code-generator slot. Volatile so LLVM cannot
/// constant-fold the load to the stand-in default (the house pattern —
/// `sqlite/cell_size.rs`).
#[inline(always)]
pub(crate) unsafe fn expr_code_target_op(
) -> unsafe extern "C" fn(*mut u8, *mut u8, i32) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(EXPR_CODE_OPS.expr_code_target))
}

/// expr_code — original: `FUN_08376bf4` @ 0x08376bf4 (52 bytes;
/// 23 `bl` call sites).
///
/// `sqlite3ExprCode`: evaluate `expr` so the result is guaranteed to
/// sit in VDBE register `target`, and return `target`. Asks the
/// [`EXPR_CODE_OPS`] code generator to evaluate the expression; when
/// the generator picked a different register AND the parse context has
/// a statement under construction (`Parse.pVdbe` non-NULL), appends
/// `OP_SCopy in_reg, target` through the ported
/// [`crate::sqlite::vdbe::vdbe_add_op2`]. `target` is returned
/// verbatim on every path, including negative values (no range check
/// exists in the firmware — the upstream `assert` is compiled out).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_code(parse: *mut u8, expr: *mut u8, target: i32) -> i32 {
    let in_reg = (expr_code_target_op())(parse, expr, target);
    if in_reg != target {
        let p_vdbe = (parse.add(P_VDBE_OFFSET) as *const *mut super::vdbe::Vdbe).read();
        if !p_vdbe.is_null() {
            super::vdbe::vdbe_add_op2(p_vdbe, OP_S_COPY, in_reg, target);
        }
    }
    target
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::vdbe::{Vdbe, VdbeOp};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the code-generator slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every `(expr, target)` pair the slot was called with, in order.
    /// (The `parse` pointer is the context's own address in every
    /// test, so recording it adds nothing.)
    static mut CALLS: Vec<(*mut u8, i32)> = Vec::new();

    /// The register the mock reports the value landed in.
    static mut MOCK_IN_REG: i32 = 0;

    unsafe extern "C" fn recording_expr_code_target(
        _parse: *mut u8,
        expr: *mut u8,
        target: i32,
    ) -> i32 {
        (*core::ptr::addr_of_mut!(CALLS)).push((expr, target));
        *core::ptr::addr_of!(MOCK_IN_REG)
    }

    /// Installs the recording mock and returns the lock guard, which
    /// must stay alive for the whole test.
    fn bench(in_reg: i32) -> MutexGuard<'static, ()> {
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            *core::ptr::addr_of_mut!(MOCK_IN_REG) = in_reg;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(EXPR_CODE_OPS),
                ExprCodeOps {
                    expr_code_target: recording_expr_code_target,
                },
            );
        }
        ops_guard
    }

    fn calls() -> Vec<(*mut u8, i32)> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// A `Parse` context: word-aligned so the `pVdbe` pointer load at
    /// +0x0c is aligned as it is on target. Only `pVdbe` is modeled;
    /// the rest is filler.
    #[repr(align(4))]
    struct ParseContext([u8; 0x20]);

    impl ParseContext {
        fn new(p_vdbe: *mut Vdbe) -> Self {
            let mut ctx = ParseContext([0xa5; 0x20]);
            unsafe {
                (ctx.0.as_mut_ptr().add(P_VDBE_OFFSET) as *mut *mut Vdbe).write(p_vdbe);
            }
            ctx
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    /// A `Vdbe` with room for one op (growth is `vdbe_add_op3`'s
    /// business, covered by its own tests).
    struct Statement {
        ops: [VdbeOp; 1],
        vdbe: Vdbe,
    }

    impl Statement {
        fn new() -> Self {
            Statement {
                ops: [VdbeOp {
                    opcode: 0xff,
                    p4type: 0x7f,
                    opflags: 0xee,
                    p5: 0xdd,
                    p1: -1,
                    p2: -1,
                    p3: -1,
                    p4: 0x1usize as *mut u8,
                }],
                vdbe: Vdbe {
                    db: core::ptr::null_mut(),
                    _gap_04: [0; 8],
                    n_op: 0,
                    n_op_alloc: 1,
                    a_op: core::ptr::null_mut(),
                    n_label: 0,
                    n_label_alloc: 0,
                    a_label: core::ptr::null_mut(),
                    _gap_24: [0; 4],
                    a_col_name: core::ptr::null_mut(),
                    _gap_2c: [0; 0xec - 0x2c],
                    n_res_column: 0,
                    _gap_f0: [0; 0xff - 0xf0],
                    expired: 1,
                },
            }
        }
        /// The `Vdbe` pointer, with `a_op` re-pinned to `ops` (the
        /// `Statement` moves after `new()` returns, so wiring `a_op`
        /// inside `new()` would leave it pointing at the dead slot).
        fn ptr(&mut self) -> *mut Vdbe {
            self.vdbe.a_op = self.ops.as_mut_ptr();
            &mut self.vdbe
        }
    }

    const EXPR_COOKIE: usize = 0x5eed;

    fn expr_cookie() -> *mut u8 {
        EXPR_COOKIE as *mut u8
    }

    #[test]
    fn already_in_target_returns_target_and_appends_nothing() {
        let _guard = bench(7);
        let mut stmt = Statement::new();
        let mut parse = ParseContext::new(stmt.ptr());
        let rc = unsafe { expr_code(parse.ptr(), expr_cookie(), 7) };
        assert_eq!(rc, 7, "target returned verbatim");
        assert_eq!(calls(), [(expr_cookie(), 7)], "one code-generator call");
        assert_eq!(stmt.vdbe.n_op, 0, "no OP_SCopy when in_reg == target");
        assert_eq!(stmt.vdbe.expired, 1, "statement untouched");
    }

    #[test]
    fn different_register_with_vdbe_appends_s_copy() {
        let _guard = bench(11);
        let mut stmt = Statement::new();
        let mut parse = ParseContext::new(stmt.ptr());
        let rc = unsafe { expr_code(parse.ptr(), expr_cookie(), 7) };
        assert_eq!(rc, 7, "target returned, not in_reg");
        assert_eq!(stmt.vdbe.n_op, 1, "exactly one op appended");
        let op = &stmt.ops[0];
        assert_eq!(op.opcode, OP_S_COPY as u8, "opcode 8 = OP_SCopy");
        assert_eq!(op.p1, 11, "p1 = register the value actually sits in");
        assert_eq!(op.p2, 7, "p2 = requested target");
        assert_eq!(op.p3, 0, "vdbe_add_op2 zeroes p3");
        assert_eq!(op.p4, core::ptr::null_mut(), "p4 zeroed");
        assert_eq!(op.p5, 0, "p5 zeroed");
        assert_eq!(stmt.vdbe.expired, 0, "appending clears expired");
    }

    #[test]
    fn different_register_without_vdbe_appends_nothing() {
        let _guard = bench(11);
        let mut parse = ParseContext::new(core::ptr::null_mut());
        let rc = unsafe { expr_code(parse.ptr(), expr_cookie(), 7) };
        assert_eq!(rc, 7, "target returned even with no statement");
        assert_eq!(calls(), [(expr_cookie(), 7)]);
    }

    #[test]
    fn in_reg_equals_target_with_null_vdbe_is_also_quiet() {
        // Both conditions fail; pins that the NULL check alone is not
        // what suppresses the op.
        let _guard = bench(7);
        let mut parse = ParseContext::new(core::ptr::null_mut());
        let rc = unsafe { expr_code(parse.ptr(), expr_cookie(), 7) };
        assert_eq!(rc, 7);
        assert_eq!(calls(), [(expr_cookie(), 7)]);
    }

    #[test]
    fn negative_target_passes_through_verbatim() {
        // No range check exists in the firmware (the upstream assert is
        // compiled out): an out-of-range target is still returned and
        // still drives the comparison.
        let _guard = bench(3);
        let mut stmt = Statement::new();
        let mut parse = ParseContext::new(stmt.ptr());
        let rc = unsafe { expr_code(parse.ptr(), expr_cookie(), -1) };
        assert_eq!(rc, -1, "negative target returned verbatim");
        assert_eq!(stmt.vdbe.n_op, 1);
        assert_eq!(stmt.ops[0].p2, -1, "negative target still used as p2");
    }

    #[test]
    fn missing_expr_code_target_stand_in_reports_value_in_target() {
        let in_reg = unsafe { missing_expr_code_target(core::ptr::null_mut(), core::ptr::null_mut(), 42) };
        assert_eq!(in_reg, 42, "stand-in claims the value is already placed");
    }

    #[test]
    fn default_ops_use_the_stand_in() {
        let default: unsafe extern "C" fn(*mut u8, *mut u8, i32) -> i32 =
            DEFAULT_EXPR_CODE_OPS.expr_code_target;
        assert_eq!(default as usize, missing_expr_code_target as usize);
    }
}
