//! Move a computed value from one VDBE register to another.
//!
//! `expr_code_move` — original: `FUN_08376e98` @ `0x08376e98` (88
//! bytes; 4 unconditional `bl` call sites, binary-scanned:
//! 0x082d0468, 0x082e8884, 0x08368bb8, 0x083838f8; no predicated `bl`
//! or tail `b` sites). SQLite 3.5.9's `sqlite3ExprCodeMove` (expr.c):
//! emit an `OP_Move` and re-point the column cache entry that tracked
//! the old register at the new one.
//!
//! Firmware algorithm (verified against osos.asm
//! 0x08376e98..0x08376ef0; the independent next function
//! `FUN_08376ef0`, the `sqlite3ExprCodeTarget` code generator proper,
//! begins at 0x08376ef0 — Ghidra's 88-byte extent is exact):
//!
//! ```text
//! if i_from == i_to: return                       // popeq
//! p_vdbe = *(parse + 0x0c)                        // Parse.pVdbe
//! vdbe_add_op2(p_vdbe, 0x72 /* OP_Move */, i_from, i_to)  // @ 0x08386824
//! i = 0
//! while *(parse + 0x58) > i:                      // nColCache, signed
//!     record = parse + 0x60 + i * 0x10            // aColCache[i]
//!     if record->iReg == i_from:                  // ldr/streq at +0x6c
//!         record->iReg = i_to
//!     i += 1
//! ```
//!
//! `Parse`/`ColCache` fields used (fixed-width, host-independent):
//!
//! ```text
//! +0x0c pVdbe      (Vdbe *)  statement under construction — loaded
//!                            unconditionally once i_from != i_to
//! +0x58 nColCache  (i32)     records in use — reloaded at every
//!                            loop head (ldr inside the loop tail)
//! +0x60 aColCache  (16-byte records)
//!        record +0x0c iReg (i32)  the cached column's VDBE register
//! ```
//!
//! Deviations: none against the firmware. Two deliberate structural
//! notes:
//! - Unlike `sqlite3ExprCode` (`crate::sqlite::expr_code`) there is
//!   NO NULL guard on `pVdbe` here: the original loads `[r4,#0xc]`
//!   and calls `vdbe_add_op2` unconditionally, and so does this port.
//! - The firmware's cache fixup is a plain equality replace
//!   (`cmp`/`streq` on `iReg`); upstream 3.5.9's range shift
//!   (`iReg >= iFrom && iReg < iFrom+nReg → iReg += iTo-iFrom`) has no
//!   counterpart in the 22 instructions, so the exact-equality form is
//!   what runs on-device and what is modeled.
//! - `vdbe_add_op2` @ 0x08386824 is ported ([`crate::sqlite::vdbe`])
//!   and called directly, matching the single direct `bl` at
//!   0x08376ec0.

use super::expr_code::P_VDBE_OFFSET;
use super::used_as_column_cache::{
    A_COL_CACHE_OFFSET, COL_CACHE_I_REG_OFFSET, COL_CACHE_RECORD_SIZE, N_COL_CACHE_OFFSET,
};

/// `OP_Move` in the firmware's opcode numbering (original:
/// `mov r1,#0x72` at 0x08376ebc). Moves the value in register `p1`
/// into register `p2` (the string `Move` sits in the firmware's
/// `sqlite3OpcodeNames` table).
pub const OP_MOVE: i32 = 0x72;

/// expr_code_move — original: `FUN_08376e98` @ `0x08376e98`
/// (88 bytes; 4 unconditional `bl` call sites; no predicated calls).
///
/// `sqlite3ExprCodeMove`: emit `OP_Move i_from, i_to` and update the
/// column cache so the record that cached register `i_from` now
/// caches register `i_to`. A no-op when the registers already agree.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_code_move(parse: *mut u8, i_from: i32, i_to: i32) {
    if i_from == i_to {
        return;
    }
    let p_vdbe = (parse.add(P_VDBE_OFFSET) as *const *mut super::vdbe::Vdbe).read();
    super::vdbe::vdbe_add_op2(p_vdbe, OP_MOVE, i_from, i_to);
    let mut i = 0i32;
    loop {
        let n_col_cache = (parse.add(N_COL_CACHE_OFFSET) as *const i32).read();
        if n_col_cache <= i {
            return;
        }
        let record = parse.add(A_COL_CACHE_OFFSET + i as usize * COL_CACHE_RECORD_SIZE);
        let i_reg = record.add(COL_CACHE_I_REG_OFFSET) as *mut i32;
        if i_reg.read() == i_from {
            i_reg.write(i_to);
        }
        i = i.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::vdbe::{Vdbe, VdbeOp};

    /// A `Parse` context large enough for `pVdbe` (+0x0c), `nColCache`
    /// (+0x58), and eight `aColCache` records (+0x60..+0xe0).
    #[repr(align(4))]
    struct ParseContext([u8; 0xe0]);

    impl ParseContext {
        fn new(p_vdbe: *mut Vdbe, i_regs: &[i32]) -> Self {
            let mut ctx = ParseContext([0xa5; 0xe0]);
            unsafe {
                (ctx.0.as_mut_ptr().add(P_VDBE_OFFSET) as *mut *mut Vdbe).write(p_vdbe);
            }
            ctx.0[N_COL_CACHE_OFFSET..N_COL_CACHE_OFFSET + 4]
                .copy_from_slice(&(i_regs.len() as i32).to_le_bytes());
            for (i, &i_reg) in i_regs.iter().enumerate() {
                let record = A_COL_CACHE_OFFSET + i * COL_CACHE_RECORD_SIZE;
                ctx.0[record + COL_CACHE_I_REG_OFFSET..record + COL_CACHE_I_REG_OFFSET + 4]
                    .copy_from_slice(&i_reg.to_le_bytes());
            }
            ctx
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        fn i_reg(&self, i: usize) -> i32 {
            let record = A_COL_CACHE_OFFSET + i * COL_CACHE_RECORD_SIZE + COL_CACHE_I_REG_OFFSET;
            i32::from_le_bytes(self.0[record..record + 4].try_into().unwrap())
        }
    }

    /// A `Vdbe` with room for one op (growth is `vdbe_add_op3`'s
    /// business, covered by its own tests). Mirrors the fixture in
    /// `sqlite/expr_code.rs`.
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
                    p_prev: core::ptr::null_mut(),
                    p_next: core::ptr::null_mut(),
                    n_op: 0,
                    n_op_alloc: 1,
                    a_op: core::ptr::null_mut(),
                    n_label: 0,
                    n_label_alloc: 0,
                    a_label: core::ptr::null_mut(),
                    _gap_24: [0; 4],
                    a_col_name: core::ptr::null_mut(),
                    a_mem: core::ptr::null_mut(),
                    ap_arg: core::ptr::null_mut(),
                    n_var: 0,
                    a_var: core::ptr::null_mut(),
                    ap_csr: core::ptr::null_mut(),
                    n_cursor: 0,
                    magic: 0,
                    _gap_48: [0; 0x70 - 0x48],
                    pc: 0,
                    _gap_74: [0; 0xec - 0x74],
                    n_res_column: 0,
                    _gap_f0: [0; 8],
                    p_result_set: core::ptr::null_mut(),
                    _gap_fc: [0; 3],
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

    fn shift(ctx: &mut ParseContext, i_from: i32, i_to: i32) {
        unsafe { expr_code_move(ctx.ptr(), i_from, i_to) }
    }

    #[test]
    fn equal_registers_emit_nothing_and_touch_nothing() {
        let mut stmt = Statement::new();
        let mut ctx = ParseContext::new(stmt.ptr(), &[5, 7, 5]);
        let before = ctx.0;
        shift(&mut ctx, 5, 5);
        assert_eq!(stmt.vdbe.n_op, 0, "no OP_Move when i_from == i_to");
        assert_eq!(stmt.vdbe.expired, 1, "statement untouched");
        assert_eq!(ctx.0, before, "cache bytes untouched on the early return");
    }

    #[test]
    fn emits_move_and_rewrites_every_matching_cache_record() {
        let mut stmt = Statement::new();
        let mut ctx = ParseContext::new(stmt.ptr(), &[3, 9, 3, 0, 3]);
        shift(&mut ctx, 3, 12);
        assert_eq!(stmt.vdbe.n_op, 1, "exactly one op appended");
        let op = &stmt.ops[0];
        assert_eq!(op.opcode, OP_MOVE as u8, "opcode 0x72 = OP_Move");
        assert_eq!(op.p1, 3, "p1 = source register");
        assert_eq!(op.p2, 12, "p2 = destination register");
        assert_eq!(op.p3, 0, "vdbe_add_op2 zeroes p3");
        assert_eq!(stmt.vdbe.expired, 0, "appending clears expired");
        assert_eq!(
            [ctx.i_reg(0), ctx.i_reg(1), ctx.i_reg(2), ctx.i_reg(3), ctx.i_reg(4)],
            [12, 9, 12, 0, 12],
            "every record with iReg == i_from is re-pointed, others keep their registers",
        );
    }

    #[test]
    fn no_matching_record_still_emits_the_move() {
        let mut stmt = Statement::new();
        let mut ctx = ParseContext::new(stmt.ptr(), &[1, 2, 4]);
        let before = ctx.0;
        shift(&mut ctx, 8, 9);
        assert_eq!(stmt.vdbe.n_op, 1, "OP_Move is unconditional once i_from != i_to");
        assert_eq!(ctx.0, before, "cache untouched when no record matches");
    }

    #[test]
    fn register_zero_is_a_valid_match() {
        let mut stmt = Statement::new();
        let mut ctx = ParseContext::new(stmt.ptr(), &[0, 1]);
        shift(&mut ctx, 0, 6);
        assert_eq!(ctx.i_reg(0), 6, "iReg 0 has no special-casing in the firmware");
        assert_eq!(ctx.i_reg(1), 1);
    }

    #[test]
    fn empty_cache_still_emits_the_move() {
        let mut stmt = Statement::new();
        let mut ctx = ParseContext::new(stmt.ptr(), &[]);
        shift(&mut ctx, 4, 5);
        assert_eq!(stmt.vdbe.n_op, 1);
        assert_eq!(stmt.ops[0].p1, 4);
        assert_eq!(stmt.ops[0].p2, 5);
    }

    #[test]
    fn negative_cache_count_scans_nothing() {
        let mut stmt = Statement::new();
        let mut ctx = ParseContext::new(stmt.ptr(), &[7]);
        ctx.0[N_COL_CACHE_OFFSET..N_COL_CACHE_OFFSET + 4]
            .copy_from_slice(&(-1i32).to_le_bytes());
        let before = ctx.0;
        shift(&mut ctx, 7, 8);
        assert_eq!(stmt.vdbe.n_op, 1, "the op is emitted before the scan");
        assert_eq!(ctx.0, before, "signed loop bound: negative count scans nothing");
    }
}
