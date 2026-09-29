//! Single-integer result emission — `return_single_int` — original:
//! `FUN_08368188` @ 0x08368188 (148 bytes, 0x08368188..0x0836821c).
//!
//! Raw ARM decoding finds four unconditional outbound `bl` instructions
//! (`sqlite3GetVdbe`, `sqlite3VdbeAddOp3`, `sqlite3VdbeSetNumCols`, and
//! `sqlite3VdbeSetColName`) and no predicated `bl`; two unconditional inbound
//! `bl` sites are at 0x082ce5ac and 0x0837f57c. It is SQLite's
//! `returnSingleInt`: obtain the VDBE, allocate one Parse register, emit
//! `OP_Integer value, register`, and, unless parsing an auxiliary program,
//! describe a one-column result named `label`; finally emit
//! `OP_ResultRow register, 1`.
//!
//! Deliberate deviation: `sqlite3GetVdbe` @ 0x0837acf4 has no Rust symbol
//! despite its stale `names.yaml` `ported` entry. This port uses the existing
//! volatile `BEGIN_WRITE_OPS` resolver, whose default returns Parse.pVdbe and
//! therefore exactly matches the common already-created-VDBE path; tests can
//! install the real callee model through that established seam.

use super::begin_write_operation::{get_vdbe_op, Parse};
use super::vdbe::{vdbe_add_op3, P4_STATIC};
use super::vdbe_set_col_name::vdbe_set_col_name;
use super::vdbe_set_num_cols::vdbe_set_num_cols;

/// `OP_Integer` in this firmware build (`mov r1,#0x2f`).
pub const OP_INTEGER: i32 = 0x2f;
/// `OP_ResultRow` in this firmware build (`mov r1,#0x56`).
pub const OP_RESULT_ROW: i32 = 0x56;
const N_MEM_OFFSET: usize = 0x48;
const EXPLAIN_OFFSET: usize = 0x15c;

/// Emit a single integer result named `label` for the current parse context.
///
/// # Safety
/// `parse` must be a writable target-layout `Parse`; its `nMem` word at
/// +0x48 and `explain` byte at +0x15c are accessed directly. The active
/// `sqlite3GetVdbe` resolver must return a live VDBE, as the original does
/// not check it for NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn return_single_int(parse: *mut Parse, label: *mut u8, value: i32) {
    let vdbe = get_vdbe_op()(parse);
    let n_mem = parse.cast::<u8>().add(N_MEM_OFFSET).cast::<i32>();
    let register = (*n_mem).wrapping_add(1);
    *n_mem = register;
    vdbe_add_op3(vdbe, OP_INTEGER, value, register, 0);
    if *parse.cast::<u8>().add(EXPLAIN_OFFSET) == 0 {
        vdbe_set_num_cols(vdbe, 1);
        vdbe_set_col_name(vdbe, 0, 0, label, P4_STATIC);
    }
    vdbe_add_op3(vdbe, OP_RESULT_ROW, register, 1, 0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    use parking_lot::Mutex;
    use crate::sqlite::begin_write_operation::{BeginWriteOps, DEFAULT_BEGIN_WRITE_OPS, BEGIN_WRITE_OPS};
    use crate::sqlite::vdbe::{Vdbe, VdbeOp};
    use core::mem::MaybeUninit;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut VDBE: *mut Vdbe = core::ptr::null_mut();

    unsafe extern "C" fn resolved_vdbe(_parse: *mut Parse) -> *mut Vdbe {
        VDBE
    }

    #[repr(align(4))]
    struct ParseFixture([u8; EXPLAIN_OFFSET + 1]);

    unsafe fn emit(explain: bool, value: i32) -> (i32, [VdbeOp; 2], i32) {
        let _guard = LOCK.lock();
        let mut ops: [VdbeOp; 2] = core::mem::zeroed();
        let mut vdbe: Vdbe = MaybeUninit::zeroed().assume_init();
        vdbe.a_op = ops.as_mut_ptr();
        vdbe.n_op_alloc = ops.len() as i32;
        let mut db = [0u8; 0x1f];
        db[0x1e] = 1;
        vdbe.db = db.as_mut_ptr();
        let mut parse = ParseFixture([0; EXPLAIN_OFFSET + 1]);
        parse.0[N_MEM_OFFSET..N_MEM_OFFSET + 4].copy_from_slice(&41i32.to_le_bytes());
        parse.0[EXPLAIN_OFFSET] = explain as u8;
        VDBE = &mut vdbe;
        let saved = BEGIN_WRITE_OPS;
        BEGIN_WRITE_OPS = BeginWriteOps { get_vdbe: resolved_vdbe, ..DEFAULT_BEGIN_WRITE_OPS };
        return_single_int(parse.0.as_mut_ptr().cast(), b"answer\0".as_ptr() as *mut u8, value);
        BEGIN_WRITE_OPS = saved;
        VDBE = core::ptr::null_mut();
        (i32::from_le_bytes(parse.0[N_MEM_OFFSET..N_MEM_OFFSET + 4].try_into().unwrap()), ops, vdbe.n_res_column)
    }

    #[test]
    fn emits_integer_and_result_row_for_auxiliary_program() {
        unsafe {
            let (n_mem, ops, columns) = emit(true, -17);
            assert_eq!(n_mem, 42);
            assert_eq!((ops[0].opcode, ops[0].p1, ops[0].p2, ops[0].p3), (OP_INTEGER as u8, -17, 42, 0));
            assert_eq!((ops[1].opcode, ops[1].p1, ops[1].p2, ops[1].p3), (OP_RESULT_ROW as u8, 42, 1, 0));
            assert_eq!(columns, 0);
        }
    }

    #[test]
    fn configures_one_result_column_for_normal_parse() {
        unsafe {
            let (_n_mem, _ops, columns) = emit(false, 0);
            assert_eq!(columns, 1);
        }
    }
}
