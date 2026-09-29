//! Emit the three VDBE operations that share one temporary register.
//!
//! `emit_temp_register_ops` — original: `FUN_082c3d0c` @ 0x082c3d0c
//! (128 bytes; 3 unconditional `bl` instructions to 2 callees, binary-decoded;
//! no predicated `bl` instructions). The next real function begins at
//! 0x082c3d8c.
//!
//! Firmware algorithm (verified against osos.dec 0x082c3d0c..0x082c3d8c):
//!
//! ```text
//! temp = get_temp_reg(parse)
//! vdbe_add_op3(parse->pVdbe, 0x55, third, fourth, temp)
//! vdbe_add_op3(parse->pVdbe, 0x7a, first, second, temp)
//! vdbe_add_op3(parse->pVdbe, 0x68, first, temp, 0)
//! release_temp_reg(parse, temp)
//! ```
//!
//! Deliberate deviation: the original helper's SQLite source name is not
//! established; this name states its verified VDBE-emission effect.

use super::expr_code::P_VDBE_OFFSET;
use super::get_temp_reg::get_temp_reg;
use super::parse::release_temp_reg;
use super::vdbe::{vdbe_add_op3, Vdbe};

const OP_FIRST: i32 = 0x55;
const OP_SECOND: i32 = 0x7a;
const OP_THIRD: i32 = 0x68;

/// Emit three operations using an allocated temporary register, then release it.
///
/// # Safety
///
/// `parse` must name a writable target-width `Parse` with a valid `pVdbe` at
/// +0x0c. That VDBE must have capacity for three appended operations. The
/// firmware dereferences both pointers without NULL guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn emit_temp_register_ops(
    parse: *mut u8,
    first: i32,
    second: i32,
    third: i32,
    fourth: i32,
) {
    let vdbe = (parse.add(P_VDBE_OFFSET) as *const *mut Vdbe).read();
    let temp = get_temp_reg(parse);
    vdbe_add_op3(vdbe, OP_FIRST, third, fourth, temp);
    vdbe_add_op3(vdbe, OP_SECOND, first, second, temp);
    vdbe_add_op3(vdbe, OP_THIRD, first, temp, 0);
    release_temp_reg(parse, temp);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::VdbeOp;

    #[repr(align(4))]
    struct ParseContext([u8; 0x50]);

    #[test]
    fn emits_ordered_ops_and_recycles_wrapping_temp() {
        unsafe {
            let mut ops = [VdbeOp {
                opcode: 0,
                p4type: 0,
                opflags: 0xa5,
                p5: 0xa5,
                p1: 0,
                p2: 0,
                p3: 0,
                p4: core::ptr::null_mut(),
            }; 3];
            let mut vdbe: Vdbe = core::mem::zeroed();
            vdbe.n_op_alloc = 3;
            vdbe.a_op = ops.as_mut_ptr();
            let mut parse = ParseContext([0; 0x50]);
            (parse.0.as_mut_ptr().add(P_VDBE_OFFSET) as *mut *mut Vdbe).write(&mut vdbe);
            (parse.0.as_mut_ptr().add(0x48) as *mut i32).write(i32::MAX);

            emit_temp_register_ops(parse.0.as_mut_ptr(), -3, 7, 11, -13);

            assert_eq!(vdbe.n_op, 3);
            assert_eq!((ops[0].opcode, ops[0].p1, ops[0].p2, ops[0].p3), (0x55, 11, -13, i32::MIN));
            assert_eq!((ops[1].opcode, ops[1].p1, ops[1].p2, ops[1].p3), (0x7a, -3, 7, i32::MIN));
            assert_eq!((ops[2].opcode, ops[2].p1, ops[2].p2, ops[2].p3), (0x68, -3, i32::MIN, 0));
            assert_eq!(parse.0[0x15], 1);
            assert_eq!((parse.0.as_ptr().add(0x18) as *const i32).read(), i32::MIN);
        }
    }
}
