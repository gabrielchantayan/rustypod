//! Left-join unmatched-row branch emission.
//!
//! `emit_left_join_null_row` — original: `FUN_082c4038` @ `0x082c4038`
//! (120 bytes, `0x082c4038..0x082c40b0`; 3 direct inbound `bl` call sites:
//! 1 plain `bl`, 2 `bleq`). Raw ARM has four unconditional outgoing `bl`
//! instructions and no predicated outgoing calls.
//!
//! If `WhereLevel.iLeftJoin` (+0x38) is non-negative and `break_addr` is
//! nonzero, emit the three-op sequence that skips the unmatched-row path when
//! the left-join flag is set, then patch the conditional branch to the next
//! VDBE operation. Otherwise it is a no-op. Deliberate deviations: the
//! recovered `WhereLevel` is represented as a raw target-layout byte pointer;
//! the Rust implementation uses the existing typed VDBE builder helpers.

use super::vdbe::{vdbe_add_op1, vdbe_add_op2, vdbe_add_op3, vdbe_change_p2, Vdbe};

const WHERE_LEVEL_I_LEFT_JOIN_OFFSET: usize = 0x38;
const OP_LEFT_JOIN_TEST: i32 = 0x29;
const OP_LEFT_JOIN_BRANCH: i32 = 0x16;
const OP_GOTO: i32 = 0x5b;

/// Emit the unmatched-left-join branch sequence for `level`.
///
/// # Safety
///
/// `vdbe` must identify a writable VDBE accepted by the builder helpers.
/// `level` must be four-byte aligned and readable through +0x3b.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn emit_left_join_null_row(
    vdbe: *mut Vdbe,
    level: *const u8,
    break_addr: i32,
) {
    let left_join_register = (level.add(WHERE_LEVEL_I_LEFT_JOIN_OFFSET) as *const i32).read();
    if left_join_register < 0 || break_addr == 0 {
        return;
    }

    vdbe_add_op2(vdbe, OP_LEFT_JOIN_TEST, left_join_register, -1);
    let branch = vdbe_add_op1(vdbe, OP_LEFT_JOIN_BRANCH, left_join_register);
    vdbe_add_op3(vdbe, OP_GOTO, 0, break_addr, 0);
    vdbe_change_p2(vdbe, branch, (*vdbe).n_op);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::vdbe::VdbeOp;
    use core::mem::MaybeUninit;

    #[repr(C, align(4))]
    struct WhereLevel([u8; 0x3c]);

    fn level(left_join_register: i32) -> WhereLevel {
        let mut level = WhereLevel([0; 0x3c]);
        unsafe {
            (level.0.as_mut_ptr().add(WHERE_LEVEL_I_LEFT_JOIN_OFFSET) as *mut i32)
                .write(left_join_register);
        }
        level
    }

    #[test]
    fn emits_and_patches_unmatched_left_join_branch() {
        unsafe {
            let mut vdbe = MaybeUninit::<Vdbe>::zeroed().assume_init();
            let mut ops = [MaybeUninit::<VdbeOp>::zeroed(); 4];
            vdbe.a_op = ops.as_mut_ptr().cast();
            vdbe.n_op_alloc = 4;
            let level = level(7);

            emit_left_join_null_row(&mut vdbe, level.0.as_ptr(), 42);

            assert_eq!(vdbe.n_op, 3);
            let ops = ops.as_ptr().cast::<VdbeOp>();
            assert_eq!(((*ops).opcode, (*ops).p1, (*ops).p2, (*ops).p3), (0x29, 7, -1, 0));
            assert_eq!(((*ops.add(1)).opcode, (*ops.add(1)).p1, (*ops.add(1)).p2, (*ops.add(1)).p3), (0x16, 7, 3, 0));
            assert_eq!(((*ops.add(2)).opcode, (*ops.add(2)).p1, (*ops.add(2)).p2, (*ops.add(2)).p3), (0x5b, 0, 42, 0));
        }
    }

    #[test]
    fn skips_negative_register_and_zero_break_address() {
        unsafe {
            let mut vdbe = MaybeUninit::<Vdbe>::zeroed().assume_init();
            let mut ops = [MaybeUninit::<VdbeOp>::zeroed(); 4];
            vdbe.a_op = ops.as_mut_ptr().cast();
            vdbe.n_op_alloc = 4;
            let inactive = level(-1);
            let active = level(3);

            emit_left_join_null_row(&mut vdbe, inactive.0.as_ptr(), 42);
            emit_left_join_null_row(&mut vdbe, active.0.as_ptr(), 0);

            assert_eq!(vdbe.n_op, 0);
        }
    }
}
