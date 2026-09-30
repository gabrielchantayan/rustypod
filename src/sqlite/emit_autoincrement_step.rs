//! Emit the register update used by INSERT's autoincrement bookkeeping.
//!
//! `FUN_082b5888` @ 0x082b5888: true size 28 bytes, ending at the
//! next push prologue at 0x082b58a4. Full-image ARM-word decoding finds
//! two inbound plain BL sites (0x0837c66c, 0x08399194), no predicated BL
//! sites. The body has no BL, only a signed-GT tail B to 0x08386824.
//! Algorithm: when the tracking register is positive, load Parse.pVdbe
//! at +0x0c and emit opcode 0x2c with (tracking register, rowid register,
//! 0) through vdbe_add_op2. Otherwise do not access Parse. Both callers
//! are INSERT code generators; Ghidra incorrectly names the tail target
//! vdbe_add_op3, but the encoded BGT targets vdbe_add_op2.
//! Deliberate deviations: no behavioral changes; Parse retains its u32
//! target pointer field, while Vdbe uses the existing host-safe Rust layout.
//! The void API discards the emitter's incidental returned opcode address.

use super::vdbe::{vdbe_add_op2, Vdbe};

/// # Safety
/// For a positive tracking register, `parse` must be aligned and readable
/// through +0x0f, with a valid target-width pVdbe for vdbe_add_op2.
/// Nonpositive tracking registers require no valid pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn emit_autoincrement_step(
    parse: *mut u8,
    tracking_register: i32,
    rowid_register: i32,
) {
    if tracking_register > 0 {
        let vdbe = parse.add(0x0c).cast::<u32>().read() as usize as *mut Vdbe;
        vdbe_add_op2(vdbe, 0x2c, tracking_register, rowid_register);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::vdbe::VdbeOp;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn signed_nonpositive_tracking_register_never_reads_parse() {
        for register in [i32::MIN, -1, 0] {
            unsafe { emit_autoincrement_step(core::ptr::null_mut(), register, i32::MAX) };
        }
    }

    #[test]
    fn positive_boundaries_append_without_changing_parse_or_prior_ops() {
        let Some(slab) = try_map_u32_slab(hints::SQLITE_EMIT_AUTOINCREMENT_STEP, 0x2000) else {
            if note_missing_u32_fixture(module_path!()) { return; }
            unreachable!();
        };
        unsafe {
            core::ptr::write_bytes(slab, 0xa5, 0x20);
            let vdbe = slab.add(0x100).cast::<Vdbe>();
            vdbe.write(core::mem::zeroed());
            let mut ops: [VdbeOp; 3] = core::mem::zeroed();
            ops[0].opcode = 0x55;
            ops[0].p1 = 17;
            let prior = ops[0];
            (*vdbe).a_op = ops.as_mut_ptr();
            (*vdbe).n_op = 1;
            (*vdbe).n_op_alloc = 3;
            (*vdbe).expired = 1;
            slab.add(0x0c).cast::<u32>().write(vdbe as usize as u32);
            let before: [u8; 0x20] = slab.cast::<[u8; 0x20]>().read();
            for (i, (tracking, rowid)) in [(1, i32::MIN), (i32::MAX, -1)].iter().enumerate() {
                emit_autoincrement_step(slab, *tracking, *rowid);
                assert_eq!((*vdbe).n_op, i as i32 + 2);
                assert_eq!((ops[i + 1].opcode, ops[i + 1].p1, ops[i + 1].p2, ops[i + 1].p3),
                           (0x2c, *tracking, *rowid, 0));
                assert_eq!(ops[0], prior);
                assert_eq!(slab.cast::<[u8; 0x20]>().read(), before);
                assert_eq!((*vdbe).expired, 0);
            }
        }
    }
}
