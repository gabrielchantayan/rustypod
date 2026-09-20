//! Emit one ResultRow-style VDBE operation for every SELECT in a compound chain.
//!
//! `emit_compound_select_rows` — original: `FUN_0837a0d4` @ 0x0837a0d4
//! (132 bytes; 2 direct outbound `bl`, both unconditional). Raw ARM words end
//! at `pop {...,pc}` @ 0x0837a154; the separate next function starts at
//! 0x0837a158. The function walks the target-width `Select.pPrior` chain at
//! +0x10. For each enabled member it delegates its code generation, then emits
//! opcode 62 with the returned register, the member's result-column count + 1,
//! and a consecutive destination register.
//!
//! Deliberate deviation: `select_codegen` @ 0x08379f38 is not yet ported, so
//! it is an explicit replaceable seam. The target default calls its verified
//! retailOS address; host tests install a recorder. `Parse.pVdbe` and chain
//! links are read as 32-bit target words so host pointer width cannot change
//! their firmware offsets.

use super::vdbe::{vdbe_add_op3, Vdbe};

const P_VDBE_OFFSET: usize = 0x0c;
const SELECT_PRIOR_OFFSET: usize = 0x10;
const SELECT_RESULT_COLUMNS_OFFSET: usize = 0x04;
const SELECT_NEXT_OFFSET: usize = 0x20;
const OP_RESULT_ROW: i32 = 0x3e;
const SELECT_CODEGEN_ADDRESS: usize = 0x0837_9f38;

/// Code-generate one SELECT member and return its first result register.
pub type SelectCodegen = unsafe extern "C" fn(*mut u8, *mut u8, i32, i32, i32) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_select_codegen(
    parse: *mut u8, select: *mut u8, destination: i32, fourth: i32, fifth: i32,
) -> i32 {
    let codegen: SelectCodegen = core::mem::transmute(SELECT_CODEGEN_ADDRESS);
    codegen(parse, select, destination, fourth, fifth)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_select_codegen(
    _parse: *mut u8, _select: *mut u8, _destination: i32, _fourth: i32, _fifth: i32,
) -> i32 {
    panic!("emit_compound_select_rows requires retail helper @ 0x08379f38")
}

#[cfg(target_os = "none")]
const DEFAULT_SELECT_CODEGEN: SelectCodegen = retail_select_codegen;
#[cfg(not(target_os = "none"))]
const DEFAULT_SELECT_CODEGEN: SelectCodegen = missing_select_codegen;

pub static mut SELECT_CODEGEN_OP: SelectCodegen = DEFAULT_SELECT_CODEGEN;

#[inline(always)]
unsafe fn select_codegen_op() -> SelectCodegen {
    core::ptr::read_volatile(core::ptr::addr_of!(SELECT_CODEGEN_OP))
}

#[inline(always)]
unsafe fn target_word(pointer: *const u8, offset: usize) -> u32 {
    (pointer.add(offset) as *const u32).read()
}

/// `FUN_0837a0d4` — original @ 0x0837a0d4 (132 bytes; two direct
/// unconditional outbound `bl` calls).
///
/// For each member of `select`'s `pPrior` chain, invoke `select_codegen` with
/// `(parse, member, destination, 0, 0)`. Unless `enabled` is non-NULL and its
/// zero-based member slot is zero, emit `OP_ResultRow` with `p1 = destination +
/// member_index`, `p2 = returned register`, and `p3 = member.nExpr + 1`.
///
/// # Safety
/// `parse` must provide target-width `Parse.pVdbe` at +0x0c. `select` and all
/// its `pPrior` members must provide target-width links at +0x10/+0x20 and a
/// signed result-column count at +0x04. If non-NULL, `enabled` must contain a
/// u32 for every traversed member.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn emit_compound_select_rows(
    parse: *mut u8, select: *mut u8, destination: i32, enabled: *const u32,
) {
    let vdbe = target_word(parse, P_VDBE_OFFSET) as usize as *mut Vdbe;
    let mut member = target_word(select, SELECT_PRIOR_OFFSET) as usize as *mut u8;
    let mut member_index = 1i32;

    while !member.is_null() {
        if enabled.is_null() || enabled.add(member_index as usize - 1).read() != 0 {
            let first_register = select_codegen_op()(parse, member, destination, 0, 0);
            vdbe_add_op3(
                vdbe,
                OP_RESULT_ROW,
                destination.wrapping_add(member_index),
                first_register,
                (member.add(SELECT_RESULT_COLUMNS_OFFSET) as *const i32).read().wrapping_add(1),
            );
        }
        member = target_word(member, SELECT_NEXT_OFFSET) as usize as *mut u8;
        member_index = member_index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::VdbeOp;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static OPS_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static mut CALLS: [(usize, i32, i32, i32); 3] = [(0, 0, 0, 0); 3];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn recording_codegen(
        _parse: *mut u8, member: *mut u8, destination: i32, fourth: i32, fifth: i32,
    ) -> i32 {
        CALLS[CALL_COUNT] = (member as usize, destination, fourth, fifth);
        CALL_COUNT += 1;
        40 + CALL_COUNT as i32
    }

    unsafe fn fixture() -> Option<(*mut u8, *mut Vdbe, *mut VdbeOp)> {
        let slab = try_map_u32_slab(hints::EMIT_COMPOUND_SELECT_ROWS, 0x1000)?;
        let parse = slab;
        let vdbe = slab.add(0x100).cast::<Vdbe>();
        let ops = slab.add(0x200).cast::<VdbeOp>();
        core::ptr::write_bytes(vdbe, 0, 1);
        (*vdbe).a_op = ops;
        (*vdbe).n_op_alloc = 3;
        (parse.add(P_VDBE_OFFSET) as *mut u32).write(vdbe as usize as u32);
        Some((parse, vdbe, ops))
    }

    #[test]
    fn emits_every_member_with_consecutive_destinations() {
        let _lock = OPS_LOCK.lock();
        unsafe {
            let Some((parse, vdbe, ops)) = fixture() else { return };
            let first = parse.add(0x400);
            let second = parse.add(0x500);
            (parse.add(0x300 + SELECT_PRIOR_OFFSET) as *mut u32).write(first as usize as u32);
            (first.add(SELECT_RESULT_COLUMNS_OFFSET) as *mut i32).write(2);
            (first.add(SELECT_NEXT_OFFSET) as *mut u32).write(second as usize as u32);
            (second.add(SELECT_RESULT_COLUMNS_OFFSET) as *mut i32).write(4);
            SELECT_CODEGEN_OP = recording_codegen;
            CALL_COUNT = 0;
            emit_compound_select_rows(parse, parse.add(0x300), 7, core::ptr::null());
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS[0], (first as usize, 7, 0, 0));
            assert_eq!(CALLS[1], (second as usize, 7, 0, 0));
            assert_eq!((*vdbe).n_op, 2);
            assert_eq!(((*ops).opcode, (*ops).p1, (*ops).p2, (*ops).p3), (62, 8, 41, 3));
            assert_eq!(((*ops.add(1)).opcode, (*ops.add(1)).p1, (*ops.add(1)).p2, (*ops.add(1)).p3), (62, 9, 42, 5));
            SELECT_CODEGEN_OP = DEFAULT_SELECT_CODEGEN;
        }
    }

    #[test]
    fn enabled_mask_skips_only_zero_slots() {
        let _lock = OPS_LOCK.lock();
        unsafe {
            let Some((parse, vdbe, _)) = fixture() else { return };
            let first = parse.add(0x400);
            let second = parse.add(0x500);
            (parse.add(0x300 + SELECT_PRIOR_OFFSET) as *mut u32).write(first as usize as u32);
            (first.add(SELECT_NEXT_OFFSET) as *mut u32).write(second as usize as u32);
            (second.add(SELECT_RESULT_COLUMNS_OFFSET) as *mut i32).write(1);
            let mask = parse.add(0x600).cast::<u32>();
            mask.write(0);
            mask.add(1).write(1);
            SELECT_CODEGEN_OP = recording_codegen;
            CALL_COUNT = 0;
            emit_compound_select_rows(parse, parse.add(0x300), -3, mask);
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(CALLS[0].0, second as usize);
            assert_eq!((*vdbe).n_op, 1);
            SELECT_CODEGEN_OP = DEFAULT_SELECT_CODEGEN;
        }
    }
}
