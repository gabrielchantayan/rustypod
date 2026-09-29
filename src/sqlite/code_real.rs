//! code_real — original: `FUN_082c40b0` @ 0x082c40b0 (156 bytes).
//!
//! Raw `osos.dec` establishes the complete A32 body at
//! `0x082c40b0..0x082c414c`; `push {r4-r11,lr}` at `0x082c414c` begins the
//! next independent function. Whole-image immediate-branch decoding finds two
//! inbound plain `bl` sites (0x082c4030 and 0x08377454) and no predicated
//! `bl` sites. The body has five plain outbound `bl` instructions and no
//! predicated calls: `sqlite3AtoF`, `sqlite_is_nan`, `vdbe_add_op3`,
//! `alloc_i64_copy`, and `vdbe_add_op4`.
//! Algorithm: ignore a NULL literal. Otherwise parse it as binary64; a NaN
//! emits `OP_Halt` (0x71) with `target` in P2. For every other value, apply
//! the requested sign, allocate an owned eight-byte copy, then emit `OP_Real`
//! (0x7d) with that copy as dynamic P4 (-12).
//!
//! Deliberate deviations: the established `VDBE_REAL_VALUE_OPS` seam supplies
//! the unported `sqlite3AtoF`; all other callees are direct Rust ports. Rust
//! flips the binary64 sign bit explicitly rather than operating on the stack
//! word holding the high half of the original's temporary.

use super::alloc_i64_copy::alloc_i64_copy;
use super::is_nan::sqlite_is_nan;
use super::vdbe::{vdbe_add_op3, vdbe_add_op4, Vdbe, P4_REAL};
use super::vdbe_real_value::sqlite_atof;

const OP_HALT: i32 = 0x71;
const OP_REAL: i32 = 0x7d;

/// Emits bytecode for a floating-point SQL literal.
///
/// `literal_len` is intentionally unused: retailOS receives it in r2 but
/// never reads it. `target` is the destination register for the emitted op.
///
/// # Safety
///
/// When non-NULL, `literal` must name a NUL-terminated numeric string. `vdbe`
/// must point to a writable VDBE accepted by the emitted-operation helpers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.code_real_082c40b0")]
#[inline(never)]
pub unsafe extern "C" fn code_real(
    vdbe: *mut Vdbe,
    literal: *const u8,
    _literal_len: u32,
    negate: i32,
    target: i32,
) {
    if literal.is_null() {
        return;
    }

    let mut value = 0.0;
    unsafe { sqlite_atof(literal, &mut value) };
    if sqlite_is_nan(value) != 0 {
        unsafe { vdbe_add_op3(vdbe, OP_HALT, 0, target, 0) };
        return;
    }

    if negate != 0 {
        value = f64::from_bits(value.to_bits() ^ 0x8000_0000_0000_0000);
    }
    let copy = unsafe { alloc_i64_copy(vdbe.cast(), (&value as *const f64).cast()) };
    unsafe { vdbe_add_op4(vdbe, OP_REAL, 0, target, 0, copy, P4_REAL) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use crate::sqlite::mem::tests::install_recorder;
    use crate::sqlite::vdbe::VdbeOp;
    use crate::sqlite::vdbe_real_value::{test_support::VDBE_REAL_VALUE_OPS_LOCK, VdbeRealValueOps, VDBE_REAL_VALUE_OPS};

    static mut PARSED_VALUE: f64 = 0.0;

    unsafe extern "C" fn parser(_literal: *const u8, out: *mut f64) -> i32 {
        out.write(*core::ptr::addr_of!(PARSED_VALUE));
        0
    }

    unsafe fn install_parser(value: f64) -> VdbeRealValueOps {
        *core::ptr::addr_of_mut!(PARSED_VALUE) = value;
        let old = core::ptr::read_volatile(core::ptr::addr_of!(VDBE_REAL_VALUE_OPS));
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(VDBE_REAL_VALUE_OPS),
            VdbeRealValueOps { atof: parser, ..old },
        );
        old
    }
    unsafe fn vdbe_with_ops(ops: &mut [VdbeOp; 2], db: *mut u8) -> Vdbe {
        let mut vdbe: Vdbe = core::mem::zeroed();
        vdbe.db = db;
        vdbe.a_op = ops.as_mut_ptr();
        vdbe.n_op_alloc = ops.len() as i32;
        vdbe
    }

    #[test]
    fn finite_literal_negates_and_emits_owned_real() {
        let Some(db) = try_map_u32_slab(hints::SQLITE_CODE_REAL_FINITE, 0x40) else {
            return;
        };
        unsafe { core::ptr::write_bytes(db.cast::<u8>(), 0, 0x40) };
        let _ops_guard = VDBE_REAL_VALUE_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let old = unsafe { install_parser(12.5) };
        let mut allocation = [0xa5; 8];
        let _allocator_guard = install_recorder(allocation.as_mut_ptr());
        let mut ops: [VdbeOp; 2] = unsafe { core::mem::zeroed() };
        let mut vdbe = unsafe { vdbe_with_ops(&mut ops, db.cast()) };

        unsafe { code_real(&mut vdbe, b"12.5\0".as_ptr(), 99, 1, 7) };

        assert_eq!(vdbe.n_op, 1);
        assert_eq!(ops[0].opcode, OP_REAL as u8);
        assert_eq!((ops[0].p1, ops[0].p2, ops[0].p3, ops[0].p4type), (0, 7, 0, P4_REAL as i8));
        assert_eq!(f64::from_ne_bytes(allocation), -12.5);
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(VDBE_REAL_VALUE_OPS), old) };
    }

    #[test]
    fn nan_emits_halt_without_allocating_a_real_payload() {
        let Some(db) = try_map_u32_slab(hints::SQLITE_CODE_REAL_NAN, 0x40) else {
            return;
        };
        unsafe { core::ptr::write_bytes(db.cast::<u8>(), 0, 0x40) };
        let _ops_guard = VDBE_REAL_VALUE_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let old = unsafe { install_parser(f64::NAN) };
        let mut ops: [VdbeOp; 2] = unsafe { core::mem::zeroed() };
        let mut vdbe = unsafe { vdbe_with_ops(&mut ops, db.cast()) };

        unsafe { code_real(&mut vdbe, b"NaN\0".as_ptr(), 0, 0, 11) };

        assert_eq!(vdbe.n_op, 1);
        assert_eq!((ops[0].opcode, ops[0].p1, ops[0].p2, ops[0].p3), (OP_HALT as u8, 0, 11, 0));
        assert!(ops[0].p4.is_null());
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(VDBE_REAL_VALUE_OPS), old) };
    }

    #[test]
    fn null_literal_leaves_the_vdbe_unchanged() {
        let mut ops: [VdbeOp; 2] = unsafe { core::mem::zeroed() };
        let mut vdbe = unsafe { vdbe_with_ops(&mut ops, core::ptr::null_mut()) };

        unsafe { code_real(&mut vdbe, core::ptr::null(), 0, 1, 3) };

        assert_eq!(vdbe.n_op, 0);
    }
}
