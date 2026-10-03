//! Matrix-transform emission dispatcher — `FUN_08246fac` @ 0x08246fac.
//!
//! Raw A32 extent: 120 bytes, 0x08246fac..0x08247024, with no literal
//! pool; the next instruction is an independent push prologue. Whole-image
//! decoding verifies two inbound plain BLs (0x082466cc, 0x08246710), zero
//! predicated inbound BLs. The body contains three plain BLs, zero predicated
//! BLs. Dimensions 2, 3 and 4 select the corresponding four-row matrix
//! transform emitter, forwarding the seven emission arguments unchanged.
//! The 2/3-component paths include the matrix's translation column; the
//! 4-component path multiplies all four columns. Other dimensions do nothing.
//!
//! Deliberate deviations: unported emitters remain literal retailOS veneers
//! on ARM, with explicitly installed host callbacks (no simulated emitter).
//! LLVM may tail-call these void helpers instead of retaining ADS's frame.

use super::ir::{CgBlock, CgVirtualReg};

pub type MatrixTransformEmitter = unsafe extern "C" fn(
    *mut u8, *mut CgBlock, *mut CgVirtualReg, *mut CgVirtualReg,
    u32, *mut CgVirtualReg, u32,
);

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_cg_emit_matrix_transform2(ctx: *mut u8, block: *mut CgBlock, source: *mut CgVirtualReg, destination: *mut CgVirtualReg, offset: u32, matrix: *mut CgVirtualReg, source_type: u32);
    fn retail_cg_emit_matrix_transform3(ctx: *mut u8, block: *mut CgBlock, source: *mut CgVirtualReg, destination: *mut CgVirtualReg, offset: u32, matrix: *mut CgVirtualReg, source_type: u32);
    fn retail_cg_emit_matrix_transform4(ctx: *mut u8, block: *mut CgBlock, source: *mut CgVirtualReg, destination: *mut CgVirtualReg, offset: u32, matrix: *mut CgVirtualReg, source_type: u32);
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_cg_emit_matrix_transform2
retail_cg_emit_matrix_transform2:
    ldr pc, [pc, #-4]
    .word 0x08247024
    .globl retail_cg_emit_matrix_transform3
retail_cg_emit_matrix_transform3:
    ldr pc, [pc, #-4]
    .word 0x082471ac
    .globl retail_cg_emit_matrix_transform4
retail_cg_emit_matrix_transform4:
    ldr pc, [pc, #-4]
    .word 0x082473c4
"#);

#[cfg(not(target_arch = "arm"))]
pub static mut CG_MATRIX_TRANSFORM_EMITTERS: [Option<MatrixTransformEmitter>; 3] = [None; 3];

/// Emit a four-row transform for a 2-, 3-, or 4-component source vector.
///
/// # Safety
/// Supported dimensions require arguments valid for the selected retailOS
/// emitter. Host callbacks must be installed without concurrent mutation.
/// Unsupported dimensions do not dereference any argument.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_emit_matrix_transform(
    ctx: *mut u8,
    block: *mut CgBlock,
    source: *mut CgVirtualReg,
    destination: *mut CgVirtualReg,
    offset: u32,
    matrix: *mut CgVirtualReg,
    source_type: u32,
    components: u32,
) {
    #[cfg(target_arch = "arm")]
    let emitter: MatrixTransformEmitter = match components {
        2 => retail_cg_emit_matrix_transform2,
        3 => retail_cg_emit_matrix_transform3,
        4 => retail_cg_emit_matrix_transform4,
        _ => return,
    };
    #[cfg(not(target_arch = "arm"))]
    let emitter = match components {
        2..=4 => CG_MATRIX_TRANSFORM_EMITTERS[(components - 2) as usize]
            .expect("install the host matrix-transform emitter"),
        _ => return,
    };
    emitter(ctx, block, source, destination, offset, matrix, source_type);
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_dimensions_leave_arguments_untouched() {
        let mut guards = [0x12345678u32, 0xabcdef01, 0x87654321, 0x10203040];
        let before = guards;
        for components in [0, 1, 5, 6, 0x7fffffff, 0x80000000, u32::MAX] {
            unsafe {
                let p = guards.as_mut_ptr();
                cg_emit_matrix_transform(p.cast(), p.cast(), p.cast(), p.cast(),
                    u32::MAX, p.cast(), u32::MAX, components);
                cg_emit_matrix_transform(core::ptr::null_mut(), core::ptr::null_mut(),
                    core::ptr::null_mut(), core::ptr::null_mut(), 0,
                    core::ptr::null_mut(), 0, components);
            }
            assert_eq!(guards, before);
        }
    }
}
