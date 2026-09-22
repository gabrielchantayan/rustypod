//! Builds a Q16.16 transform from three coordinate pairs, then applies it.

use super::fixed_matrix_identity::FixedMatrix4x4;
#[cfg(not(target_arch = "arm"))]
use super::matrix_state_apply_transform::{matrix_state_apply_transform, MatrixState};
#[cfg(not(target_arch = "arm"))]
use core::ptr::addr_of;

/// ABI of the unported transform constructor at `0x08256d98`.
pub type FixedMatrixFromSixCoordinates = unsafe extern "C" fn(
    matrix: *mut FixedMatrix4x4,
    first_start: i32,
    first_end: i32,
    second_start: i32,
    second_end: i32,
    third_start: i32,
    third_end: i32,
);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_fixed_matrix_from_six_coordinates(
    _matrix: *mut FixedMatrix4x4,
    _first_start: i32,
    _first_end: i32,
    _second_start: i32,
    _second_end: i32,
    _third_start: i32,
    _third_end: i32,
) {
}

/// Host seam for the stock transform constructor.
#[cfg(not(target_arch = "arm"))]
static mut FIXED_MATRIX_FROM_SIX_COORDINATES: FixedMatrixFromSixCoordinates =
    missing_fixed_matrix_from_six_coordinates;

/// matrix_state_apply_six_coordinate_transform — original: `FUN_082540dc` @
/// **0x082540dc** (76 bytes, `0x082540dc..0x08254128`; raw decoding confirms
/// that the next separately linked entry begins at `0x08254128`).
///
/// Whole-image A32 branch decoding finds three direct inbound `bl` calls:
/// unconditional plain `bl` at `0x082540d4` and `0x082d1d40`, plus predicated
/// `blge` at `0x089ede4c`. The body has two unconditional outgoing `bl` calls
/// and no predicated outgoing calls. It allocates a 0x44-byte Q16.16 matrix,
/// delegates construction from three signed coordinate pairs to the separately
/// linked, unported routine at `0x08256d98`, then applies that matrix to
/// `state` through `matrix_state_apply_transform`.
///
/// Deliberate deviation: the constructor has no recovered identity beyond its
/// observed inputs and output, so the ARM build retains its literal retail
/// veneer and host builds expose it as a seam.
///
/// # Safety
///
/// `state` must be non-NULL, four-byte aligned, and valid for the delegated
/// matrix-state operation. The retail code performs no validation.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn matrix_state_apply_six_coordinate_transform(
    state: *mut MatrixState,
    first_start: i32,
    first_end: i32,
    second_start: i32,
    second_end: i32,
    third_start: i32,
    third_end: i32,
) {
    let mut matrix = core::mem::MaybeUninit::<FixedMatrix4x4>::uninit();
    core::ptr::read_volatile(addr_of!(FIXED_MATRIX_FROM_SIX_COORDINATES))(
        matrix.as_mut_ptr(),
        first_start,
        first_end,
        second_start,
        second_end,
        third_start,
        third_end,
    );
    matrix_state_apply_transform(state, matrix.as_ptr());
}

// The raw ARM body retains the stack layout and the literal veneer for its
// unported constructor. The ported matrix-state routine is called directly.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl matrix_state_apply_six_coordinate_transform
    .type matrix_state_apply_six_coordinate_transform, %function
matrix_state_apply_six_coordinate_transform:
    push    {{r4, lr}}
    sub     sp, sp, #80
    mov     lr, r3
    mov     r4, r0
    mov     r0, r1
    add     r3, sp, #88
    mov     ip, r2
    ldm     r3, {{r1, r2, r3}}
    stm     sp, {{r1, r2, r3}}
    mov     r1, r0
    add     r0, sp, #12
    mov     r3, lr
    mov     r2, ip
    bl      retail_fixed_matrix_from_six_coordinates
    add     r1, sp, #12
    mov     r0, r4
    bl      matrix_state_apply_transform
    add     sp, sp, #80
    pop     {{r4, pc}}
    .size matrix_state_apply_six_coordinate_transform, . - matrix_state_apply_six_coordinate_transform

retail_fixed_matrix_from_six_coordinates:
    ldr     pc, [pc, #-4]
    .word   0x08256d98
"#
);

#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) static MATRIX_STATE_APPLY_SIX_COORDINATE_TRANSFORM_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::{mem::MaybeUninit, ptr::addr_of_mut};
    use std::sync::MutexGuard;

    static mut SEEN_MATRIX: *mut FixedMatrix4x4 = core::ptr::null_mut();
    static mut SEEN_COORDINATES: [i32; 6] = [0; 6];

    unsafe extern "C" fn record_constructor(
        matrix: *mut FixedMatrix4x4,
        first_start: i32,
        first_end: i32,
        second_start: i32,
        second_end: i32,
        third_start: i32,
        third_end: i32,
    ) {
        SEEN_MATRIX = matrix;
        SEEN_COORDINATES = [first_start, first_end, second_start, second_end, third_start, third_end];
        (*matrix).elements = [0x1234_5678; 16];
        (*matrix).is_identity = 0;
    }

    struct Reset(FixedMatrixFromSixCoordinates);

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                FIXED_MATRIX_FROM_SIX_COORDINATES = self.0;
                SEEN_MATRIX = core::ptr::null_mut();
                SEEN_COORDINATES = [0; 6];
            }
        }
    }

    #[test]
    fn constructs_and_applies_all_three_coordinate_pairs_in_order() {
        let _guard: MutexGuard<'static, ()> = MATRIX_STATE_APPLY_SIX_COORDINATE_TRANSFORM_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old = unsafe { core::ptr::read_volatile(addr_of!(FIXED_MATRIX_FROM_SIX_COORDINATES)) };
        let _reset = Reset(old);
        unsafe { core::ptr::write_volatile(addr_of_mut!(FIXED_MATRIX_FROM_SIX_COORDINATES), record_constructor) };
        let Some(matrix_slab) = try_map_u32_slab(hints::MATRIX_STATE_APPLY_SIX_COORDINATE_TRANSFORM, 0x44) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        let mut state = MaybeUninit::<MatrixState>::zeroed();
        unsafe { (*state.as_mut_ptr()).active_matrix = matrix_slab as usize as u32 };

        unsafe {
            matrix_state_apply_six_coordinate_transform(state.as_mut_ptr(), -1, 2, -3, 4, i32::MIN, i32::MAX);
            assert_ne!(SEEN_MATRIX, core::ptr::null_mut());
            assert_eq!(SEEN_COORDINATES, [-1, 2, -3, 4, i32::MIN, i32::MAX]);
            assert_eq!((*SEEN_MATRIX).elements, [0x1234_5678; 16]);
            assert_eq!((*SEEN_MATRIX).is_identity, 0);
        }
    }
}
