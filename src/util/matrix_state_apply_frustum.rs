//! Validates and applies a Q16.16 perspective frustum.

use super::fixed_matrix_identity::FixedMatrix4x4;
use super::matrix_state_apply_transform::MatrixState;
#[cfg(not(target_arch = "arm"))]
use super::matrix_state_apply_transform::matrix_state_apply_transform;
use super::error_latch::latch_first_error;

#[inline]
fn valid_frustum(left: i32, right: i32, bottom: i32, top: i32, near: i32, far: i32) -> bool {
    left != right && bottom != top && near > 0 && far > 0
}

/// ABI recovered from the raw call and constructor at 0x08257140.
type FrustumConstructor = unsafe extern "C" fn(
    *mut FixedMatrix4x4, i32, i32, i32, i32, i32, i32,
);

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    ".syntax unified",
    ".text",
    ".p2align 2",
    ".type retail_frustum_constructor, %function",
    "retail_frustum_constructor:",
    "ldr pc, [pc, #-4]",
    ".word 0x08257140",
    ".size retail_frustum_constructor, . - retail_frustum_constructor",
);

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_frustum_constructor(
        matrix: *mut FixedMatrix4x4,
        left: i32, right: i32, bottom: i32, top: i32, near: i32, far: i32,
    );
    fn matrix_state_apply_transform(state: *mut MatrixState, transform: *const FixedMatrix4x4);
}

/// matrix_state_apply_frustum — FUN_08254f34 @ 0x08254f34.
/// True extent: 116 bytes, 0x08254f34..0x08254fa8, including the 0x501 literal;
/// the next real entry starts at 0x08254fa8. Whole-image A32 decoding finds
/// two inbound plain BLs (0x08254f2c, 0x082d1430), zero predicated BLs.
/// The body has three plain outgoing BLs and zero predicated BLs.
///
/// Reject equal horizontal or vertical bounds and nonpositive near/far planes
/// by latching error 0x501 in the state's first word. Otherwise construct a
/// 0x44-byte Q16.16 perspective matrix with the stock helper at 0x08257140,
/// then apply it with matrix_state_apply_transform. Reversed bounds and equal
/// positive near/far planes are deliberately accepted, just as in retailOS.
///
/// Deliberate deviations: no firmware behavior changes. The unported constructor
/// remains a relocation-safe retail veneer; host valid-path calls require an
/// explicitly supplied constructor via the internal seam rather than pretending
/// to implement the stock routine. Host public calls panic on that unavailable
/// path. Padding in the local matrix remains uninitialized as in the original.
///
/// # Safety
/// `state` must be aligned and writable at its first word; for a valid frustum
/// it must additionally satisfy matrix_state_apply_transform's safety contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn matrix_state_apply_frustum(
    state: *mut MatrixState,
    left: i32, right: i32, bottom: i32, top: i32, near: i32, far: i32,
) {
    #[cfg(target_arch = "arm")]
    let constructor: FrustumConstructor = retail_frustum_constructor;
    #[cfg(not(target_arch = "arm"))]
    let constructor: FrustumConstructor = unavailable_frustum_constructor;
    apply_frustum(state, left, right, bottom, top, near, far, constructor);
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn unavailable_frustum_constructor(
    _: *mut FixedMatrix4x4, _: i32, _: i32, _: i32, _: i32, _: i32, _: i32,
) {
    panic!("the retail frustum constructor at 0x08257140 is unavailable on host");
}

#[inline(always)]
unsafe fn apply_frustum(
    state: *mut MatrixState,
    left: i32, right: i32, bottom: i32, top: i32, near: i32, far: i32,
    constructor: FrustumConstructor,
) {
    if !valid_frustum(left, right, bottom, top, near, far) {
        latch_first_error(state.cast(), 0x501);
        return;
    }
    let mut matrix = core::mem::MaybeUninit::<FixedMatrix4x4>::uninit();
    constructor(matrix.as_mut_ptr(), left, right, bottom, top, near, far);
    matrix_state_apply_transform(state, matrix.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_matches_conditional_arm_flags_at_signed_boundaries() {
        let values = [i32::MIN, -1, 0, 1, i32::MAX];
        for left in values { for right in values {
            for bottom in values { for top in values {
                for near in values { for far in values {
                    // CMPNE chains preserve Z on equal bounds; CMPGT only
                    // executes after a strictly positive near-plane comparison.
                    let mut z = left == right;
                    if !z { z = bottom == top; }
                    let mut positive = false;
                    if !z { z = near == 0; positive = near > 0; }
                    if positive { z = far == 0; positive = far > 0; }
                    assert_eq!(valid_frustum(left, right, bottom, top, near, far),
                               !z && positive);
                }}
            }}
        }}
    }

    #[test]
    fn rejected_frusta_latch_error_without_touching_state_tail() {
        for bounds in [(1, 1, 0, 1, 1, 2), (0, 1, -1, -1, 1, 2),
                       (0, 1, 0, 1, 0, 2), (0, 1, 0, 1, -1, 2),
                       (0, 1, 0, 1, 1, 0), (0, 1, 0, 1, 1, i32::MIN)] {
            for error in [0, 0x500, u32::MAX] {
                let mut state = [0xa5a5_a5a5u32; 14];
                state[0] = error;
                unsafe { matrix_state_apply_frustum(state.as_mut_ptr().cast(),
                    bounds.0, bounds.1, bounds.2, bounds.3, bounds.4, bounds.5); }
                assert_eq!(state[0], if error == 0 { 0x501 } else { error });
                assert_eq!(&state[1..], &[0xa5a5_a5a5; 13]);
            }
        }
    }
}
