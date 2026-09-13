//! Applies a Q16.16 transform to a matrix-state object's active matrix.

use super::fixed_matrix_identity::FixedMatrix4x4;
#[cfg(not(target_arch = "arm"))]
use core::ptr::addr_of;

/// Prefix of the opaque matrix-state object used by the transform controller.
///
/// The retail helper reads the active matrix's 32-bit target address from
/// `state + 0x34`. Keeping it as a target-width word avoids host pointer-width
/// layout drift.
#[repr(C)]
pub struct MatrixState {
    words_before_active_matrix: [u32; 13],
    pub active_matrix: u32,
}

const _: [u8; 0x34] = [0; core::mem::offset_of!(MatrixState, active_matrix)];
const _: [u8; 0x38] = [0; core::mem::size_of::<MatrixState>()];

/// ABI of the recovered matrix multiplication helper at `0x08242da4`.
pub type FixedMatrixMultiply = unsafe extern "C" fn(
    destination: *mut FixedMatrix4x4,
    transform: *const FixedMatrix4x4,
);

/// ABI of the separately linked post-multiplication routine at `0x08252124`.
pub type MatrixStateRefresh = unsafe extern "C" fn(state: *mut MatrixState);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_fixed_matrix_multiply(
    _destination: *mut FixedMatrix4x4,
    _transform: *const FixedMatrix4x4,
) {
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_matrix_state_refresh(_state: *mut MatrixState) {}

/// Host seams for the two stock routines reached by the 28-byte wrapper.
///
/// The pointers are volatile-loaded because tests deliberately replace them.
#[cfg(not(target_arch = "arm"))]
static mut FIXED_MATRIX_MULTIPLY: FixedMatrixMultiply = missing_fixed_matrix_multiply;
#[cfg(not(target_arch = "arm"))]
static mut MATRIX_STATE_REFRESH: MatrixStateRefresh = missing_matrix_state_refresh;

/// matrix_state_apply_transform — original: `FUN_0824d548` @ **0x0824d548**
/// (28 bytes, `0x0824d548..0x0824d564`; raw decoding confirms that the next
/// separately linked entry begins at `0x0824d564`).
///
/// Decoding every ARM `B`/`BL` immediate in `osos.dec` finds six direct inbound
/// `bl` calls — `0x0824e068`, `0x0824f31c`, `0x0825411c`, `0x0825418c`,
/// `0x0825478c`, and `0x08254f9c` — all unconditional, with no predicated
/// forms or direct tail `b` callers. The function gets the active matrix from
/// the opaque state object's `+0x34` target pointer, multiplies it by the
/// supplied Q16.16 transform through `0x08242da4`, then tail-enters the
/// separately linked post-multiplication routine at `0x08252124`.
///
/// A data word at `0x089b25a4` also references this entry amid an undecoded
/// dispatch table, so direct-call decoding does not establish the total
/// indirect-call count. No deliberate Rust deviations: target builds retain
/// the exact helper call and tail transfer through relocation-safe veneers;
/// host builds expose those calls as test seams.
///
/// # Safety
///
/// `state` must be non-NULL, four-byte aligned, and contain a live aligned
/// matrix pointer at `+0x34`; `transform` must point to an aligned readable
/// [`FixedMatrix4x4`]. The retail code performs none of these checks.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn matrix_state_apply_transform(
    state: *mut MatrixState,
    transform: *const FixedMatrix4x4,
) {
    let destination = core::ptr::read_volatile(addr_of!((*state).active_matrix)) as usize
        as *mut FixedMatrix4x4;
    core::ptr::read_volatile(addr_of!(FIXED_MATRIX_MULTIPLY))(destination, transform);
    core::ptr::read_volatile(addr_of!(MATRIX_STATE_REFRESH))(state);
}

// The stock body directly calls the unported multiplication helper and tail
// branches to an unported state routine. Literal veneers preserve both targets
// after this function moves into the patch payload.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl matrix_state_apply_transform
    .type matrix_state_apply_transform, %function
matrix_state_apply_transform:
    push    {{r4, lr}}
    mov     r4, r0
    ldr     r0, [r0, #0x34]
    bl      retail_fixed_matrix_multiply
    mov     r0, r4
    pop     {{r4, lr}}
    b       retail_matrix_state_refresh
    .size matrix_state_apply_transform, . - matrix_state_apply_transform

retail_fixed_matrix_multiply:
    ldr     pc, [pc, #-4]
    .word   0x08242da4

retail_matrix_state_refresh:
    ldr     pc, [pc, #-4]
    .word   0x08252124
"#
);

#[cfg(test)]
extern crate std;

#[cfg(test)]
pub(crate) static MATRIX_STATE_APPLY_TRANSFORM_TEST_LOCK: std::sync::Mutex<()> =
    std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr::addr_of_mut;
    use std::sync::MutexGuard;

    static mut SEEN_DESTINATION: *mut FixedMatrix4x4 = core::ptr::null_mut();
    static mut SEEN_TRANSFORM: *const FixedMatrix4x4 = core::ptr::null();
    static mut REFRESHED_STATE: *mut MatrixState = core::ptr::null_mut();
    static mut CALL_ORDER: [u8; 2] = [0; 2];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_multiply(
        destination: *mut FixedMatrix4x4,
        transform: *const FixedMatrix4x4,
    ) {
        SEEN_DESTINATION = destination;
        SEEN_TRANSFORM = transform;
        CALL_ORDER[CALL_COUNT] = 1;
        CALL_COUNT += 1;
    }

    unsafe extern "C" fn record_refresh(state: *mut MatrixState) {
        REFRESHED_STATE = state;
        CALL_ORDER[CALL_COUNT] = 2;
        CALL_COUNT += 1;
    }

    struct Reset {
        old_multiply: FixedMatrixMultiply,
        old_refresh: MatrixStateRefresh,
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                FIXED_MATRIX_MULTIPLY = self.old_multiply;
                MATRIX_STATE_REFRESH = self.old_refresh;
                SEEN_DESTINATION = core::ptr::null_mut();
                SEEN_TRANSFORM = core::ptr::null();
                REFRESHED_STATE = core::ptr::null_mut();
                CALL_ORDER = [0; 2];
                CALL_COUNT = 0;
            }
        }
    }

    unsafe fn arrange() -> Reset {
        let old_multiply = core::ptr::read_volatile(addr_of!(FIXED_MATRIX_MULTIPLY));
        let old_refresh = core::ptr::read_volatile(addr_of!(MATRIX_STATE_REFRESH));
        core::ptr::write_volatile(addr_of_mut!(FIXED_MATRIX_MULTIPLY), record_multiply);
        core::ptr::write_volatile(addr_of_mut!(MATRIX_STATE_REFRESH), record_refresh);
        SEEN_DESTINATION = core::ptr::null_mut();
        SEEN_TRANSFORM = core::ptr::null();
        REFRESHED_STATE = core::ptr::null_mut();
        CALL_ORDER = [0; 2];
        CALL_COUNT = 0;
        Reset { old_multiply, old_refresh }
    }

    #[test]
    fn applies_the_active_matrix_then_refreshes_its_state() {
        let _guard: MutexGuard<'static, ()> = MATRIX_STATE_APPLY_TRANSFORM_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = unsafe { arrange() };
        let Some(matrix_slab) = try_map_u32_slab(hints::MATRIX_STATE_APPLY_TRANSFORM, 0x44) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        let destination = matrix_slab.cast::<FixedMatrix4x4>();
        let transform = FixedMatrix4x4 { elements: [0x1234_5678; 16], is_identity: 0xa5 };
        let mut state = MatrixState {
            words_before_active_matrix: [0; 13],
            active_matrix: destination as usize as u32,
        };

        unsafe { matrix_state_apply_transform(&mut state, &transform) };

        unsafe {
            assert_eq!(SEEN_DESTINATION, destination);
            assert!(SEEN_TRANSFORM == &transform);
            assert!(REFRESHED_STATE == &mut state);
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALL_ORDER, [1, 2]);
        }
    }
}
