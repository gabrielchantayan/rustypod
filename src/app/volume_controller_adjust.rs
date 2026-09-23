//! `volume_controller_adjust` — original: `FUN_081f9120` @ **0x081f9120**.
//!
//! The true extent is **16 bytes**, `0x081f9120..0x081f9130`: `cmp`, a
//! predicated absolute-value `rsble`, and two branches. `0x081f9130` is the
//! next real function (`push {r4-r8,lr}`), not part of this entry despite
//! Ghidra's 212-byte extent. Raw ARM decoding finds **3 direct plain `bl`**
//! callers (`0x0810caf8`, `0x0821e6e4`, `0x0821ff0c`) and **0 predicated `bl`**
//! callers.
//!
//! # Algorithm
//!
//! For a non-positive signed wheel delta, negate the delta when negative and
//! tail-branch to the retail lower-bound handler at `0x081f9c34`. For a positive
//! delta, tail-branch unchanged to the upper-bound handler at `0x081f9bc8`.
//! The apparent fall-through body is a separately linked routine.
//!
//! # Deliberate deviations
//!
//! Host builds expose the two verified tail targets as seams. Target builds use
//! the original ARM instruction sequence and absolute veneers, preserving the
//! tail-call ABI without inventing either handler's identity.

#[cfg(not(target_os = "none"))]
pub type VolumeAdjustTail = unsafe extern "C" fn(*mut u8, i32) -> u32;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct VolumeControllerAdjustOps {
    pub lower_bound_handler: VolumeAdjustTail,
    pub upper_bound_handler: VolumeAdjustTail,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_tail(_: *mut u8, _: i32) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
pub const DEFAULT_VOLUME_CONTROLLER_ADJUST_OPS: VolumeControllerAdjustOps = VolumeControllerAdjustOps {
    lower_bound_handler: missing_tail,
    upper_bound_handler: missing_tail,
};

#[cfg(not(target_os = "none"))]
pub static mut VOLUME_CONTROLLER_ADJUST_OPS: VolumeControllerAdjustOps = DEFAULT_VOLUME_CONTROLLER_ADJUST_OPS;

/// Dispatches a signed wheel delta to the retail lower- or upper-bound path.
///
/// # Safety
/// `controller` must meet the selected retail tail handler's requirements.
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn volume_controller_adjust(controller: *mut u8, delta: i32) -> u32 {
    let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(VOLUME_CONTROLLER_ADJUST_OPS)) };
    if delta <= 0 {
        unsafe { (ops.lower_bound_handler)(controller, delta.wrapping_neg()) }
    } else {
        unsafe { (ops.upper_bound_handler)(controller, delta) }
    }
}

#[cfg(target_os = "none")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl volume_controller_adjust
    .type volume_controller_adjust, %function
volume_controller_adjust:
    cmp     r1, #0
    rsble   r1, r1, #0
    ble     retail_volume_adjust_lower_bound
    bgt     retail_volume_adjust_upper_bound
    .size volume_controller_adjust, . - volume_controller_adjust
retail_volume_adjust_lower_bound:
    ldr     pc, [pc, #-4]
    .word   0x081f9c34
retail_volume_adjust_upper_bound:
    ldr     pc, [pc, #-4]
    .word   0x081f9bc8
"#);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
    static LOWER: AtomicI32 = AtomicI32::new(-1);
    static UPPER: AtomicI32 = AtomicI32::new(-1);
    static CONTROLLER: AtomicU32 = AtomicU32::new(0);
    unsafe extern "C" fn lower(controller: *mut u8, delta: i32) -> u32 { CONTROLLER.store(controller as usize as u32, Ordering::Relaxed); LOWER.store(delta, Ordering::Relaxed); 1 }
    unsafe extern "C" fn upper(_: *mut u8, delta: i32) -> u32 { UPPER.store(delta, Ordering::Relaxed); 2 }
    #[test]
    fn normalizes_nonpositive_deltas_and_preserves_positive_deltas() {
        unsafe { VOLUME_CONTROLLER_ADJUST_OPS = VolumeControllerAdjustOps { lower_bound_handler: lower, upper_bound_handler: upper }; }
        let controller = 0x1234usize as *mut u8;
        assert_eq!(unsafe { volume_controller_adjust(controller, -7) }, 1);
        assert_eq!(LOWER.load(Ordering::Relaxed), 7);
        assert_eq!(CONTROLLER.load(Ordering::Relaxed), 0x1234);
        assert_eq!(unsafe { volume_controller_adjust(controller, 0) }, 1);
        assert_eq!(LOWER.load(Ordering::Relaxed), 0);
        assert_eq!(unsafe { volume_controller_adjust(controller, 9) }, 2);
        assert_eq!(UPPER.load(Ordering::Relaxed), 9);
    }
    #[test]
    fn minimum_delta_wraps_like_arm_rsb() {
        unsafe { VOLUME_CONTROLLER_ADJUST_OPS = VolumeControllerAdjustOps { lower_bound_handler: lower, upper_bound_handler: upper }; }
        unsafe { volume_controller_adjust(core::ptr::null_mut(), i32::MIN) };
        assert_eq!(LOWER.load(Ordering::Relaxed), i32::MIN);
    }
}
