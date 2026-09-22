//! Access to the shared input-feedback controller.
//!
//! `input_feedback_controller_get` — original: `FUN_08294d98` @
//! **0x08294d98** (**12 bytes**, **3 direct `bl` call sites**, all
//! unconditional; no predicated `bl`). Raw ARM is `ldr r0,[pc,#4]; ldr
//! r0,[r0,#0x10]; bx lr`; its literal at 0x08294da4 is 0x089d049c, so it
//! returns the runtime-owned controller word at 0x089d04ac as-is. The next
//! independently entered function starts at 0x08294da8. No construction,
//! NULL guard, or validation occurs.
//!
//! The shared global also contains the input-feedback adjustment halfword at
//! `+0x04`, used by [`super::input_delta_feedback_update`], and each direct
//! caller uses the returned object's state fields. This establishes the
//! controller role without inventing its concrete class. Deliberate host
//! deviation: the firmware's 32-bit pointer field is represented by a
//! native-width static pointer so 64-bit test fixtures remain valid.

/// Native-width host model of the firmware's 32-bit controller pointer field
/// at `0x089d049c + 0x10`.
#[cfg(not(target_os = "none"))]
static mut HOST_INPUT_FEEDBACK_CONTROLLER: *mut u8 = core::ptr::null_mut();

/// Returns the current input-feedback controller without constructing or
/// validating it.
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn input_feedback_controller_get() -> *mut u8 {
    unsafe { core::ptr::addr_of!(HOST_INPUT_FEEDBACK_CONTROLLER).read_volatile() }
}

// Keep the exact three-word retail accessor and its literal pool: a direct
// Rust load would fold the +0x10 offset into the literal and add a frame.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    ".section .text.input_feedback_controller_get,\"ax\",%progbits",
    ".global input_feedback_controller_get",
    ".type input_feedback_controller_get,%function",
    "input_feedback_controller_get:",
    "ldr r0,[pc,#4]",
    "ldr r0,[r0,#0x10]",
    "bx lr",
    ".word 0x089d049c",
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ACCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct ControllerReset;

    impl Drop for ControllerReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HOST_INPUT_FEEDBACK_CONTROLLER)
                    .write(core::ptr::null_mut());
            }
        }
    }

    fn install_empty_controller_slot() -> MutexGuard<'static, ()> {
        let guard = ACCESS_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(HOST_INPUT_FEEDBACK_CONTROLLER).write(core::ptr::null_mut());
        }
        guard
    }

    #[test]
    fn returns_null_before_controller_initialization() {
        let _guard = install_empty_controller_slot();
        let _reset = ControllerReset;

        assert!(unsafe { input_feedback_controller_get() }.is_null());
    }

    #[test]
    fn loads_the_current_controller_global_word() {
        let _guard = install_empty_controller_slot();
        let _reset = ControllerReset;
        let mut first = [0u32; 1];
        let mut second = [0u32; 1];

        unsafe {
            core::ptr::addr_of_mut!(HOST_INPUT_FEEDBACK_CONTROLLER).write(first.as_mut_ptr().cast());
            assert_eq!(input_feedback_controller_get(), first.as_mut_ptr().cast());

            core::ptr::addr_of_mut!(HOST_INPUT_FEEDBACK_CONTROLLER).write(second.as_mut_ptr().cast());
            assert_eq!(input_feedback_controller_get(), second.as_mut_ptr().cast());
        }
    }
}
