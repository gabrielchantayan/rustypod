//! `controller_mark_pending_and_dispatch` — original: `FUN_08284c2c` @
//! `0x08284c2c` (12 bytes).
//!
//! Raw `osos.dec` establishes the three-instruction extent: `mov r1,#1`,
//! `strb r1,[r0,#0x5c]`, then a tail branch to `0x08285708`; the next real
//! function begins with `push {r4-r8,lr}` at `0x08284c38`. There are no
//! internal plain or predicated `bl` instructions. A full raw ARM branch scan
//! finds three inbound plain `bl` calls (`0x08284b14`, `0x08284b64`, and
//! `0x0828550c`) and no predicated calls.
//!
//! # Algorithm
//!
//! Sets the controller's pending byte at ARM offset `0x5c`, then tail-enters
//! the shared controller dispatcher at `0x08285708`, preserving its incoming
//! `r1` dispatch mode and returning the dispatcher's result.
//!
//! # Deliberate deviations
//!
//! The dispatcher has no established symbolic identity and is not separately
//! ported. The ARM port uses a literal veneer to its verified retail address;
//! host builds expose a callback seam for its observable tail-call edge.

/// ABI of the unported shared controller dispatcher at `0x08285708`.
pub type ControllerDispatch = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_controller_dispatch(_controller: *mut u8, _mode: u32) -> u32 {
    0
}

/// Host-only callback replacing the tail call to the retail dispatcher.
#[cfg(not(target_arch = "arm"))]
pub static mut CONTROLLER_DISPATCH: ControllerDispatch = missing_controller_dispatch;

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_mark_pending_and_dispatch(
    controller: *mut u8,
    dispatch_mode: u32,
) -> u32 {
    controller.add(0x5c).write_volatile(1);
    core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_DISPATCH))(controller, dispatch_mode)
}

// The retail body tail-branches to a separately linked function. A literal
// veneer leaves that edge valid after this port is linked into the payload.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl controller_mark_pending_and_dispatch
    .type controller_mark_pending_and_dispatch, %function
controller_mark_pending_and_dispatch:
    mov     r1, #1
    strb    r1, [r0, #0x5c]
    b       retail_controller_dispatch
    .size controller_mark_pending_and_dispatch, . - controller_mark_pending_and_dispatch

retail_controller_dispatch:
    ldr     pc, [pc, #-4]
    .word   0x08285708
    .size retail_controller_dispatch, . - retail_controller_dispatch
"#
);

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_ARGS: (*mut u8, u32) = (core::ptr::null_mut(), 0);
    static mut DISPATCH_RESULT: u32 = 0;

    unsafe extern "C" fn recording_dispatch(controller: *mut u8, mode: u32) -> u32 {
        DISPATCH_ARGS = (controller, mode);
        DISPATCH_RESULT
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                CONTROLLER_DISPATCH = missing_controller_dispatch;
                DISPATCH_ARGS = (core::ptr::null_mut(), 0);
                DISPATCH_RESULT = 0;
            }
        }
    }

    #[test]
    fn marks_pending_byte_and_forwards_dispatch_mode() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        let mut controller = [0xa5u8; 0x60];
        unsafe {
            CONTROLLER_DISPATCH = recording_dispatch;
            DISPATCH_RESULT = 0x7e57_1ed0;
            assert_eq!(
                controller_mark_pending_and_dispatch(controller.as_mut_ptr(), 0xfeed_beef),
                DISPATCH_RESULT,
            );
            assert_eq!(DISPATCH_ARGS, (controller.as_mut_ptr(), 0xfeed_beef));
        }
        assert_eq!(controller[0x5c], 1);
        assert_eq!(controller[0x5b], 0xa5);
        assert_eq!(controller[0x5d], 0xa5);
    }
}
