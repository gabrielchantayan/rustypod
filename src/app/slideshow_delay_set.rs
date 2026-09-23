//! `slideshow_delay_set` — original: `FUN_081cd2d8` @ `0x081cd2d8`
//! (**24 instruction bytes**, `0x081cd2d8..0x081cd2ef`; the two literal words
//! at `0x081cd2f0` and `0x081cd2f4` are followed by the next real function at
//! `0x081cd2f8`).
//!
//! Raw A32 decoding finds three inbound plain unconditional `bl` calls
//! (`0x0810d690`, `0x081ccb54`, and `0x081cd4d8`) and no predicated `bl` calls.
//! The body has no direct `bl`: after storing the delay at `state+0x8c8`, it
//! tail-dispatches vtable slot `+0x58` with message `(0x848e, 0x53747220)`.
//!
//! # Deliberate deviations
//!
//! The vtable callee has no recovered semantic identity. ARM retains the exact
//! target-width virtual dispatch; the host build uses a narrow recording seam.

const DELAY_OFFSET: usize = 0x8c8;
const MESSAGE_CATEGORY: u32 = 0x848e;
const MESSAGE_NAME: u32 = 0x5374_7220;

pub type SlideshowMessageDispatch = unsafe extern "C" fn(*mut u8, u32, u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_slideshow_message_dispatch(_: *mut u8, _: u32, _: u32) {}

/// Host replacement for the slideshow state vtable's `+0x58` dispatch slot.
#[cfg(not(target_arch = "arm"))]
pub static mut SLIDESHOW_MESSAGE_DISPATCH: SlideshowMessageDispatch = missing_slideshow_message_dispatch;

/// Stores a slideshow delay and dispatches its fixed resource notification.
///
/// # Safety
/// `state` must point to writable, four-byte-aligned target-layout storage at
/// `+0x8c8`. On ARM, its vtable's `+0x58` slot must accept `(state, u32, u32)`.
#[cfg(not(target_arch = "arm"))]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slideshow_delay_set(state: *mut u8, delay: u32) {
    unsafe { state.add(DELAY_OFFSET).cast::<u32>().write(delay) };
    let dispatch = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(SLIDESHOW_MESSAGE_DISPATCH))
    };
    unsafe { dispatch(state, MESSAGE_CATEGORY, MESSAGE_NAME) };
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl slideshow_delay_set
    .type slideshow_delay_set, %function
slideshow_delay_set:
    str     r1, [r0, #0x8c8]
    ldr     r1, [r0]
    ldr     r2, [pc, #8]
    ldr     r3, [r1, #0x58]
    ldr     r1, [pc, #4]
    bx      r3
    .word   0x0000848e
    .word   0x53747220
    .size slideshow_delay_set, . - slideshow_delay_set
"#
);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::Mutex;

    const STATE_BYTES: usize = DELAY_OFFSET + 4;
    #[repr(align(4))]
    struct State([u8; STATE_BYTES]);

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_ARGS: (*mut u8, u32, u32) = (core::ptr::null_mut(), 0, 0);

    unsafe extern "C" fn record_dispatch(state: *mut u8, category: u32, name: u32) {
        unsafe { addr_of_mut!(DISPATCH_ARGS).write((state, category, name)) };
    }

    #[test]
    fn stores_full_delay_word_before_dispatching_fixed_message() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut state = State([0xa5; STATE_BYTES]);
        unsafe {
            addr_of_mut!(DISPATCH_ARGS).write((core::ptr::null_mut(), 0, 0));
            addr_of_mut!(SLIDESHOW_MESSAGE_DISPATCH).write(record_dispatch);
            slideshow_delay_set(state.0.as_mut_ptr(), 0xfedc_ba98);
            assert_eq!(state.0.as_ptr().add(DELAY_OFFSET).cast::<u32>().read(), 0xfedc_ba98);
            assert_eq!(addr_of!(DISPATCH_ARGS).read(), (state.0.as_mut_ptr(), MESSAGE_CATEGORY, MESSAGE_NAME));
        }
    }
}
