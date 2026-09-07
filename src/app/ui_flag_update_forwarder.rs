//! `ui_flag_update_forwarder` — original: `thunk_FUN_0819f604` @
//! `0x082879b0` (4 bytes: `eafc5f13`, a direct tail `b 0x0819f604`).
//!
//! # Verified call sites
//!
//! A raw scan of every ARM `B`/`BL` word in `osos.dec` finds **21 direct
//! `bl` callers** to the thunk: 19 unconditional and two `blne`
//! (`0x081ecb7c`, `0x081ecf74`). It also finds seven tail transfers: six
//! unconditional `b` instructions and one `bne` at `0x08289c10`. The
//! predication gates the caller's update path; the thunk itself has no guard.
//!
//! # Algorithm
//!
//! The thunk preserves `r0` and `r1`, then tail-branches to the 304-byte body
//! at `0x0819f604`. That body conditionally updates its selected UI object's
//! byte at `+0x64` from `r1` and emits two framework notifications. Its
//! identity is not otherwise inferred here: this port is only the verified
//! forwarding entry at `0x082879b0`.
//!
//! # Deliberate deviations
//!
//! The payload cannot retain the stock PC-relative branch. ARM builds replace
//! it with a literal veneer that tail-enters the same retailOS body. Host
//! builds use a volatile callback seam to prove the complete two-word ABI and
//! return value without mapping the retailOS address.

/// ABI of the unported UI flag-update body at `0x0819f604`.
pub type UiFlagUpdateBody = unsafe extern "C" fn(object: *mut u8, flag: u32) -> u32;

/// RetailOS load address reached by the stock tail branch.
pub const UI_FLAG_UPDATE_BODY_ADDRESS: usize = 0x0819_f604;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_ui_flag_update_body(_object: *mut u8, _flag: u32) -> u32 {
    0
}

/// Host callback replacing the retailOS body at [`UI_FLAG_UPDATE_BODY_ADDRESS`].
///
/// It is read volatily so test replacements cannot be folded away.
#[cfg(not(target_arch = "arm"))]
pub static mut UI_FLAG_UPDATE_BODY: UiFlagUpdateBody = missing_ui_flag_update_body;

/// Preserves the thunk's two incoming words and its body result on host builds.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_flag_update_forwarder(object: *mut u8, flag: u32) -> u32 {
    let body = core::ptr::read_volatile(core::ptr::addr_of!(UI_FLAG_UPDATE_BODY));
    body(object, flag)
}

// The stock thunk is a direct PC-relative tail branch. A payload address cannot
// encode that branch, so keep the ABI and tail transfer through a literal veneer.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl ui_flag_update_forwarder
    .type ui_flag_update_forwarder, %function
ui_flag_update_forwarder:
    ldr     pc, [pc, #-4]
    .word   0x0819f604
    .size ui_flag_update_forwarder, . - ui_flag_update_forwarder
"#
);

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static FORWARDER_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut RECEIVED_OBJECTS: [usize; 2] = [0; 2];
    static mut RECEIVED_FLAGS: [u32; 2] = [0; 2];
    static mut RETURN_VALUE: u32 = 0;

    unsafe extern "C" fn recording_ui_flag_update_body(object: *mut u8, flag: u32) -> u32 {
        let slot = CALLS as usize;
        RECEIVED_OBJECTS[slot] = object as usize;
        RECEIVED_FLAGS[slot] = flag;
        CALLS += 1;
        RETURN_VALUE
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                UI_FLAG_UPDATE_BODY = missing_ui_flag_update_body;
                CALLS = 0;
                RECEIVED_OBJECTS = [0; 2];
                RECEIVED_FLAGS = [0; 2];
                RETURN_VALUE = 0;
            }
        }
    }

    #[test]
    fn forwards_null_and_noncanonical_flag_words_without_a_guard() {
        let _lock = FORWARDER_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        let mut object = 0u8;
        let non_null = ptr::addr_of_mut!(object);

        unsafe {
            UI_FLAG_UPDATE_BODY = recording_ui_flag_update_body;
            RETURN_VALUE = 0xfeed_beef;

            assert_eq!(ui_flag_update_forwarder(ptr::null_mut(), 0), RETURN_VALUE);
            assert_eq!(ui_flag_update_forwarder(non_null, 0xffff_ffff), RETURN_VALUE);

            assert_eq!(CALLS, 2, "the tail thunk must dispatch each call exactly once");
            assert_eq!(RECEIVED_OBJECTS, [0, non_null as usize]);
            assert_eq!(RECEIVED_FLAGS, [0, 0xffff_ffff]);
        }
    }
}
