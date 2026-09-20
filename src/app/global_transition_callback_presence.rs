//! Presence code for the global transition callback state.
//!
//! `global_transition_callback_presence_code` — original: `FUN_0836b17c` @
//! **0x0836b17c**. Raw `osos.dec` has 24 instruction bytes at
//! `0x0836b17c..0x0836b193`, followed by its `0x089ca458` global-pointer
//! literal at `0x0836b194`; the distinct next function begins at
//! `0x0836b198`, for a 28-byte true extent. Decoding every aligned ARM
//! B/BL word finds three inbound direct calls, all plain unconditional `bl`
//! at `0x08369ac0`, `0x08393480`, and `0x083934b8`; there are no predicated
//! `bl` forms.
//!
//! Algorithm: load the global transition callback-state pointer at
//! `0x089ca458` and return 2 when it is NULL, otherwise 1. The target reads
//! a 32-bit pointer word; host builds deliberately use a native-width static
//! so test pointers remain valid on 64-bit hosts.

#[cfg(not(target_os = "none"))]
use core::ptr;

/// Runtime global pointer tested by the retailOS body.
pub const GLOBAL_TRANSITION_CALLBACK_STATE_ADDRESS: usize = 0x089c_a458;

#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_TRANSITION_CALLBACK_STATE: *mut u8 = ptr::null_mut();

/// Returns 1 when the global transition callback state is installed, or 2
/// when it is absent.
///
/// # Safety
///
/// On firmware, `GLOBAL_TRANSITION_CALLBACK_STATE_ADDRESS` must be a readable
/// 32-bit global pointer slot. Its pointee is not dereferenced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_transition_callback_presence_code() -> u32 {
    #[cfg(target_os = "none")]
    let state = (GLOBAL_TRANSITION_CALLBACK_STATE_ADDRESS as *const u32).read_volatile();
    #[cfg(not(target_os = "none"))]
    let state = ptr::addr_of!(HOST_GLOBAL_TRANSITION_CALLBACK_STATE).read_volatile() as usize;

    if state == 0 { 2 } else { 1 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static GLOBAL_TRANSITION_CALLBACK_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct GlobalTransitionCallbackStateReset;

    impl Drop for GlobalTransitionCallbackStateReset {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(HOST_GLOBAL_TRANSITION_CALLBACK_STATE).write(ptr::null_mut());
            }
        }
    }

    #[test]
    fn distinguishes_absent_and_installed_callback_state() {
        let _guard = GLOBAL_TRANSITION_CALLBACK_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = GlobalTransitionCallbackStateReset;
        let mut state = [0u32; 1];

        unsafe {
            ptr::addr_of_mut!(HOST_GLOBAL_TRANSITION_CALLBACK_STATE).write(ptr::null_mut());
            assert_eq!(global_transition_callback_presence_code(), 2);

            ptr::addr_of_mut!(HOST_GLOBAL_TRANSITION_CALLBACK_STATE).write(state.as_mut_ptr().cast());
            assert_eq!(global_transition_callback_presence_code(), 1);
        }
    }
}
