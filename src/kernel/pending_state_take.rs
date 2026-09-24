//! Takes and clears the pending state word.
//!
//! Original: `FUN_080d4b2c` @ `0x080d4b2c`, 20 bytes. Raw ARM establishes the
//! executable extent `0x080d4b2c..0x080d4b3f`; `0x080d4b40` is the literal
//! `0x3c200000`, and the `push {r4,lr}` at `0x080d4b44` begins the next real
//! function. A full A32 branch decode found three plain direct `bl` callers
//! (`0x0836d8f4`, `0x0836d984`, and `0x0836da28`) and no predicated direct
//! `bl` callers. The leaf body has no calls.
//!
//! Algorithm: load the word at `0x3c200010`, clear it, and return its previous
//! value. Its higher-level state identity is unrecovered, so the name states
//! only the verified take-and-clear operation. Deliberate deviation: host
//! builds replace the fixed address with private storage for behavioral tests;
//! target builds access the retail address directly.

#[cfg(target_os = "none")]
const PENDING_STATE_WORD_ADDRESS: usize = 0x3c20_0010;

#[cfg(not(target_os = "none"))]
static mut HOST_PENDING_STATE_WORD: u32 = 0;

#[inline(always)]
unsafe fn pending_state_word() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        PENDING_STATE_WORD_ADDRESS as *mut u32
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_PENDING_STATE_WORD)
    }
}

/// pending_state_take — `FUN_080d4b2c` @ `0x080d4b2c` (20 bytes; three plain
/// and zero predicated direct `bl` call sites).
///
/// Returns the current pending-state word and clears it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_state_take() -> u32 {
    unsafe {
        let state = pending_state_word();
        let pending = state.read_volatile();
        state.write_volatile(0);
        pending
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::Mutex;

    static PENDING_STATE_WORD_LOCK: Mutex<()> = Mutex::new(());

    fn reference_take(word: &mut u32) -> u32 {
        let pending = *word;
        *word = 0;
        pending
    }

    #[test]
    fn returns_and_clears_zero_and_nonzero_pending_words() {
        let _lock = PENDING_STATE_WORD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for initial in [0, 1, 0x8000_0000, u32::MAX] {
            let mut expected = initial;
            let expected_result = reference_take(&mut expected);
            unsafe {
                ptr::addr_of_mut!(HOST_PENDING_STATE_WORD).write_volatile(initial);
                assert_eq!(pending_state_take(), expected_result);
                assert_eq!(ptr::addr_of!(HOST_PENDING_STATE_WORD).read_volatile(), expected);
            }
        }
    }
}
