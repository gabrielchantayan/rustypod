//! Base64 decoder stream-state reset.
//!
//! `base64_decode_state_reset` — original: `FUN_0804a0b4` @ `0x0804a0b4`,
//! **28 bytes** (`0x0804a0b4..0x0804a0cf`); the next independently linked
//! function begins at `0x0804a0d0`. Raw A32 decoding finds three inbound plain
//! `bl` calls (`0x080ee7b4`, `0x080ee934`, and `0x080ee9b0`) and no predicated
//! `bl` calls.
//!
//! Resets the Base64 decode stream state: stores the 30-byte output capacity
//! in word one, then clears words zero, 22, and 23. The state layout remains
//! word-addressed because only these four fields are established.
//!
//! # Deliberate deviations
//!
//! None.

/// Restores the four fields initialized by the retail Base64 decode-state reset.
///
/// # Safety
///
/// `state_words` must point to at least 24 writable 32-bit words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn base64_decode_state_reset(state_words: *mut u32) {
    unsafe {
        core::ptr::write_volatile(state_words.add(1), 30);
        core::ptr::write_volatile(state_words, 0);
        core::ptr::write_volatile(state_words.add(22), 0);
        core::ptr::write_volatile(state_words.add(23), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::base64_decode_state_reset;

    #[test]
    fn initializes_only_the_retail_state_words() {
        let mut state = [0xa5a5_a5a5; 24];

        unsafe { base64_decode_state_reset(state.as_mut_ptr()) };

        assert_eq!(state[0], 0);
        assert_eq!(state[1], 30);
        assert_eq!(state[22], 0);
        assert_eq!(state[23], 0);
        assert!(state[2..22].iter().all(|&word| word == 0xa5a5_a5a5));
    }

    #[test]
    fn overwrites_prior_stream_state_on_each_reset() {
        let mut state = [0; 24];
        state[0] = 19;
        state[1] = 7;
        state[22] = 64;
        state[23] = 1;

        unsafe { base64_decode_state_reset(state.as_mut_ptr()) };

        assert_eq!([state[0], state[1], state[22], state[23]], [0, 30, 0, 0]);
    }
}
