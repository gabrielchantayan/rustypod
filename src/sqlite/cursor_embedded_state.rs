//! Return the embedded state storage of an initialized SQLite cursor wrapper.
//!
//! `cursor_embedded_state` — retailOS `FUN_0837e18c` at `0x0837e18c` (20
//! bytes; `0x0837e18c..0x0837e19c`, with the next distinct function at
//! `0x0837e1a0`). Five direct plain-`bl` callers reference it in the
//! decompiler output; raw instruction decoding establishes that the body has
//! no calls, predicated or otherwise.
//!
//! The wrapper's first target word is its initialized pointer/flag. A zero
//! word returns null; otherwise the embedded cursor state begins at `+0x38`.
//! This deliberately models the target's 32-bit first word rather than a host
//! pointer, so the tested field offset remains valid on 64-bit hosts. There
//! are no deliberate behavioral deviations.

/// Byte offset of the wrapper's embedded cursor state.
const EMBEDDED_STATE_OFFSET: usize = 0x38;

/// Return the embedded cursor state if `cursor_wrapper` is initialized.
///
/// The wrapper must be aligned for a 32-bit word, as required by the retail
/// ARM `ldr` instruction. A non-null wrapper with a zero first word returns
/// null; otherwise this returns the address at `+0x38` without dereferencing
/// the embedded state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cursor_embedded_state(cursor_wrapper: *mut u8) -> *mut u8 {
    if (cursor_wrapper as *const u32).read() == 0 {
        core::ptr::null_mut()
    } else {
        cursor_wrapper.add(EMBEDDED_STATE_OFFSET)
    }
}

#[cfg(test)]
mod tests {
    use super::cursor_embedded_state;

    #[test]
    fn returns_null_when_wrapper_is_uninitialized() {
        let mut wrapper = [0_u32; 15];

        assert!(unsafe { cursor_embedded_state(wrapper.as_mut_ptr().cast()) }.is_null());
    }

    #[test]
    fn returns_embedded_state_at_target_offset_when_initialized() {
        let mut wrapper = [0_u32; 15];
        wrapper[0] = 1;
        let base = wrapper.as_mut_ptr().cast::<u8>();

        assert_eq!(unsafe { cursor_embedded_state(base) }, unsafe { base.add(0x38) });
        assert_eq!(wrapper[0], 1);
    }
}
