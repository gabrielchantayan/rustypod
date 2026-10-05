//! Empty destructor for the context used by the retailOS FORM lookup.
//!
//! Load address: 0x081e609c. True size: 4 bytes, ending at the real
//! function entry 0x081e60a0. Raw word: e12fff1e (`bx lr`). Verified calls:
//! two inbound plain BLs (0x0818dc84, 0x0818dcbc), zero predicated inbound
//! BLs, and zero outbound BLs. The caller constructs a one-word context
//! with 0x081e608c, performs the FORM lookup at 0x081e5fa0, then invokes
//! this destructor on both success and failure. No memory is accessed;
//! r0 passes through unchanged. No deliberate behavioral deviations.
//! The pointer return models raw register preservation, not Ghidra's void
//! signature. The exact C++ class identity is not established.

/// Return the context unchanged, without inspecting or releasing it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn form_lookup_context_destruct(context: *mut u32) -> *mut u32 {
    context
}

#[cfg(test)]
mod tests {
    use super::form_lookup_context_destruct;

    #[test]
    fn preserves_context_and_adjacent_words() {
        let mut words = [0x12345678, 0x0898efec, 0xffffffff];
        let context = unsafe { words.as_mut_ptr().add(1) };
        assert_eq!(form_lookup_context_destruct(context), context);
        assert_eq!(words, [0x12345678, 0x0898efec, 0xffffffff]);
    }

    #[test]
    fn accepts_null_and_non_dereferenceable_contexts() {
        for address in [0usize, 1, 3, 0x081e609c, usize::MAX] {
            let context = address as *mut u32;
            assert_eq!(form_lookup_context_destruct(context), context);
        }
    }
}
