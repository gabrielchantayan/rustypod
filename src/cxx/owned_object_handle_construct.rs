//! Owned-object handle constructor, `FUN_0815743c` @ **0x0815743c**.
//!
//! True size: 12 bytes, ending at the next function's push at 0x08157448.
//! Raw words: e3a01000 (mov r1,#0), e5801000 (str r1,[r0]), e12fff1e
//! (bx lr). Full-image word decoding finds two inbound plain BL calls at
//! 0x08124614 and 0x0815fc0c, zero predicated BL calls, and no outgoing calls.
//!
//! Clear the handle's first target-width object word and return the same
//! handle. Both callers allocate eight bytes, construct this handle, and pass
//! the returned pointer to owned_guarded_slot_04_replace. The adjacent dispatch
//! wrapper interprets its first word as an optional object's pointer.
//!
//! Deliberate deviations: none in the memory algorithm; host storage remains
//! u32 words rather than widened pointers. Ghidra's void return is corrected
//! because r0 is preserved and both raw callers consume it. The second allocated
//! word is deliberately untouched; the concrete object's class is unrecovered.
//!
//! Codegen: match.py reports a structural diff (exit 1). LLVM adds a frame
//! push/setup/pop around the same mov-zero and single str; r0 remains intact.

/// # Safety
/// `handle` must point to at least one aligned, writable u32. No NULL check.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_object_handle_construct(handle: *mut u32) -> *mut u32 {
    unsafe { handle.write(0); }
    handle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_exactly_one_word_and_preserves_return_pointer() {
        for initial in [0, 1, 0x8000_0000, u32::MAX] {
            for index in 1..4 {
                let mut words = [0xa5a5_5a5a; 5];
                words[index] = initial;
                let handle = unsafe { words.as_mut_ptr().add(index) };
                let result = unsafe { owned_object_handle_construct(handle) };
                assert_eq!(result, handle);
                let mut expected = [0xa5a5_5a5a; 5];
                expected[index] = 0;
                assert_eq!(words, expected);
            }
        }
    }

    #[test]
    fn accepts_single_word_storage() {
        let mut word = 0xffff_ffffu32;
        let handle = &mut word as *mut u32;
        assert_eq!(unsafe { owned_object_handle_construct(handle) }, handle);
        assert_eq!(word, 0);
    }
}
