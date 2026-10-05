//! Reset segmented-buffer state, FUN_0818b494 @ 0x0818b494.
//!
//! True extent: 36 bytes, 0x0818b494..0x0818b4b8, where the next real
//! function begins with a push prologue. Raw aligned A32 decoding finds two
//! inbound plain BLs (0x0818b434, 0x0818b84c), zero predicated BLs; the body
//! contains zero plain or predicated BLs. Clear words at +8, +12, +16, +28,
//! +36, +32, then +20, preserving the vtable, flag word, and context at +24.
//! The constructor initializes the preserved fields before calling this leaf;
//! the release path calls it after releasing the chain rooted at +28. The
//! adjacent read routine advances the position at +8, intra-segment offset
//! at +12, and segment at +16. Other cleared fields remain unidentified.
//! Deliberate deviations: none. Return the unchanged object pointer, matching
//! raw r0 pass-through (Ghidra renders the unused return as void). Volatile
//! word writes preserve the original store order and avoid memset lowering.

/// # Safety
/// `buffer` must point to ten writable, aligned u32 words, exclusively owned
/// for the call. Pointer-valued words use the firmware's 32-bit layout even
/// on hosts; this function never dereferences their contents. No NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn segmented_buffer_state_reset(buffer: *mut u32) -> *mut u32 {
    buffer.add(2).write_volatile(0);
    buffer.add(3).write_volatile(0);
    buffer.add(4).write_volatile(0);
    buffer.add(7).write_volatile(0);
    buffer.add(9).write_volatile(0);
    buffer.add(8).write_volatile(0);
    buffer.add(5).write_volatile(0);
    buffer
}

#[cfg(test)]
mod tests {
    use super::segmented_buffer_state_reset;

    #[test]
    fn clears_state_without_touching_header_context_or_neighbors() {
        for seed in [0u32, 1, 0x8000_0000, u32::MAX] {
            let mut storage = [0u32; 12];
            for (index, word) in storage.iter_mut().enumerate() {
                *word = seed.wrapping_add((index as u32).wrapping_mul(0x1020_3041));
            }
            let before = storage;
            let buffer = unsafe { storage.as_mut_ptr().add(1) };
            assert_eq!(unsafe { segmented_buffer_state_reset(buffer) }, buffer);
            // Independent byte-offset reference, including both boundary canaries.
            let mut expected = before;
            for offset in [8, 12, 16, 20, 28, 32, 36] {
                expected[1 + offset / 4] = 0;
            }
            assert_eq!(storage, expected);
        }
    }

    #[test]
    fn repeated_reset_preserves_new_context_and_flag_values() {
        let mut buffer = [u32::MAX; 10];
        unsafe { segmented_buffer_state_reset(buffer.as_mut_ptr()); }
        buffer[0] = 0x0898_0000;
        buffer[1] = 0xdead_be01;
        buffer[6] = 0x0800_1234;
        unsafe { segmented_buffer_state_reset(buffer.as_mut_ptr()); }
        assert_eq!(buffer, [0x0898_0000, 0xdead_be01, 0, 0, 0, 0, 0x0800_1234, 0, 0, 0]);
    }
}
