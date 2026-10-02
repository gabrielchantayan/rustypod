//! Saved clock-selection index — `FUN_08285160` @ 0x08285160.
//! True extent: 8 bytes, 0x08285160..0x08285168; the next entry begins
//! with `push {r4, lr}`. Raw words: `e5900040 e12fff1e`.
//! Whole-image A32 decoding verifies two inbound plain BLs (0x08274c88,
//! 0x08274d98), zero predicated BLs, and zero outgoing calls.
//!
//! Loads the signed word at clock-state offset +0x40 and returns it unchanged.
//! The callers feed this saved index to the clock selection operation at
//! 0x08284b40; reset at 0x08285168 initializes it to -1. No range or NULL
//! validation is added. Deliberate deviations: none; word indexing keeps
//! firmware offsets independent of the host pointer width.

/// Returns the saved selection index, including the -1 reset sentinel.
///
/// # Safety
/// `clock` must point to an aligned readable allocation of at least 17 u32
/// words, with the saved index at word 16.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clock_saved_selection_index(clock: *const u32) -> i32 {
    clock.add(16).read() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_sentinel_and_full_width_indices_without_mutation() {
        let mut clock = [0x1357_9bdfu32; 18];
        for index in [-1, 0, 1, i32::MAX, i32::MIN, -2] {
            clock[16] = index as u32;
            let before = clock;
            assert_eq!(unsafe { clock_saved_selection_index(clock.as_ptr()) }, index);
            assert_eq!(clock, before);
        }
    }

    #[test]
    fn uses_receiver_relative_word_offset() {
        let mut storage = [0x2468_ace0u32; 20];
        storage[16] = 7;
        storage[17] = 23;
        storage[18] = 41;
        assert_eq!(unsafe { clock_saved_selection_index(storage.as_ptr().add(1)) }, 23);
        assert_eq!(unsafe { clock_saved_selection_index(storage.as_ptr().add(2)) }, 41);
    }
}
