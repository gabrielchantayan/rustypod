//! Image-format descriptor slot count accessor.
//!
//! `image_format_descriptor_slot_count` — original `FUN_081d5f90` @
//! `0x081d5f90` (**8 bytes, `0x081d5f90..0x081d5f97`**). `mov r3,r1` at
//! `0x081d5f98` begins the separately linked next function. Whole-image A32
//! decoding finds **three inbound plain `bl` calls** at `0x0811f418`,
//! `0x081f0d14`, and `0x0821b278`, with **zero predicated inbound `bl` calls**.
//!
//! # Algorithm
//!
//! Returns word 164 (`+0x290`) of the opaque image-format descriptor slots
//! object. Slot insertion increments this word, and callers use it as the
//! number of populated descriptors. It has no NULL, bounds, or alignment
//! checks. No deliberate deviations.

const DESCRIPTOR_COUNT_WORD: usize = 0xa4;

/// Returns the number of populated image-format descriptor slots.
///
/// # Safety
///
/// `slots` must be non-null, aligned, and readable through word 164. As in
/// retailOS, this function does not validate the pointer or object extent.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_descriptor_slot_count(slots: *const u32) -> u32 {
    slots.add(DESCRIPTOR_COUNT_WORD).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_count_word_without_touching_adjacent_words() {
        let mut slots = [0xc0de_cafe; DESCRIPTOR_COUNT_WORD + 2];
        slots[DESCRIPTOR_COUNT_WORD] = 17;

        let count = unsafe { image_format_descriptor_slot_count(slots.as_ptr()) };

        assert_eq!(count, 17);
        assert_eq!(slots[DESCRIPTOR_COUNT_WORD - 1], 0xc0de_cafe);
        assert_eq!(slots[DESCRIPTOR_COUNT_WORD + 1], 0xc0de_cafe);
    }

    #[test]
    fn preserves_full_width_count_values() {
        let mut slots = [0; DESCRIPTOR_COUNT_WORD + 1];
        slots[DESCRIPTOR_COUNT_WORD] = u32::MAX;

        assert_eq!(unsafe { image_format_descriptor_slot_count(slots.as_ptr()) }, u32::MAX);
    }
}
