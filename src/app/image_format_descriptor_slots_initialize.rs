//! Image-format descriptor slots initialization.
//!
//! `image_format_descriptor_slots_initialize` — original `FUN_081d5ff8` @
//! `0x081d5ff8` (**56 bytes, `0x081d5ff8..0x081d6030`**): 52 instruction
//! bytes followed by its 4-byte literal-pool vtable word at `0x081d602c`.
//! The separately linked next function begins at `0x081d6030`. Decoding every
//! ARM B/BL immediate in `osos.dec` finds **six direct call sites**, all
//! unconditional plain `bl`: `0x081b7d7c`, `0x081cd20c`, `0x081fd088`,
//! `0x0820a4d0`, `0x0822020c`, and `0x0822bab0`; there are no predicated calls
//! or plain-`b` tail branches.
//!
//! # Algorithm
//!
//! Initializes the 165-word image-format descriptor slots object: install its
//! literal vtable pointer in word 0, zero sequence word 164, set sentinel word
//! 163 and word 0 of each of the 18 nine-word records (starting at word 9) to
//! `u32::MAX`. It performs no pointer or bounds checks. The raw body leaves r0
//! unchanged, although Ghidra models it as `void`; the Rust signature returns
//! the input pointer so callers may use the observed result. No deliberate
//! behavioral deviations.

const IMAGE_FORMAT_DESCRIPTOR_SLOTS_VTABLE: u32 = 0x0898_dfe4;
const FIRST_RECORD_WORD: usize = 9;
const RECORD_WORDS: usize = 9;
const RECORD_COUNT: usize = 18;
const SENTINEL_WORD: usize = 0xa3;
const SEQUENCE_WORD: usize = 0xa4;

/// Initializes an opaque image-format descriptor slots object.
///
/// # Safety
///
/// `slots` must be aligned and writable for 165 `u32` words. As in retailOS,
/// it is not checked for NULL, validity, or bounds.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_format_descriptor_slots_initialize(slots: *mut u32) -> *mut u32 {
    slots.write(IMAGE_FORMAT_DESCRIPTOR_SLOTS_VTABLE);
    slots.add(SEQUENCE_WORD).write(0);
    slots.add(SENTINEL_WORD).write(u32::MAX);

    for record in 0..RECORD_COUNT {
        slots
            .add(FIRST_RECORD_WORD + record * RECORD_WORDS)
            .write(u32::MAX);
    }

    slots
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITIAL_WORD: u32 = 0xc0de_cafe;

    #[test]
    fn initializes_all_record_starts_and_preserves_other_words() {
        let mut slots = [INITIAL_WORD; SEQUENCE_WORD + 1];
        let result = unsafe { image_format_descriptor_slots_initialize(slots.as_mut_ptr()) };

        assert_eq!(result, slots.as_mut_ptr());
        for (word, value) in slots.into_iter().enumerate() {
            let is_record_start = word >= FIRST_RECORD_WORD
                && word < FIRST_RECORD_WORD + RECORD_COUNT * RECORD_WORDS
                && (word - FIRST_RECORD_WORD) % RECORD_WORDS == 0;
            let expected = if word == 0 {
                IMAGE_FORMAT_DESCRIPTOR_SLOTS_VTABLE
            } else if word == SENTINEL_WORD || is_record_start {
                u32::MAX
            } else if word == SEQUENCE_WORD {
                0
            } else {
                INITIAL_WORD
            };
            assert_eq!(value, expected, "word {word}");
        }
    }

    #[test]
    fn overwrites_existing_metadata_values() {
        let mut slots = [u32::MAX; SEQUENCE_WORD + 1];
        slots[0] = 0;
        slots[SENTINEL_WORD] = 0;
        for record in 0..RECORD_COUNT {
            slots[FIRST_RECORD_WORD + record * RECORD_WORDS] = record as u32;
        }

        unsafe { image_format_descriptor_slots_initialize(slots.as_mut_ptr()) };

        assert_eq!(slots[0], IMAGE_FORMAT_DESCRIPTOR_SLOTS_VTABLE);
        assert_eq!(slots[SENTINEL_WORD], u32::MAX);
        assert_eq!(slots[SEQUENCE_WORD], 0);
        for record in 0..RECORD_COUNT {
            assert_eq!(slots[FIRST_RECORD_WORD + record * RECORD_WORDS], u32::MAX);
        }
    }
}
