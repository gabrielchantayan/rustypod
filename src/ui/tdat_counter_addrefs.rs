//! 'tdat' UI-element counter acquisition — `FUN_0805c220` @ 0x0805c220
//! (180 bytes; 11 direct `bl` call sites, all unconditional).
//!
//! The raw ARM body first rejects NULL and non-'tdat' elements through the
//! already-ported class predicate. For a valid element it attempts to increment
//! fourteen individually located tagged counters, then all ten counters in the
//! contiguous 0x58-byte-stride group. Each nested increment retains its own
//! tag validation and can therefore leave an unrecognised embedded counter
//! unchanged. The function returns no status and ignores every nested result.
//!
//! The exact 180-byte extent is 0x0805c220..0x0805c2d0; the separately entered
//! next function starts at 0x0805c2d4. Decoding every ARM B/BL-immediate word
//! in `osos.dec` found 11 inbound direct `bl` calls (0x080461b8, 0x08046e80,
//! 0x08052b54, 0x08055b2c, 0x0805cd70, 0x0808677c, 0x0808d148, 0x0809dc54,
//! 0x0809dfe0, 0x0809efc0, and 0x080aa4d0), with no predicated or tail-branch
//! forms. Deliberate deviations: none; the existing Rust ports directly
//! replace both retail callees rather than branching back into stock code.

use crate::ui::tdat_class_check::ui_element_is_tdat_class;
use crate::util::tagged_counter::{tagged_counter_try_increment, TaggedCounter};

const COUNTER_C0_WORD: usize = 0xc0 / 4;
const COUNTER_118_WORD: usize = 0x118 / 4;
const COUNTER_170_WORD: usize = 0x170 / 4;
const COUNTER_1C8_WORD: usize = 0x1c8 / 4;
const COUNTER_220_WORD: usize = 0x220 / 4;
const COUNTER_278_WORD: usize = 0x278 / 4;
const COUNTER_2D0_WORD: usize = 0x2d0 / 4;
const COUNTER_328_WORD: usize = 0x328 / 4;
const COUNTER_380_WORD: usize = 0x380 / 4;
const COUNTER_3D8_WORD: usize = 0x3d8 / 4;
const COUNTER_7A0_WORD: usize = 0x7a0 / 4;
const COUNTER_7F8_WORD: usize = 0x7f8 / 4;
const COUNTER_8A8_WORD: usize = 0x8a8 / 4;
const COUNTER_850_WORD: usize = 0x850 / 4;
const COUNTER_GROUP_430_WORD: usize = 0x430 / 4;
const COUNTER_GROUP_STRIDE_WORDS: usize = 0x58 / 4;
const COUNTER_GROUP_LEN: usize = 10;

/// Attempts the retail tagged-counter increment at a word-indexed field.
///
/// The original's counters are all word aligned. Word indices, rather than
/// byte offsets into a pointer-bearing host struct, retain the target layout
/// on both 32-bit firmware and 64-bit test hosts.
#[inline(always)]
unsafe fn addref_counter_at(element: *mut u8, counter_word: usize) {
    unsafe {
        tagged_counter_try_increment(
            element.cast::<u32>().add(counter_word).cast::<TaggedCounter>(),
        );
    }
}

/// tdat_element_addref_counters — original: `FUN_0805c220` @ 0x0805c220
/// (180 bytes; 11 direct `bl` call sites, all unconditional).
///
/// If `element` is a live 'tdat' UI element, attempts to increment its fourteen
/// individually located tagged counters and its ten-entry counter group. An
/// invalid element, a NULL element, or any invalid nested counter has no
/// observable error result; invalid nested counters are simply not changed.
///
/// # Safety
///
/// `element` may be NULL. A non-NULL 'tdat' element must be word aligned and
/// valid through its final embedded counter at offset +0x8db, matching the
/// retail aligned loads and stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tdat_element_addref_counters(element: *mut u8) {
    if unsafe { ui_element_is_tdat_class(element) } == 0 {
        return;
    }

    unsafe {
        addref_counter_at(element, COUNTER_C0_WORD);
        addref_counter_at(element, COUNTER_118_WORD);
        addref_counter_at(element, COUNTER_170_WORD);
        addref_counter_at(element, COUNTER_1C8_WORD);
        addref_counter_at(element, COUNTER_220_WORD);
        addref_counter_at(element, COUNTER_278_WORD);
        addref_counter_at(element, COUNTER_2D0_WORD);
        addref_counter_at(element, COUNTER_328_WORD);
        addref_counter_at(element, COUNTER_380_WORD);
        addref_counter_at(element, COUNTER_3D8_WORD);
        addref_counter_at(element, COUNTER_7A0_WORD);
        addref_counter_at(element, COUNTER_7F8_WORD);
        addref_counter_at(element, COUNTER_8A8_WORD);
        addref_counter_at(element, COUNTER_850_WORD);

        for index in 0..COUNTER_GROUP_LEN {
            addref_counter_at(
                element,
                COUNTER_GROUP_430_WORD + index * COUNTER_GROUP_STRIDE_WORDS,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::crts_tag::CRTS_TAG;

    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    const COUNTER_COUNT_WORD: usize = 0x30 / 4;
    const ELEMENT_WORDS: usize = (0x8a8 + 0x34) / 4;

    const ALL_COUNTER_WORDS: [usize; 24] = [
        COUNTER_C0_WORD,
        COUNTER_118_WORD,
        COUNTER_170_WORD,
        COUNTER_1C8_WORD,
        COUNTER_220_WORD,
        COUNTER_278_WORD,
        COUNTER_2D0_WORD,
        COUNTER_328_WORD,
        COUNTER_380_WORD,
        COUNTER_3D8_WORD,
        COUNTER_7A0_WORD,
        COUNTER_7F8_WORD,
        COUNTER_8A8_WORD,
        COUNTER_850_WORD,
        COUNTER_GROUP_430_WORD,
        COUNTER_GROUP_430_WORD + COUNTER_GROUP_STRIDE_WORDS,
        COUNTER_GROUP_430_WORD + 2 * COUNTER_GROUP_STRIDE_WORDS,
        COUNTER_GROUP_430_WORD + 3 * COUNTER_GROUP_STRIDE_WORDS,
        COUNTER_GROUP_430_WORD + 4 * COUNTER_GROUP_STRIDE_WORDS,
        COUNTER_GROUP_430_WORD + 5 * COUNTER_GROUP_STRIDE_WORDS,
        COUNTER_GROUP_430_WORD + 6 * COUNTER_GROUP_STRIDE_WORDS,
        COUNTER_GROUP_430_WORD + 7 * COUNTER_GROUP_STRIDE_WORDS,
        COUNTER_GROUP_430_WORD + 8 * COUNTER_GROUP_STRIDE_WORDS,
        COUNTER_GROUP_430_WORD + 9 * COUNTER_GROUP_STRIDE_WORDS,
    ];

    fn tdat_element() -> [u32; ELEMENT_WORDS] {
        let mut element = [0; ELEMENT_WORDS];
        element[1] = TDAT_CLASS_TAG;
        for (index, &counter_word) in ALL_COUNTER_WORDS.iter().enumerate() {
            element[counter_word] = CRTS_TAG;
            element[counter_word + COUNTER_COUNT_WORD] = index as u32;
        }
        element
    }

    #[test]
    fn increments_every_valid_embedded_counter() {
        let mut element = tdat_element();

        unsafe { tdat_element_addref_counters(element.as_mut_ptr().cast()) };

        for (index, &counter_word) in ALL_COUNTER_WORDS.iter().enumerate() {
            assert_eq!(element[counter_word + COUNTER_COUNT_WORD], index as u32 + 1);
        }
    }

    #[test]
    fn ignores_invalid_embedded_counter_but_acquires_the_rest() {
        let mut element = tdat_element();
        let rejected_counter = COUNTER_8A8_WORD;
        element[rejected_counter] = 0;

        unsafe { tdat_element_addref_counters(element.as_mut_ptr().cast()) };

        for (index, &counter_word) in ALL_COUNTER_WORDS.iter().enumerate() {
            let expected = if counter_word == rejected_counter { index as u32 } else { index as u32 + 1 };
            assert_eq!(element[counter_word + COUNTER_COUNT_WORD], expected);
        }
    }

    #[test]
    fn ignores_non_tdat_element_without_examining_counters() {
        let mut element = tdat_element();
        element[1] = 0;
        let before = element;

        unsafe { tdat_element_addref_counters(element.as_mut_ptr().cast()) };

        assert_eq!(element, before);
    }

    #[test]
    fn null_element_is_rejected_by_the_class_predicate() {
        unsafe { tdat_element_addref_counters(core::ptr::null_mut()) };
    }
}
