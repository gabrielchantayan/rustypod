//! `payload_word_exchange` — `FUN_082b5154` @ `0x082b5154`.
//! True extent: 24 bytes, `0x082b5154..0x082b516c`; the next function
//! starts with `push {r0-r11,lr}`. Whole-image A32 decoding verifies two
//! inbound plain BL calls (0x0803ad14, 0x080d3ba4), zero predicated BL
//! calls, and zero outbound calls.
//!
//! Loads the context slot's payload base and the descriptor's +0x04 byte
//! offset, reads the aligned word there, writes the replacement, and returns
//! the old word. Raw words: e5900000 e5922004 e0802002 e5920000 e5821000
//! e12fff1e. No flags are inspected and no NULL checks are performed.
//! Deliberate deviations: none; repr(C) u32 fields preserve descriptor
//! offsets on hosts, while the context slot uses a native pointer.

/// The descriptor prefix used by the word exchange (remaining fields unused).
#[repr(C)]
pub struct PayloadWordDescriptor {
    pub flags: u32,
    pub word_offset: u32,
}

/// Exchanges a payload word selected by a descriptor's byte offset.
///
/// # Safety
/// `context_slot` and `descriptor` must be readable. The selected address
/// must be aligned and valid for reading and writing one u32. The operation
/// is not atomic; callers must exclude concurrent access.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.payload_word_exchange")]
#[inline(never)]
pub unsafe extern "C" fn payload_word_exchange(
    context_slot: *mut *mut u8,
    replacement: u32,
    descriptor: *const PayloadWordDescriptor,
) -> u32 {
    let base = *context_slot;
    let offset = (*descriptor).word_offset;
    let word = base.wrapping_add(offset as usize).cast::<u32>();
    let previous = word.read();
    word.write(replacement);
    previous
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchanges_first_interior_and_last_words_without_changing_neighbors() {
        for index in [0usize, 2, 4] {
            for replacement in [0, u32::MAX, 0x8000_0000, 0x1234_5678] {
                let original = [0x1122_3344, 0x5566_7788, 0x99aa_bbcc, 0, u32::MAX];
                let mut payload = original;
                let mut base = payload.as_mut_ptr().cast::<u8>();
                let descriptor = PayloadWordDescriptor {
                    flags: u32::MAX,
                    word_offset: (index * 4) as u32,
                };
                let previous = unsafe {
                    payload_word_exchange(&mut base, replacement, &descriptor)
                };
                let mut expected = original;
                expected[index] = replacement;
                assert_eq!(previous, original[index]);
                assert_eq!(payload, expected);
                assert_eq!(base, payload.as_mut_ptr().cast::<u8>());
            }
        }
    }

    #[test]
    fn captures_offset_before_overwriting_the_descriptor_offset_itself() {
        let mut descriptor = PayloadWordDescriptor { flags: 0x400, word_offset: 4 };
        let mut base = (&mut descriptor as *mut PayloadWordDescriptor).cast::<u8>();
        let descriptor_ptr = &descriptor as *const PayloadWordDescriptor;
        assert_eq!(unsafe { payload_word_exchange(&mut base, u32::MAX, descriptor_ptr) }, 4);
        assert_eq!(descriptor.flags, 0x400);
        assert_eq!(descriptor.word_offset, u32::MAX);
    }
}
