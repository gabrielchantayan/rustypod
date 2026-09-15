//! `opaque_header_payload_construct` — original: `FUN_082a89b4` @
//! **0x082a89b4** (32 bytes: seven instruction words through 0x082a89cc plus
//! the four-byte literal-pool word at 0x082a89d0; Ghidra reports only the 28
//! instruction bytes).
//!
//! # Extent and reachability, binary-verified
//!
//! The next separately linked function begins at 0x082a89d4. Decoding every
//! ARM B/BL immediate in `work/firmware/osos.dec` finds exactly five direct
//! call sites, all unconditional `bl`: 0x082a898c, 0x082a8c6c, 0x082a8c94,
//! 0x083e71c4, and 0x083e7740. There are no predicated `bl` calls.
//!
//! # Algorithm
//!
//! Store the opaque literal `0x089a8518` at word 0, the third argument at word
//! 1, zero at word 2, and the second argument at word 3, then return `this`.
//! The ARM body has no null or alignment guard.
//!
//! # Deliberate deviations
//!
//! None. The literal points into opaque data and callers overwrite word 0 with
//! their own literals, so this port deliberately does not infer a class or
//! vtable identity.

/// The opaque literal-pool word at 0x082a89d0.
pub const OPAQUE_HEADER_PAYLOAD_LITERAL: u32 = 0x089a_8518;

/// Initializes a four-word opaque record and returns `this`.
///
/// # Safety
///
/// `this` must point to at least four writable, four-byte-aligned `u32` words.
/// The original ARM `str` instructions dereference it without a null or
/// alignment check.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_header_payload_construct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_header_payload_construct(
    this: *mut u32,
    second_word: u32,
    third_word: u32,
) -> *mut u32 {
    unsafe {
        this.add(1).write_volatile(third_word);
        this.add(3).write_volatile(second_word);
        this.write_volatile(OPAQUE_HEADER_PAYLOAD_LITERAL);
        this.add(2).write_volatile(0);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_all_words_in_retail_store_order() {
        let mut record = [0xa5a5_a5a5; 4];
        let returned = unsafe {
            opaque_header_payload_construct(record.as_mut_ptr(), 0x1122_3344, 0x5566_7788)
        };

        assert_eq!(returned, record.as_mut_ptr());
        assert_eq!(
            record,
            [
                OPAQUE_HEADER_PAYLOAD_LITERAL,
                0x5566_7788,
                0,
                0x1122_3344,
            ]
        );
    }

    #[test]
    fn overwrites_prior_values_including_zero_payloads() {
        let mut record = [0xffff_ffff, 1, 2, 3];

        unsafe { opaque_header_payload_construct(record.as_mut_ptr(), 0, 0) };

        assert_eq!(record, [OPAQUE_HEADER_PAYLOAD_LITERAL, 0, 0, 0]);
    }
}
