//! crts_has_tag — `FUN_080a7714` @ 0x080a7714 (36 bytes of code plus a
//! 4-byte literal pool; 11 direct `bl` call sites, binary-scanned).
//!
//! Raw ARM's nine code words run from `cmp r0,#0` at 0x080a7714 through
//! `bx lr` at 0x080a7734, followed by its `0x7374_7263` literal-pool word at
//! 0x080a7738. The separately linked next function starts at 0x080a773c.
//! It returns one only for a non-NULL, word-aligned object whose first word is
//! that literal (in-memory bytes `"crts"`); it otherwise returns zero and does
//! not mutate the object. Decoding every ARM B/BL-immediate word in `osos.dec`
//! finds 11 inbound calls, all unconditional `bl` (0x080760b4, 0x0808e174,
//! 0x0809e168, 0x0809f74c, 0x080b4340, 0x080b4e74, 0x080c5ab4,
//! 0x080c5f08, 0x080d6dc8, 0x080d86bc, and 0x080e27f0), with no predicated
//! forms or direct B tail callers.
//!
//! Deliberate deviations: none. The raw `ldr r0,[r0]` requires a valid,
//! word-aligned non-NULL address on its success path; the Rust safety contract
//! states the same precondition.

/// Literal required in the first word of a recognized object. Its in-memory
/// little-endian bytes read `"crts"`.
pub const CRTS_TAG: u32 = 0x7374_7263;

/// crts_has_tag — original: `FUN_080a7714` @ 0x080a7714 (36-byte code body,
/// plus 4-byte literal pool).
///
/// Returns 1 when `object` is non-NULL and its first word equals
/// [`CRTS_TAG`], otherwise returns 0. The object is not modified.
///
/// # Safety
///
/// A non-NULL `object` must be valid and aligned for a `u32` read, matching
/// the original ARM `ldr`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn crts_has_tag(object: *const u32) -> u32 {
    u32::from(!object.is_null() && object.read() == CRTS_TAG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_is_not_a_crts_object() {
        assert_eq!(unsafe { crts_has_tag(core::ptr::null()) }, 0);
    }

    #[test]
    fn exact_tag_is_recognized_without_mutation() {
        let object = [CRTS_TAG, 0xfeed_beef];
        assert_eq!(unsafe { crts_has_tag(object.as_ptr()) }, 1);
        assert_eq!(object, [CRTS_TAG, 0xfeed_beef]);
    }

    #[test]
    fn every_other_first_word_is_rejected() {
        for tag in [0, 0x7374_7262, 0x7374_7264, 0xffff_ffff] {
            let object = [tag, CRTS_TAG];
            assert_eq!(unsafe { crts_has_tag(object.as_ptr()) }, 0, "tag {tag:#010x}");
        }
    }

    #[test]
    fn only_the_first_word_is_examined() {
        let object = [CRTS_TAG, 0];
        assert_eq!(unsafe { crts_has_tag(object.as_ptr()) }, 1);
    }
}
