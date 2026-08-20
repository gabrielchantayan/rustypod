//! `object_word_at_4` — original: `FUN_080fe4c4` @ `0x080fe4c4` (8 bytes).
//!
//! Reference: `decomp/c/009/080fe4c4_FUN_080fe4c4.c`. This two-instruction
//! ARM leaf loads and returns the full 32-bit word at byte offset `+0x04` of
//! an opaque, word-aligned object. Its seven direct callers first obtain the
//! object pointer from `FUN_083d602c`, but do not establish a concrete object
//! type or field meaning; this port therefore retains the precise offset-based
//! name. The function performs no null check and does not mutate the object.

/// object_word_at_4 — original: `FUN_080fe4c4` @ `0x080fe4c4` (8 bytes).
///
/// Returns the raw word at byte offset `+0x04` without modifying the opaque
/// object.
///
/// # Safety
///
/// `object` must be non-null, word-aligned, and valid to read through its
/// second `u32` word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_word_at_4(object: *const u32) -> u32 {
    object.add(1).read()
}

/// object_word_at_8 — original: `FUN_0811e82c` @ `0x0811e82c` (8 bytes).
///
/// The two-instruction ARM leaf (`ldr r0, [r0, #8]; bx lr`) returns the raw
/// 32-bit word at byte offset `+0x08` from an opaque object. Its two direct
/// callers consume the result as a signed 16-bit value or compare it to one,
/// which does not establish a stronger field type. The load has no null check
/// and does not modify the object.
///
/// # Safety
///
/// `object` must be non-null, word-aligned, and valid to read through its
/// third `u32` word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_word_at_8(object: *const u32) -> u32 {
    object.add(2).read()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_arbitrary_second_words() {
        for word in [0x1234_5678, 0x89ab_cdef, 0xfeed_beef, 0x1357_9bdf] {
            let object = [0x2468_ace0, word];

            assert_eq!(unsafe { object_word_at_4(object.as_ptr()) }, word);
        }
    }

    #[test]
    fn preserves_zero_and_all_ones_words() {
        for word in [0, u32::MAX] {
            let object = [0xa5a5_5a5a, word];

            assert_eq!(unsafe { object_word_at_4(object.as_ptr()) }, word);
        }
    }

    #[test]
    fn observes_the_same_word_through_an_alias() {
        let object = [0x0000_0001, 0xc001_d00d];
        let object_pointer = object.as_ptr();
        let field_alias = unsafe { object_pointer.add(1) };

        assert_eq!(unsafe { object_word_at_4(object_pointer) }, unsafe { field_alias.read() });
    }

    #[test]
    fn leaves_the_object_unmodified() {
        let object = [0xdead_beef, 0x0123_4567];
        let before = object;

        assert_eq!(unsafe { object_word_at_4(object.as_ptr()) }, 0x0123_4567);
        assert_eq!(object, before);
    }

    #[test]
    fn returns_arbitrary_third_words() {
        for word in [0x1234_5678, 0x89ab_cdef, 0xfeed_beef, 0x1357_9bdf] {
            let object = [0x2468_ace0, 0xf0f0_0f0f, word, 0x55aa_aa55];

            assert_eq!(unsafe { object_word_at_8(object.as_ptr()) }, word);
        }
    }

    #[test]
    fn preserves_third_word_boundaries() {
        for word in [0, u32::MAX] {
            let object = [0x0000_0001, 0x2222_2222, word, 0xffff_fffe];

            assert_eq!(unsafe { object_word_at_8(object.as_ptr()) }, word);
        }
    }

    #[test]
    fn observes_the_third_word_through_an_alias() {
        let object = [0x0000_0001, 0x1111_1111, 0xc001_d00d];
        let object_pointer = object.as_ptr();
        let field_alias = unsafe { object_pointer.add(2) };

        assert_eq!(unsafe { object_word_at_8(object_pointer) }, unsafe { field_alias.read() });
    }

    #[test]
    fn leaves_the_third_word_object_unmodified() {
        let object = [0xdead_beef, 0x7654_3210, 0x0123_4567];
        let before = object;

        assert_eq!(unsafe { object_word_at_8(object.as_ptr()) }, 0x0123_4567);
        assert_eq!(object, before);
    }
}
