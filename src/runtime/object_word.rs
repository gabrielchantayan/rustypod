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
}
