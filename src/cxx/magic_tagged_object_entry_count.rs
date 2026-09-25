//! `magic_tagged_object_entry_count` — original: `FUN_080470a0` @
//! **0x080470a0** (28 bytes).
//!
//! Raw `osos.dec` establishes the seven-instruction body at
//! 0x080470a0..0x080470b8; the separately entered function at 0x080470bc
//! immediately follows. Whole-image ARM B/BL-immediate decoding finds three
//! direct inbound calls, all plain unconditional `bl` at 0x08054b30,
//! 0x080df3c4, and 0x080e5af8; there are no predicated calls. The body has
//! one plain `bl` to `magic_tagged_object_validate`.
//!
//! # Algorithm
//!
//! Validates the opaque tagged object. On success returns its 32-bit entry
//! count at `+0x10`; otherwise returns zero. Callers use the count as the
//! upper bound while enumerating the object's 0x14-byte child entries.
//! Deliberate deviations: the validation call is a direct Rust call rather
//! than a branch into stock code.

use crate::cxx::magic_tagged_object::{magic_tagged_object_validate, MagicTaggedObject};

const ENTRY_COUNT_WORD: usize = 0x10 / core::mem::size_of::<u32>();

/// Returns the entry count of a valid opaque tagged object, or zero otherwise.
///
/// # Safety
///
/// A non-null `object` must be readable through its aligned tag word and
/// `+0x10` count word. The retail implementation has no additional bounds or
/// lifetime validation.
#[cfg_attr(target_os = "none", link_section = ".text.magic_tagged_object_entry_count")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn magic_tagged_object_entry_count(object: *const u32) -> u32 {
    if unsafe { magic_tagged_object_validate(object.cast::<MagicTaggedObject>()) } == 0 {
        unsafe { object.add(ENTRY_COUNT_WORD).read_volatile() }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::magic_tagged_object::MAGIC_TAGGED_OBJECT_TAG;

    const ENTRY_COUNT_WORDS: usize = ENTRY_COUNT_WORD + 1;

    fn object_with(tag: u32, count: u32) -> [u32; ENTRY_COUNT_WORDS] {
        let mut object = [0xa5a5_a5a5; ENTRY_COUNT_WORDS];
        object[0] = tag;
        object[ENTRY_COUNT_WORD] = count;
        object
    }

    #[test]
    fn returns_all_entry_count_representations_for_a_valid_object() {
        for count in [0, 1, 0x8000_0000, u32::MAX] {
            let object = object_with(MAGIC_TAGGED_OBJECT_TAG, count);
            assert_eq!(unsafe { magic_tagged_object_entry_count(object.as_ptr()) }, count);
        }
    }

    #[test]
    fn rejects_null_and_invalid_tags_without_reading_the_count() {
        assert_eq!(unsafe { magic_tagged_object_entry_count(core::ptr::null()) }, 0);

        let object = object_with(!MAGIC_TAGGED_OBJECT_TAG, 0xdead_beef);
        assert_eq!(unsafe { magic_tagged_object_entry_count(object.as_ptr()) }, 0);
    }
}
