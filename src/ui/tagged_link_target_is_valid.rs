//! `tagged_link_target_is_valid` — original: `FUN_080c67b8` @ 0x080c67b8 (48 bytes).
//!
//! The next independently entered body begins at 0x080c67e8, immediately
//! after this routine's twelve ARM words, establishing the 48-byte extent.
//! Raw `osos.dec` decoding finds no outbound calls. Four direct callers target
//! this address, all plain `bl` instructions (at 0x0804880c, 0x08048934,
//! 0x0805bc54, and 0x08066c2c); there are no predicated `bl` callers.
//!
//! # Algorithm
//!
//! Return one exactly when `target` is non-null, its first word is the target
//! link tag, and its word at +0x30 is nonzero; otherwise return zero. The
//! +0x30 word is represented by `TaggedLinkTarget::entry_list_words[9]` to
//! preserve the target's four-byte word layout on 64-bit host tests. No
//! deliberate deviations.

use super::tagged_object_link::{TaggedLinkTarget, LINK_TARGET_TAG};

/// Tests whether a target object has the tag and active word required by the
/// retailOS link operations.
///
/// # Safety
///
/// `target` must be null or a valid, aligned pointer to a complete
/// [`TaggedLinkTarget`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_link_target_is_valid")]
pub unsafe extern "C" fn tagged_link_target_is_valid(target: *const TaggedLinkTarget) -> u32 {
    if target.is_null() {
        return 0;
    }

    let words = target.cast::<u32>();
    u32::from(unsafe { *words == LINK_TARGET_TAG && *words.add(12) != 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(tag: u32, active_word: u32) -> TaggedLinkTarget {
        let mut entry_list_words = [0; 10];
        entry_list_words[9] = active_word;
        TaggedLinkTarget { tag, opaque_04: 0, link_count: 0, entry_list_words }
    }

    #[test]
    fn accepts_only_tagged_targets_with_an_active_word() {
        let valid = target(LINK_TARGET_TAG, 1);
        let wrong_tag = target(LINK_TARGET_TAG ^ 1, 1);
        let inactive = target(LINK_TARGET_TAG, 0);

        assert_eq!(unsafe { tagged_link_target_is_valid(&valid) }, 1);
        assert_eq!(unsafe { tagged_link_target_is_valid(&wrong_tag) }, 0);
        assert_eq!(unsafe { tagged_link_target_is_valid(&inactive) }, 0);
    }

    #[test]
    fn rejects_null_target() {
        assert_eq!(unsafe { tagged_link_target_is_valid(core::ptr::null()) }, 0);
    }
}
