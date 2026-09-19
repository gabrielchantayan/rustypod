//! `tagged_link_source_is_valid` — original: `FUN_080b49a4` @ 0x080b49a4 (36 bytes).
//!
//! The literal tag at 0x080b49c8 follows the nine instruction body; the next
//! independently entered function begins at 0x080b49cc, establishing the
//! 36-byte extent. Raw `osos.dec` decoding verifies four direct callers, all
//! plain `bl` instructions (at 0x08048840, 0x080488dc, 0x0805bc44, and
//! 0x08066bd0); there are no predicated `bl` callers. This leaf has no
//! outgoing calls.
//!
//! # Algorithm
//!
//! Return one exactly when `source` is non-null and its first word is the
//! source link tag; otherwise return zero. No deliberate deviations.

use super::tagged_object_link::{TaggedLinkSource, LINK_SOURCE_TAG};

/// Tests whether a source object has the tag required by retailOS link operations.
///
/// # Safety
///
/// `source` must be null or a valid, aligned pointer to a complete
/// [`TaggedLinkSource`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_link_source_is_valid")]
pub unsafe extern "C" fn tagged_link_source_is_valid(source: *const TaggedLinkSource) -> u32 {
    if source.is_null() {
        return 0;
    }

    u32::from(unsafe { source.cast::<u32>().read() == LINK_SOURCE_TAG })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_source_link_tag() {
        let valid = TaggedLinkSource {
            tag: LINK_SOURCE_TAG,
            opaque_04: 0,
            opaque_08: 0,
            link_count: 0,
            entry_list_words: [0; 10],
        };
        let invalid = TaggedLinkSource {
            tag: LINK_SOURCE_TAG ^ 1,
            opaque_04: 0,
            opaque_08: 0,
            link_count: 0,
            entry_list_words: [0; 10],
        };

        assert_eq!(unsafe { tagged_link_source_is_valid(&valid) }, 1);
        assert_eq!(unsafe { tagged_link_source_is_valid(&invalid) }, 0);
    }

    #[test]
    fn rejects_null_source() {
        assert_eq!(unsafe { tagged_link_source_is_valid(core::ptr::null()) }, 0);
    }
}
