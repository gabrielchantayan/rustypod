//! `magic_tagged_object_validate` — original: `FUN_080d8f64` @
//! **0x080d8f64** (36 bytes).
//!
//! Raw `osos.dec` establishes nine instruction words at
//! 0x080d8f64..0x080d8f84, followed by its literal-pool tag word at
//! 0x080d8f88; the next separately linked function starts at 0x080d8f8c.
//! Decoding every ARM `B`/`BL` immediate in the whole image finds exactly 11
//! direct callers: all are unconditional plain `bl`, with no predicated forms
//! or tail branches.
//!
//! # Algorithm
//!
//! A null pointer returns the retail invalid-argument status `-0x32` without
//! reading memory. A non-null object's first word must equal the literal tag
//! `0x534c7374`; matching objects return zero and every other tag returns
//! `-0x32`. The tag does not establish a recoverable class identity, so this
//! module deliberately uses a structural name and introduces no dispatch seam.
//!
//! Deliberate deviations: none.

/// The opaque first-word tag required by [`magic_tagged_object_validate`].
pub const MAGIC_TAGGED_OBJECT_TAG: u32 = 0x534c_7374;

/// Target-width prefix read by [`magic_tagged_object_validate`].
#[repr(C)]
pub struct MagicTaggedObject {
    /// +0x00: opaque type tag.
    pub tag: u32,
}

/// Checks whether an opaque object has the required first-word tag.
///
/// # Safety
///
/// A non-null `object` must point to a readable, four-byte-aligned
/// [`MagicTaggedObject`]. The retail `ldr` has no other bounds or lifetime
/// guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.magic_tagged_object_validate")]
#[inline(never)]
pub unsafe extern "C" fn magic_tagged_object_validate(object: *const MagicTaggedObject) -> i32 {
    if object.is_null() {
        return -0x32;
    }

    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*object).tag)) }
        == MAGIC_TAGGED_OBJECT_TAG
    {
        0
    } else {
        -0x32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_tag_returns_success() {
        let object = MagicTaggedObject {
            tag: MAGIC_TAGGED_OBJECT_TAG,
        };

        assert_eq!(unsafe { magic_tagged_object_validate(&object) }, 0);
    }

    #[test]
    fn null_and_nonmatching_tags_return_invalid_argument() {
        assert_eq!(unsafe { magic_tagged_object_validate(core::ptr::null()) }, -0x32);

        for tag in [0, MAGIC_TAGGED_OBJECT_TAG - 1, !MAGIC_TAGGED_OBJECT_TAG, u32::MAX] {
            let object = MagicTaggedObject { tag };
            assert_eq!(unsafe { magic_tagged_object_validate(&object) }, -0x32);
        }
    }
}
