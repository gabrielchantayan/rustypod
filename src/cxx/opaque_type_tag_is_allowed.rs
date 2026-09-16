//! `opaque_type_tag_is_allowed` — original: `FUN_08382be4` @
//! **0x08382be4** (44 bytes).
//!
//! Raw `osos.dec` establishes eleven instruction words at
//! 0x08382be4..0x08382c10, followed by two literal tag words at
//! 0x08382c10 and 0x08382c14; the next distinct function starts at
//! 0x08382c18. Decoding every aligned ARM branch-with-link immediate in the
//! image finds four direct inbound plain `bl` calls at 0x0837d314,
//! 0x08381638, 0x08390ad8, and 0x08390e84, with no predicated `bl` calls.
//!
//! # Algorithm
//!
//! A null object returns false without a memory access. Otherwise, the word at
//! object offset +0x40 must equal either opaque literal tag `0xa029a697` or
//! `0xf03b7906`. The tag values and object class have no recovered semantic
//! identity, so this module deliberately describes only the verified
//! predicate and introduces no callee seam.
//!
//! Deliberate deviations: none.

/// First accepted opaque type tag.
pub const OPAQUE_TYPE_TAG_A: u32 = 0xa029_a697;
/// Second accepted opaque type tag.
pub const OPAQUE_TYPE_TAG_B: u32 = 0xf03b_7906;

/// Target-width object prefix read by [`opaque_type_tag_is_allowed`].
#[repr(C)]
pub struct OpaqueTypeTaggedObject {
    /// +0x00..+0x3c: unrecovered object data.
    pub prefix: [u32; 16],
    /// +0x40: opaque type tag.
    pub type_tag: u32,
}

/// Checks whether an opaque object carries one of the two accepted type tags.
///
/// # Safety
///
/// A non-null `object` must point to a readable, four-byte-aligned
/// [`OpaqueTypeTaggedObject`]. The retail `ldr` has no other bounds or
/// lifetime guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_type_tag_is_allowed")]
#[inline(never)]
pub unsafe extern "C" fn opaque_type_tag_is_allowed(object: *const OpaqueTypeTaggedObject) -> u32 {
    if object.is_null() {
        return 0;
    }

    let type_tag = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*object).type_tag)) };
    if type_tag == OPAQUE_TYPE_TAG_A {
        1
    } else if type_tag == OPAQUE_TYPE_TAG_B {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_with_tag(type_tag: u32) -> OpaqueTypeTaggedObject {
        OpaqueTypeTaggedObject {
            prefix: [0; 16],
            type_tag,
        }
    }

    #[test]
    fn both_accepted_tags_return_true() {
        for type_tag in [OPAQUE_TYPE_TAG_A, OPAQUE_TYPE_TAG_B] {
            let object = object_with_tag(type_tag);
            assert_eq!(unsafe { opaque_type_tag_is_allowed(&object) }, 1);
        }
    }

    #[test]
    fn null_and_adjacent_nonmatching_tags_return_false() {
        assert_eq!(unsafe { opaque_type_tag_is_allowed(core::ptr::null()) }, 0);

        for type_tag in [
            0,
            OPAQUE_TYPE_TAG_A.wrapping_sub(1),
            OPAQUE_TYPE_TAG_A.wrapping_add(1),
            OPAQUE_TYPE_TAG_B.wrapping_sub(1),
            OPAQUE_TYPE_TAG_B.wrapping_add(1),
            u32::MAX,
        ] {
            let object = object_with_tag(type_tag);
            assert_eq!(unsafe { opaque_type_tag_is_allowed(&object) }, 0);
        }
    }
}
