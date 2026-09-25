//! `opaque_tagged_object_word_at_20` — original: `FUN_0805228c` @
//! **0x0805228c** (20 bytes).
//!
//! Raw `osos.dec` establishes five ARM instruction words at
//! 0x0805228c..0x080522a0; the next independently callable accessor begins at
//! 0x080522a4. The body has one outbound plain `bl` to 0x08057c2c and no
//! predicated `bl` forms. Whole-image ARM decoding identifies three inbound
//! plain `bl` callsites and no predicated inbound calls.
//!
//! # Algorithm
//!
//! A null object, or an object whose first word differs from the opaque tag
//! `0x6974696c`, returns zero. A matching object returns its word at +0x20.
//! The tag and its original predicate helper's class identity are unrecovered,
//! so this port uses structural names and no callee seam.
//!
//! Deliberate deviation: the five-instruction wrapper's call to the unported
//! predicate at 0x08057c2c is inlined as its verified null-and-tag comparison.

/// Opaque first-word tag required for the +0x20 payload accessor.
pub const OPAQUE_TAGGED_OBJECT_TAG: u32 = 0x6974_696c;

/// Target-width prefix read by [`opaque_tagged_object_word_at_20`].
#[repr(C)]
pub struct OpaqueTaggedObjectWordAt20 {
    /// +0x00: opaque type tag.
    pub tag: u32,
    /// +0x04..+0x1c: unrecovered object data.
    pub prefix: [u32; 7],
    /// +0x20: payload returned for matching objects.
    pub payload: u32,
}

/// Returns the +0x20 word only for objects with the required opaque tag.
///
/// # Safety
///
/// A non-null `object` must point to a readable, four-byte-aligned
/// [`OpaqueTaggedObjectWordAt20`]. The retail routine performs no bounds or
/// lifetime checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_tagged_object_word_at_20")]
#[inline(never)]
pub unsafe extern "C" fn opaque_tagged_object_word_at_20(
    object: *const OpaqueTaggedObjectWordAt20,
) -> u32 {
    if object.is_null() {
        return 0;
    }

    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*object).tag)) }
        == OPAQUE_TAGGED_OBJECT_TAG
    {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*object).payload)) }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_with(tag: u32, payload: u32) -> OpaqueTaggedObjectWordAt20 {
        OpaqueTaggedObjectWordAt20 {
            tag,
            prefix: [0xa5a5_a5a5; 7],
            payload,
        }
    }

    #[test]
    fn matching_tag_returns_payload() {
        for payload in [0, 1, 0xdead_beef, u32::MAX] {
            let object = object_with(OPAQUE_TAGGED_OBJECT_TAG, payload);
            assert_eq!(unsafe { opaque_tagged_object_word_at_20(&object) }, payload);
        }
    }

    #[test]
    fn null_and_nonmatching_tags_return_zero() {
        assert_eq!(unsafe { opaque_tagged_object_word_at_20(core::ptr::null()) }, 0);

        for tag in [0, OPAQUE_TAGGED_OBJECT_TAG - 1, OPAQUE_TAGGED_OBJECT_TAG + 1, u32::MAX] {
            let object = object_with(tag, 0xdead_beef);
            assert_eq!(unsafe { opaque_tagged_object_word_at_20(&object) }, 0);
        }
    }
}
