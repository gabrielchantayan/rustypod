//! `opaque_layout_initialize` — original: `FUN_082e7bf0` @ **0x082e7bf0**
//! (76 bytes, body 0x082e7bf0..0x082e7c3c; literal at 0x082e7c3c).
//!
//! Raw words establish the boundary: the next separately linked function begins
//! at 0x082e7c40. Whole-image ARM branch decoding finds three inbound BL calls:
//! two plain (`0x080ccbfc`, `0x08261db0`) and one predicated `blne`
//! (`0x082e813c`).
//!
//! Algorithm: reject a null layout with retailOS status `0x1a`; otherwise write
//! the ten-word opaque layout record's fixed tag and defaults, then return zero.
//! Deliberate deviation: word-indexed writes replace the original STM/STR
//! register order, preserving every observable word value and status.

const NULL_POINTER_STATUS: u32 = 0x1a;
const OPAQUE_LAYOUT_TAG: u32 = 0x5054_4841;

/// Initializes the 40-byte retailOS opaque layout record.
///
/// # Safety
/// `layout` must be null or point to ten writable, properly aligned `u32`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_layout_initialize")]
#[inline(never)]
pub unsafe extern "C" fn opaque_layout_initialize(layout: *mut u32) -> u32 {
    if layout.is_null() {
        return NULL_POINTER_STATUS;
    }

    *layout.add(0) = OPAQUE_LAYOUT_TAG;
    *layout.add(1) = 0;
    *layout.add(2) = 1;
    *layout.add(3) = 0;
    *layout.add(4) = 0x800;
    *layout.add(5) = 0;
    *layout.add(6) = 2;
    *layout.add(7) = 1;
    *layout.add(8) = 1;
    *layout.add(9) = 0;
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_null_layout() {
        assert_eq!(unsafe { opaque_layout_initialize(core::ptr::null_mut()) }, NULL_POINTER_STATUS);
    }

    #[test]
    fn replaces_every_layout_word_with_retail_defaults() {
        let mut layout = [u32::MAX; 10];

        assert_eq!(unsafe { opaque_layout_initialize(layout.as_mut_ptr()) }, 0);
        assert_eq!(layout, [OPAQUE_LAYOUT_TAG, 0, 1, 0, 0x800, 0, 2, 1, 1, 0]);
    }
}
