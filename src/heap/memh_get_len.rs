//! `memh_get_len` — original: `FUN_0805d0cc` @ 0x0805d0cc (36 instruction
//! bytes, followed by the separate `"MemH"` literal at 0x0805d0f0).
//!
//! Raw `osos.dec` words establish the body through `bx lr` at 0x0805d0ec;
//! 0x0805d0f0 is the `0x4d656d48` literal and 0x0805d0f4 begins the next
//! function. Decoding every aligned ARM `BL` word finds four inbound plain
//! `bl` calls (0x0805d204, 0x080916e0, 0x0809bda8, and 0x080d2418) and no
//! predicated `bl` calls.
//!
//! Returns a MemH buffer header's +0x0c length only when the pointer is
//! non-NULL and its +0x04 word is `"MemH"`; otherwise returns zero.
//!
//! Deliberate deviation: the Rust comparison uses the shared `MEMH_MAGIC`
//! constant instead of this function's PC-relative literal load. The
//! target-width `MemhBufferHeader` preserves the original word offsets on
//! host and target.

use crate::heap::memh_handle::MEMH_MAGIC;
use crate::heap::memh_set_len::MemhBufferHeader;

/// Returns the used length of a valid MemH buffer header, or zero.
///
/// # Safety
///
/// A non-NULL `header` must point to an aligned, readable
/// [`MemhBufferHeader`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn memh_get_len(header: *const MemhBufferHeader) -> u32 {
    if header.is_null() || (*header).magic != MEMH_MAGIC {
        0
    } else {
        (*header).length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_zero_for_null_or_non_memh_header() {
        let invalid = MemhBufferHeader {
            payload: 0x1234_5678,
            magic: 0,
            capacity: 32,
            length: 29,
        };

        assert_eq!(unsafe { memh_get_len(core::ptr::null()) }, 0);
        assert_eq!(unsafe { memh_get_len(&invalid) }, 0);
    }

    #[test]
    fn returns_length_at_target_word_offset() {
        let header = MemhBufferHeader {
            payload: 0,
            magic: MEMH_MAGIC,
            capacity: u32::MAX,
            length: 0xdead_beef,
        };

        assert_eq!(unsafe { memh_get_len(&header) }, 0xdead_beef);
    }
}
