//! OpenSSL's null-safe `BIO_next` accessor.
//!
//! Port: `bio_next` — `FUN_0803d670` @ 0x0803d670 (16 bytes,
//! 0x0803d670..0x0803d680; the next function is `BIO_printf`). Raw A32
//! decoding verifies two inbound plain BL calls (0x0805fcb8, 0x08060738),
//! zero predicated BL calls, and no outbound calls.
//!
//! Returns null for a null BIO; otherwise returns its `next_bio` word at
//! +0x24 without dereferencing the successor. Both callers advance searches
//! for digest BIOs through this link. Deliberate deviations: none; the stored
//! pointer remains target-width even on hosts.

use crate::crypto::bio_ctrl::Bio;

/// Returns the next BIO, or null when `bio` is null or has no successor.
///
/// # Safety
///
/// A non-null `bio` must be aligned and readable through its `next_bio` field.
/// The successor need not be readable; this function does not follow it.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bio_next(bio: *const Bio) -> *mut Bio {
    if bio.is_null() {
        core::ptr::null_mut()
    } else {
        unsafe { (*bio).next_bio as usize as *mut Bio }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_bio_returns_null() {
        assert!(unsafe { bio_next(core::ptr::null()) }.is_null());
    }

    #[test]
    fn successor_is_exact_target_word_and_is_not_followed() {
        let mut bio: Bio = unsafe { core::mem::zeroed() };
        bio._ptr = 0x12345678;
        bio._prev_bio = 0x87654321;
        for successor in [0, 1, 0x08001234, 0x80000000, u32::MAX] {
            bio.next_bio = successor;
            assert_eq!(unsafe { bio_next(&bio) } as usize, successor as usize);
            assert_eq!(bio.next_bio, successor);
            assert_eq!(bio._ptr, 0x12345678);
            assert_eq!(bio._prev_bio, 0x87654321);
        }
    }
}
