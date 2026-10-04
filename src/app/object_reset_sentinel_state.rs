//! Object sentinel-state reset.
//!
//! Original: `FUN_08220518` @ `0x08220518`, true size 28 bytes, ending
//! at the independent branch veneer `0x08220534`. Raw words: e3e01000
//! e580189c e58018a0 e3a01000 e5c018a4 e58018a8 e12fff1e.
//! Whole-image A32 decoding finds two plain inbound BLs (0x082203f4,
//! 0x08220568), zero predicated inbound BLs and zero outbound BLs.
//! Stores UINT32_MAX at +0x89c and +0x8a0, clears the byte at +0x8a4,
//! then clears the word at +0x8a8. Both callers retain their object in r4
//! for subsequent cleanup. Field identities beyond these reset values are
//! unestablished. Deliberate deviations: none in memory effects; the void
//! ABI does not promise the original's incidental r0 passthrough. Volatile
//! stores preserve order and the byte-only clear leaves +0x8a5..+0x8a7 intact.

/// # Safety
/// `object` must be writable through +0x8ab and four-byte aligned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_reset_sentinel_state(object: *mut u8) {
    unsafe {
        object.add(0x89c).cast::<u32>().write_volatile(u32::MAX);
        object.add(0x8a0).cast::<u32>().write_volatile(u32::MAX);
        object.add(0x8a4).write_volatile(0);
        object.add(0x8a8).cast::<u32>().write_volatile(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resets_only_selected_fields_including_byte_width() {
        for fill in [0u8, 1, 0x80, 0xa5, 0xff] {
            let mut object = [u32::from_le_bytes([fill; 4]); 0x8b0 / 4];
            let bytes = object.as_mut_ptr().cast::<u8>();
            let mut expected = [fill; 0x8b0];
            expected[0x89c..0x8a4].fill(0xff);
            expected[0x8a4] = 0;
            expected[0x8a8..0x8ac].fill(0);
            unsafe {
                object_reset_sentinel_state(bytes);
                assert_eq!(core::slice::from_raw_parts(bytes, expected.len()), &expected);
            }
        }
    }

    #[test]
    fn repeated_reset_preserves_intervening_bytes_and_new_unrelated_state() {
        let mut object = [0x1234_5678u32; 0x8b0 / 4];
        let bytes = object.as_mut_ptr().cast::<u8>();
        unsafe {
            object_reset_sentinel_state(bytes);
            bytes.add(0x8a5).write(0x81);
            bytes.add(0x8a6).write(0x42);
            bytes.add(0x8a7).write(0xff);
            bytes.add(0x898).cast::<u32>().write(0xfeed_beef);
            object_reset_sentinel_state(bytes);
        }
        assert_eq!(object[0x89c / 4], u32::MAX);
        assert_eq!(object[0x8a0 / 4], u32::MAX);
        assert_eq!(object[0x8a4 / 4], u32::from_le_bytes([0, 0x81, 0x42, 0xff]));
        assert_eq!(object[0x8a8 / 4], 0);
        assert_eq!(object[0x898 / 4], 0xfeed_beef);
        assert_eq!(object[0x8ac / 4], 0x1234_5678);
    }
}
