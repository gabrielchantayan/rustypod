//! Validate continuation forms in a permissive retail UTF-8 C string.
//!
//! Original: `thunk_FUN_08276c70` @ **0x08276c1c**, true extent **104 bytes**
//! (`0x08276c1c..0x08276c84`; next entry pushes r3-r11 and lr). Raw entry word
//! `0xea000013` branches to 0x08276c70, whose loop returns to 0x08276c20;
//! Ghidra's four-byte thunk boundary splits this single routine. Whole-image
//! A32 decoding verifies two plain inbound BLs (0x08119af8, 0x0812e11c), zero
//! predicated inbound BLs, and zero plain or predicated outbound BLs.
//!
//! Algorithm: return one on a NUL lead; advance over ASCII; check one
//! continuation for c0-df and two for e0-ef. All other high-bit leads skip
//! two following bytes without checking them. Overlong encodings and UTF-16
//! surrogates are accepted. NULs consumed inside a high-bit window do not end
//! the scan. No deliberate behavioral deviations; Rust expresses the entry
//! branch and shared loop as one function, with no retail callee seam.

/// Returns one for retail-valid text, zero for a malformed continuation.
///
/// # Safety
/// `text` must be non-NULL and readable through every consumed window and the
/// eventual NUL lead. A high-bit lead can consume bytes past an embedded NUL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn utf8_validate_c_string_permissive(mut text: *const u8) -> u32 {
    loop {
        let lead = unsafe { text.read_volatile() };
        if lead == 0 {
            return 1;
        }
        text = unsafe { text.add(1) };
        if lead & 0x80 == 0 {
            continue;
        }
        let second = unsafe { text.read_volatile() };
        text = unsafe { text.add(1) };
        if lead & 0xe0 == 0xc0 {
            if second & 0xc0 != 0x80 {
                return 0;
            }
            continue;
        }
        let third = unsafe { text.read_volatile() };
        text = unsafe { text.add(1) };
        if lead & 0xf0 == 0xe0 && (second & 0xc0 != 0x80 || third & 0xc0 != 0x80) {
            return 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::utf8_validate_c_string_permissive;

    fn validate(bytes: &[u8]) -> u32 {
        unsafe { utf8_validate_c_string_permissive(bytes.as_ptr()) }
    }

    #[test]
    fn ascii_and_nul_lead_terminate() {
        assert_eq!(validate(b"\0"), 1);
        assert_eq!(validate(b"iPod Classic\0"), 1);
        assert_eq!(validate(&[0, 0xc0, 0]), 1);
        assert_eq!(validate(&[b'A', 0xc2, 0xa2, 0xe2, 0x82, 0xac, b'Z', 0]), 1);
    }

    #[test]
    fn checks_every_continuation_byte_value() {
        for lead in 0xc0..=0xdf {
            for second in 0u8..=255 {
                assert_eq!(validate(&[lead, second, 0]), u32::from(second & 0xc0 == 0x80));
            }
        }
        for lead in 0xe0..=0xef {
            for byte in 0u8..=255 {
                let expected = u32::from(byte & 0xc0 == 0x80);
                assert_eq!(validate(&[lead, byte, 0x80, 0]), expected);
                assert_eq!(validate(&[lead, 0x80, byte, 0]), expected);
            }
        }
    }

    #[test]
    fn accepts_overlong_and_surrogate_encodings() {
        assert_eq!(validate(&[0xc0, 0x80, 0xe0, 0x80, 0x80, 0xed, 0xa0, 0x80, 0]), 1);
    }

    #[test]
    fn unsupported_leads_skip_exactly_two_bytes_including_nuls() {
        for lead in (0x80..=0xbf).chain(0xf0..=0xff) {
            assert_eq!(validate(&[lead, 0, 0, 0]), 1);
            assert_eq!(validate(&[lead, 0xc0, 0xff, b'A', 0]), 1);
            assert_eq!(validate(&[lead, 0, 0, 0xc2, b'A', 0]), 0);
        }
        // A standard four-byte sequence leaves its final continuation as a
        // new unsupported lead; the following malformed pair is skipped.
        assert_eq!(validate(&[0xf0, 0x9f, 0x92, 0xa9, 0xc0, 0, 0]), 1);
    }
}
