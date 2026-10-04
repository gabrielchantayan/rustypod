//! Packed-selector classification used by the selector validation/registration path.
//!
//! Original: `FUN_081f31a0` at load address `0x081f31a0`, 140 bytes,
//! extent `[0x081f31a0, 0x081f322c)` verified from raw ARM words and the
//! next independent push prologue. Two inbound plain BLs (`0x081f361c`,
//! `0x081f3798`), zero predicated inbound BLs; zero outbound BLs of either kind.
//!
//! Decode the low five bits and bits 17..23. Low tag zero maps codes 1..3
//! to classes 0..2; tag fourteen maps codes 1..6 to 3,4,5,6,8,7 respectively.
//! Every other combination returns sentinel 9. The callers store the class
//! and distinguish classes below three and invalid class nine.
//! Deliberate deviations: none in behavior; numeric classes remain unnamed
//! because the callers do not establish their individual domain meanings.

/// Classify a packed selector, ignoring all bits outside `0x00fe001f`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn packed_selector_class(selector: u32) -> u32 {
    let tag = selector & 0x1f;
    let code = selector & 0x00fe0000;
    if tag == 0 {
        if code == 0x20000 { return 0; }
        if code == 0x40000 { return 1; }
        if code == 0x60000 { return 2; }
    } else if tag == 14 {
        if code == 0x80000 { return 6; }
        if code < 0x80000 {
            if code == 0x20000 { return 3; }
            if code == 0x40000 { return 4; }
            if code == 0x60000 { return 5; }
        } else {
            if code == 0xa0000 { return 8; }
            if code == 0xc0000 { return 7; }
        }
    }
    9
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_tag_and_code_combinations_match_the_verified_mapping() {
        let valid = [
            (0, 1, 0), (0, 2, 1), (0, 3, 2),
            (14, 1, 3), (14, 2, 4), (14, 3, 5),
            (14, 4, 6), (14, 5, 8), (14, 6, 7),
        ];
        for tag in 0..32 {
            for code in 0..128 {
                let expected = valid.iter()
                    .find(|&&(valid_tag, valid_code, _)| tag == valid_tag && code == valid_code)
                    .map_or(9, |&(_, _, class)| class);
                assert_eq!(packed_selector_class(tag | (code << 17)), expected,
                    "tag={tag}, code={code}");
            }
        }
    }

    #[test]
    fn ignored_bits_do_not_change_valid_or_invalid_classes() {
        let ignored = !0x00fe001fu32;
        for selector in [0, 0x20000, 0x40000, 0x60000, 14,
                         0x2000e, 0x4000e, 0x6000e, 0x8000e,
                         0xa000e, 0xc000e, 0xe000e, 0xfe001f] {
            let expected = packed_selector_class(selector);
            for bit in 0..32 {
                let noise = (1u32 << bit) & ignored;
                assert_eq!(packed_selector_class(selector | noise), expected);
            }
            assert_eq!(packed_selector_class(selector | ignored), expected);
        }
        assert_eq!(packed_selector_class(u32::MAX), 9);
    }
}
