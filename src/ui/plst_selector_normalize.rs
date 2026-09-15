//! 'plst' selector normalization shared by indexed item and position lookups.

/// Element byte offset containing selector-mode flags.
const SELECTOR_FLAGS_OFFSET: usize = 0x18c;
/// Element byte offset containing reverse-direction flags.
const REVERSE_FLAGS_OFFSET: usize = 0x18d;
/// Element word offset containing the configured selector/state.
const SELECTOR_STATE_OFFSET: usize = 0xc8;

/// normalize_plst_selector — original: `FUN_080b48dc` @ 0x080b48dc (200 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x080b48dc..0x080b49a4`; the next function begins with `cmp r0, #0` at
/// 0x080b49a4. Decoding all branch-with-link words in the firmware finds ten
/// incoming plain `bl` calls and zero predicated `bl` calls; this leaf has no
/// outgoing calls.
///
/// Algorithm: selectors 0x34 and 0x37 become 4. Selector 0x33 selects the
/// element word at +0xc8 when flag +0x18c bit 0 is clear; otherwise it becomes
/// 2 and, unless that word is 1 or 2 (or `reverse_flag` is NULL), clears the
/// reverse flag byte. A resulting selector of zero becomes 1. Selector 0x35
/// becomes 1 when +0x18c bit 5 is clear, otherwise 4. Selector 0x36 becomes
/// the +0xc8 word and rewrites a non-NULL reverse flag from +0x18d bit 2,
/// inverted when its incoming byte was nonzero. Other selectors are unchanged.
///
/// Deliberate deviations: none. Rust's structured branches preserve the ARM
/// predication and its byte/word access widths.
///
/// # Safety
/// `selector` must be non-NULL and writable. `element` must point to a
/// readable object through +0x18d and +0xc8. When non-NULL, `reverse_flag`
/// must be writable for one byte.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_plst_selector_normalize")]
pub unsafe extern "C" fn normalize_plst_selector(
    element: *mut u8,
    selector: *mut u32,
    reverse_flag: *mut u8,
) {
    let original_selector = selector.read();
    match original_selector {
        0x34 | 0x37 => selector.write(4),
        0x33 => {
            let selector_flags = element.add(SELECTOR_FLAGS_OFFSET).read();
            if selector_flags & 1 == 0 {
                selector.write(element.add(SELECTOR_STATE_OFFSET).cast::<u32>().read());
            } else {
                selector.write(2);
                let state = if reverse_flag.is_null() {
                    0
                } else {
                    element.add(SELECTOR_STATE_OFFSET).cast::<u32>().read()
                };
                if reverse_flag.is_null() || state == 1 || state == 2 {
                    return;
                }
                reverse_flag.write(0);
            }
            if selector.read() == 0 {
                selector.write(1);
            }
        }
        0x35 => {
            if element.add(SELECTOR_FLAGS_OFFSET).read() & 0x20 == 0 {
                selector.write(1);
            } else {
                selector.write(4);
            }
        }
        0x36 => {
            selector.write(element.add(SELECTOR_STATE_OFFSET).cast::<u32>().read());
            if reverse_flag.is_null() {
                return;
            }
            let reverse_flags = element.add(REVERSE_FLAGS_OFFSET).read();
            let reverse = if reverse_flag.read() == 0 {
                (reverse_flags >> 2) & 1
            } else {
                !(reverse_flags >> 2) & 1
            };
            reverse_flag.write(reverse);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Element([u8; 0x190]);

    fn element(flags: u8, reverse_flags: u8, state: u32) -> Element {
        let mut element = Element([0; 0x190]);
        element.0[SELECTOR_FLAGS_OFFSET] = flags;
        element.0[REVERSE_FLAGS_OFFSET] = reverse_flags;
        element.0[SELECTOR_STATE_OFFSET..SELECTOR_STATE_OFFSET + 4].copy_from_slice(&state.to_le_bytes());
        element
    }

    #[test]
    fn normalizes_special_selectors_and_zero_state() {
        let mut object = element(0, 0, 0);
        for selector_value in [0x34, 0x37] {
            let mut selector = selector_value;
            unsafe { normalize_plst_selector(object.0.as_mut_ptr(), &mut selector, core::ptr::null_mut()) };
            assert_eq!(selector, 4);
        }
        let mut selector = 0x33;
        unsafe { normalize_plst_selector(object.0.as_mut_ptr(), &mut selector, core::ptr::null_mut()) };
        assert_eq!(selector, 1);
    }

    #[test]
    fn selector_33_preserves_or_clears_reverse_flag_as_arm_predication_requires() {
        let mut object = element(1, 0, 3);
        let mut selector = 0x33;
        let mut reverse = 1;
        unsafe { normalize_plst_selector(object.0.as_mut_ptr(), &mut selector, &mut reverse) };
        assert_eq!((selector, reverse), (2, 0));

        object.0[SELECTOR_STATE_OFFSET..SELECTOR_STATE_OFFSET + 4].copy_from_slice(&2u32.to_le_bytes());
        selector = 0x33;
        reverse = 1;
        unsafe { normalize_plst_selector(object.0.as_mut_ptr(), &mut selector, &mut reverse) };
        assert_eq!((selector, reverse), (2, 1));
    }

    #[test]
    fn selector_35_and_36_use_the_correct_flag_bits() {
        let mut object = element(0, 4, 0x1234);
        let mut selector = 0x35;
        unsafe { normalize_plst_selector(object.0.as_mut_ptr(), &mut selector, core::ptr::null_mut()) };
        assert_eq!(selector, 1);
        object.0[SELECTOR_FLAGS_OFFSET] = 0x20;
        selector = 0x35;
        unsafe { normalize_plst_selector(object.0.as_mut_ptr(), &mut selector, core::ptr::null_mut()) };
        assert_eq!(selector, 4);

        selector = 0x36;
        let mut reverse = 0;
        unsafe { normalize_plst_selector(object.0.as_mut_ptr(), &mut selector, &mut reverse) };
        assert_eq!((selector, reverse), (0x1234, 1));
        reverse = 1;
        selector = 0x36;
        unsafe { normalize_plst_selector(object.0.as_mut_ptr(), &mut selector, &mut reverse) };
        assert_eq!(reverse, 0);
    }
}
