//! Settings-item target selection.
//!
//! `FUN_08153534` @ load address 0x08153534: 28 instruction bytes,
//! extent [0x08153534, 0x08153550), followed by a real push prologue.
//! Whole-image raw A32 decoding verifies two incoming plain BL calls
//! (0x08067fc4, 0x0806b89c), zero predicated BL calls, and no outgoing calls.
//! Selector 0 returns record word +4; selector 1 returns word +0; other
//! selectors return zero without reading the record. Callers use selector 1
//! as an object pointer for virtual dispatch. Deliberate deviations: none;
//! pointer words remain u32 even on hosts, rather than native-width pointers.

/// Select a target address from the first two words of a settings item.
///
/// # Safety
/// For selector 0, `item` must permit an aligned u32 read at +4; for
/// selector 1, at +0. Other selectors do not require a valid pointer.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn settings_item_select(item: *const u8, selector: u32) -> u32 {
    match selector {
        0 => item.cast::<u32>().add(1).read(),
        1 => item.cast::<u32>().read(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_read_reversed_word_order_and_preserve_all_bits() {
        for words in [[0x1234_5678, 0xfedc_ba98], [0, u32::MAX], [u32::MAX, 0]] {
            let item = words.as_ptr().cast::<u8>();
            assert_eq!(unsafe { settings_item_select(item, 0) }, words[1]);
            assert_eq!(unsafe { settings_item_select(item, 1) }, words[0]);
            assert_eq!(words, unsafe { *(item.cast::<[u32; 2]>()) });
        }
    }

    #[test]
    fn invalid_selectors_do_not_read_even_a_null_record() {
        for selector in [2, 3, 0x8000_0000, u32::MAX] {
            assert_eq!(unsafe { settings_item_select(core::ptr::null(), selector) }, 0);
        }
    }
}
