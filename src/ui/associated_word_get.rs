//! UI-element associated-word getter.
//!
//! `ui_element_associated_word_get` — `FUN_0815cab0` @ 0x0815cab0.
//! True size: 16 bytes, ending at 0x0815cac0, where a separate r1-based
//! selector begins. Raw words: e5900048 e3500000 1590000c e12fff1e.
//! Whole-image aligned A32 decoding verifies two incoming plain BLs
//! (0x0815cf18, 0x0815e3d0), zero predicated incoming BLs, and zero
//! outgoing plain or predicated BLs.
//!
//! Read the 32-bit associated-object pointer at element +0x48. Return zero
//! for a null pointer; otherwise return the complete word at associated +0xc.
//! Caller 0x0815e390 formats this value using a 1000 divisor and time fields;
//! no stronger identity is assumed. Deliberate deviations: none. Target
//! pointers remain 32-bit words on hosts as well as ARM.

/// # Safety
/// `element` must be four-byte aligned and readable through +0x4b. A nonzero
/// pointer word at +0x48 must identify aligned storage readable through +0xf.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_associated_word_get(element: *const u8) -> u32 {
    let associated = element.add(0x48).cast::<u32>().read();
    if associated == 0 {
        return 0;
    }
    (associated as usize as *const u32).add(3).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_association_needs_only_the_pointer_field() {
        let mut element = [u32::MAX; 19];
        element[18] = 0;
        assert_eq!(unsafe { ui_element_associated_word_get(element.as_ptr().cast()) }, 0);
    }

    #[test]
    fn follows_target_pointer_and_preserves_all_value_bits() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::UI_ELEMENT_ASSOCIATED_WORD_GET, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("ui/associated_word_get"));
            return;
        };
        unsafe {
            let words = slab.cast::<u32>();
            for index in 0..0x1000 / 4 { words.add(index).write(0xa5a5_a5a5); }
            for offset in [0x100usize, 0x200] {
                let associated = slab.add(offset).cast::<u32>();
                words.add(18).write(associated as usize as u32);
                for value in [0, 1, 999, 1000, 0x8000_0000, u32::MAX] {
                    associated.add(3).write(value);
                    assert_eq!(ui_element_associated_word_get(slab), value);
                    assert_eq!(associated.add(2).read(), 0xa5a5_a5a5);
                    assert_eq!(associated.add(4).read(), 0xa5a5_a5a5);
                    assert_eq!(words.add(18).read(), associated as usize as u32);
                }
            }
        }
    }
}
