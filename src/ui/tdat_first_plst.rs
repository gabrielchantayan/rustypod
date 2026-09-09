//! The 'tdat' UI element's first linked 'plst' element.
//!
//! - `ui_tdat_first_plst` — original: `FUN_080522d4` @ 0x080522d4
//!   (24 bytes; 17 direct `bl` call sites, 0 predicated, verified by
//!   decoding every B/BL word in `osos.dec`).

use crate::ui::tdat_class_check::ui_element_is_tdat_class;

/// Byte offset of the first linked 'plst' element word (`ldrne r0,[r2,#0x34]`).
const FIRST_PLST_OFFSET: usize = 0x34;

/// ui_tdat_first_plst — original: `FUN_080522d4` @ 0x080522d4 (24 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x080522d4..0x080522ec`; the next function begins with `cmp r0,#0` at
/// `0x080522ec`, confirming Ghidra's 24-byte extent:
///
/// ```text
/// 080522d4  mov r2, r0
/// 080522d8  push {lr}
/// 080522dc  bl 0x0806aa3c       ; ui_element_is_tdat_class
/// 080522e0  movs r0, r0
/// 080522e4  ldrne r0, [r2, #0x34]
/// 080522e8  pop {pc}
/// ```
///
/// Algorithm: validate `element` as a 'tdat' UI element, then return the
/// word at `element + 0x34`; return zero for every other input. The stored
/// word is the first 'plst' element in the element's linked sequence:
/// caller 0x08050ae0 starts there and repeatedly invokes the 'plst'
/// successor selector 0x08053bd0, while callers 0x0805473c and 0x080561cc
/// inspect the resulting 'plst' element's flag byte at +0x1ac.
///
/// All 17 recovered call sites are unconditional `bl` instructions; none is
/// predicated. This matches the internal 'tdat' validation rather than a
/// caller-side class guard. Deliberate deviations: none. The aligned word
/// load matches the original `ldr`; the port calls the already-ported
/// predicate directly instead of branching to its retailOS address.
///
/// # Safety
///
/// `element` may be NULL. A non-NULL pointer must be readable through +0x7
/// for the class predicate; if it has the 'tdat' tag it must also be readable
/// through +0x37 for the returned word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_tdat_first_plst")]
pub unsafe extern "C" fn ui_tdat_first_plst(element: *const u8) -> u32 {
    if ui_element_is_tdat_class(element) != 0 {
        element.add(FIRST_PLST_OFFSET).cast::<u32>().read()
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    const PLST_CLASS_TAG: u32 = 0x706c_7374;

    fn tdat_element(first_plst: u32) -> [u32; 14] {
        let mut element = [0u32; 14];
        element[1] = TDAT_CLASS_TAG;
        element[FIRST_PLST_OFFSET / core::mem::size_of::<u32>()] = first_plst;
        element
    }

    #[test]
    fn null_element_returns_zero() {
        assert_eq!(unsafe { ui_tdat_first_plst(core::ptr::null()) }, 0);
    }

    #[test]
    fn tdat_element_returns_its_first_plst_word() {
        for first_plst in [0, 0x0804_7bfc, 0x2200_aed8, u32::MAX] {
            let element = tdat_element(first_plst);
            assert_eq!(
                unsafe { ui_tdat_first_plst(element.as_ptr().cast()) },
                first_plst
            );
        }
    }

    #[test]
    fn other_class_tag_returns_zero_even_with_link_word() {
        let mut element = tdat_element(0x0804_7bfc);
        element[1] = PLST_CLASS_TAG;
        assert_eq!(unsafe { ui_tdat_first_plst(element.as_ptr().cast()) }, 0);
    }

    #[test]
    fn only_word_at_offset_34_is_returned() {
        let mut element = tdat_element(0x1020_3040);
        element[FIRST_PLST_OFFSET / core::mem::size_of::<u32>() - 1] = 0xdead_beef;
        assert_eq!(
            unsafe { ui_tdat_first_plst(element.as_ptr().cast()) },
            0x1020_3040
        );
    }
}
