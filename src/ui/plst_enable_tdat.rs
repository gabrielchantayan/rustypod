//! Enable the associated TDAT element of a 'plst' UI element.

use super::plst_class_check::ui_element_is_plst_class;
use super::tdat_flag_20_bit_2::tdat_element_set_flag_20_bit_2;

/// Original: `FUN_0805d31c` @ `0x0805d31c`, 36 bytes, ending at the
/// next push prologue at `0x0805d340`. Whole-image aligned A32 decoding
/// verifies two inbound plain BLs (0x08067340, 0x0806743c), zero predicated
/// BLs; the body has one plain BL to 0x080613e0, zero predicated BLs,
/// and a BNE tail call to 0x08067b4c.
///
/// Returns zero for NULL or a non-'plst' element, without reading +0x0c.
/// Otherwise reads the target-width pointer at +0x0c and enables its TDAT
/// flag byte bit 2 via the existing setter, returning that setter's result.
/// The associated pointer is not NULL-checked, matching retailOS.
/// Deliberate deviations: calls the two existing Rust ports rather than
/// stock addresses; LLVM controls whether the final call is a tail branch.
///
/// # Safety
/// A non-NULL element must be aligned and readable through +0x07. A 'plst'
/// element must additionally contain a readable u32 pointer at +0x0c whose
/// target satisfies `tdat_element_set_flag_20_bit_2`'s safety contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn plst_enable_tdat(element: *const u8) -> u32 {
    if ui_element_is_plst_class(element) == 0 {
        return 0;
    }
    let associated = element.cast::<u32>().add(3).read() as usize as *mut u8;
    tdat_element_set_flag_20_bit_2(associated, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_elements_do_not_read_associated_pointer() {
        unsafe {
            assert_eq!(plst_enable_tdat(core::ptr::null()), 0);
            // Exactly the two readable words required by the class check:
            // reading the associated pointer would exceed this object.
            for tag in [0, 0x7464_6174, 0xffff_ffff, 0x706c_7375] {
                let element = [0u32, tag];
                assert_eq!(plst_enable_tdat(element.as_ptr().cast()), 0);
            }
        }
    }

    #[test]
    fn already_enabled_associated_element_preserves_all_flags() {
        let Some(associated) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PLST_ENABLE_TDAT, 4096,
        ) else { return; };
        unsafe {
            associated.cast::<u32>().add(1).write(0x7464_6174);
            let element = [0u32, 0x706c_7374, 0xdead_beef, associated as usize as u32];
            for flags in [4u8, 0x85, 0xff] {
                associated.add(0x20).write(flags);
                associated.add(0x40).cast::<u16>().write(0x1234);
                assert_eq!(plst_enable_tdat(element.as_ptr().cast()), u32::from(flags));
                assert_eq!(associated.add(0x20).read(), flags);
                assert_eq!(associated.add(0x40).cast::<u16>().read(), 0x1234);
            }
        }
    }
}
