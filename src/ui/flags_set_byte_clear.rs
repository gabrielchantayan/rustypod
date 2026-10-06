//! UI-element flag-word and clear-byte predicate.
//!
//! `ui_element_flags_set_byte_clear` — original: `FUN_0815cae0` @
//! `0x0815cae0`, 44 bytes (`0x0815cae0..0x0815cb0c`); the next function
//! begins with `cmp r1, #0`. Whole-image A32 decoding finds two incoming
//! plain BLs (0x08126058, 0x082246d0), zero predicated incoming BLs.
//! The body has one plain BL to `ui_element_has_nonzero_flags` @
//! 0x0815d7d4 and zero predicated BLs.
//!
//! Query the complete aligned flag word at +0x48 using the existing port.
//! If it is zero, return zero without reading +0x4c. Otherwise return one
//! exactly when byte +0x4c is zero, and zero for every nonzero byte.
//! Deliberate deviations: none; the byte's broader meaning is not assumed.

use crate::ui::nonzero_flags::ui_element_has_nonzero_flags;

/// # Safety
/// `element + 0x48` must hold a readable aligned u32. If that word is nonzero,
/// `element + 0x4c` must also be readable. No pointer field is dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_flags_set_byte_clear(element: *const u8) -> u32 {
    if ui_element_has_nonzero_flags(element) == 0 {
        return 0;
    }
    (element.add(0x4c).read() == 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Element {
        prefix: [u32; 18],
        flags: u32,
        byte: u8,
        suffix: [u8; 3],
    }

    #[test]
    fn complete_flag_word_and_every_byte_value() {
        for flags in [0, 1, 2, 0x800, 0x8000_0000, u32::MAX] {
            for byte in 0..=u8::MAX {
                let element = Element {
                    prefix: [u32::MAX; 18],
                    flags,
                    byte,
                    suffix: [0xff; 3],
                };
                let expected = if flags != 0 && byte == 0 { 1 } else { 0 };
                assert_eq!(unsafe {
                    ui_element_flags_set_byte_clear(core::ptr::addr_of!(element).cast())
                }, expected, "flags={flags:#x}, byte={byte:#x}");
            }
        }
    }

    #[test]
    fn zero_flags_need_no_following_byte() {
        let element = [0u32; 19];
        assert_eq!(unsafe { ui_element_flags_set_byte_clear(element.as_ptr().cast()) }, 0);
    }
}
