//! Nonzero UI-element flag-word query.
//!
//! `ui_element_has_nonzero_flags` — original: `FUN_0815d7d4` @
//! `0x0815d7d4` (16 bytes; 10 binary-verified direct `bl` call sites, all
//! unconditional).
//!
//! Raw `osos.dec` establishes the exact extent `0x0815d7d4..0x0815d7e4`:
//! `ldr r0, [r0, #0x48]; cmp r0, #0; movne r0, #1; bx lr`. It reads the
//! UI element's aligned flag word at `element + 0x48` and returns 1 exactly
//! when the complete word is nonzero, otherwise 0. The function has no NULL
//! or alignment guard. Whole-image ARM B/BL decoding finds ten plain `bl`
//! callers at `0x08125e90`, `0x0815cae8`, `0x0815d074`, `0x0815d19c`,
//! `0x0815d230`, `0x0815d4f0`, `0x0815dcd4`, `0x0819ab4c`, `0x0819ab60`, and
//! `0x0819ac70`; there are no predicated calls, direct tail branches, or
//! aligned data words containing this address.
//!
//! Deliberate deviations: none.

/// Byte offset of the UI element flag word loaded by the retail helper.
const FLAGS_OFFSET: usize = 0x48;

/// Returns whether a UI element's complete flag word is nonzero.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_has_nonzero_flags(element: *const u8) -> u32 {
    (element.add(FLAGS_OFFSET).cast::<u32>().read() != 0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Element {
        before_flags: [u32; FLAGS_OFFSET / core::mem::size_of::<u32>()],
        flags: u32,
        after_flags: u32,
    }

    fn call(flags: u32) -> u32 {
        let element = Element {
            before_flags: [0xa5a5_a5a5; FLAGS_OFFSET / core::mem::size_of::<u32>()],
            flags,
            after_flags: 0x5a5a_5a5a,
        };

        unsafe { ui_element_has_nonzero_flags(core::ptr::addr_of!(element).cast()) }
    }

    #[test]
    fn zero_flag_word_returns_zero() {
        assert_eq!(call(0), 0);
    }

    #[test]
    fn each_nonzero_word_form_returns_one() {
        for flags in [1, 2, 0x800, 0x8000_0000, u32::MAX] {
            assert_eq!(call(flags), 1, "flags={flags:#010x}");
        }
    }

    #[test]
    fn only_reads_the_flag_word_at_offset_48() {
        let mut element = Element {
            before_flags: [u32::MAX; FLAGS_OFFSET / core::mem::size_of::<u32>()],
            flags: 0,
            after_flags: u32::MAX,
        };

        assert_eq!(unsafe { ui_element_has_nonzero_flags(core::ptr::addr_of!(element).cast()) }, 0);
        element.flags = 0x800;
        assert_eq!(unsafe { ui_element_has_nonzero_flags(core::ptr::addr_of!(element).cast()) }, 1);
    }
}
