//! UI-element flag-bit update with invalidation — `FUN_0826ed44` @
//! `0x0826ed44` (44 bytes).
//!
//! ## Verified call sites
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds eight direct
//! calls: seven unconditional `bl` calls at `0x082034bc`, `0x0820350c`,
//! `0x0820366c`, `0x082036fc`, `0x08203768`, `0x0820ade8`, and `0x0820ae38`,
//! plus predicated `bleq` at `0x0816a804`. No tail branch or image data word
//! references this entry. The predicated caller checks its preceding event
//! condition; this body has no NULL guard and immediately loads `element+0x48`.
//!
//! ## Algorithm
//!
//! Compares bit 3 of the flag word at `element+0x48`, normalized to 0 or 1,
//! with `mode`. When they differ it clears the bit for zero `mode`, otherwise
//! sets it, then tail-branches to `ui_element_invalidate_region(element,
//! &element->bounds)`. Thus normal boolean modes update and redraw only on a
//! state change. Non-boolean non-zero modes set the bit, but differ from the
//! normalized current value and therefore still request invalidation.
//!
//! ## Deliberate deviations
//!
//! The ARM tail branch is an ordinary call, preserving its returned `element`
//! pointer. No other deviations.

use crate::ui::invalidate::ui_element_invalidate_region;
use crate::ui::rect::Rect;

/// Flag word offset in the retail UI-element layout.
const FLAGS_OFFSET: usize = 0x48;
/// Bounds rectangle offset in the retail UI-element layout.
const BOUNDS_OFFSET: usize = 0x80;
/// Bit selected by this state update.
const FLAG_BIT_3: u32 = 0x08;

/// ui_element_set_flag_bit_3 — original: `FUN_0826ed44` @ `0x0826ed44`
/// (44 bytes; eight direct `bl` call sites: seven unconditional and one
/// predicated `bleq`).
///
/// Updates bit 3 of `element+0x48` when its normalized value differs from
/// `mode`. A changed comparison passes the element's bounds at `+0x80` to the
/// region invalidator and returns its `element` result. `element` is required
/// to point to a live, word-aligned UI element; retailOS has no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_element_set_flag_bit_3(element: *mut u8, mode: u32) -> *mut u8 {
    let flags_ptr = element.add(FLAGS_OFFSET).cast::<u32>();
    let flags = flags_ptr.read();
    let current_mode = (flags & FLAG_BIT_3) >> 3;

    if current_mode == mode {
        return element;
    }

    flags_ptr.write(if mode == 0 {
        flags & !FLAG_BIT_3
    } else {
        flags | FLAG_BIT_3
    });
    ui_element_invalidate_region(element, element.add(BOUNDS_OFFSET).cast::<Rect>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct UiElementFixture {
        _before_flags: [u8; FLAGS_OFFSET],
        flags: u32,
        _after_flags: [u8; 0x54],
        invalidate_suppressed: u8,
    }

    impl UiElementFixture {
        fn new(flags: u32) -> Self {
            Self {
                _before_flags: [0xa5; FLAGS_OFFSET],
                flags,
                _after_flags: [0xa5; 0x54],
                invalidate_suppressed: 1,
            }
        }
    }

    #[test]
    fn boolean_modes_update_only_bit_3_and_return_element() {
        for &(initial_flags, mode, expected_flags) in &[
            (0xa5a5_0000, 0, 0xa5a5_0000),
            (0xa5a5_0000, 1, 0xa5a5_0008),
            (0xa5a5_0008, 0, 0xa5a5_0000),
            (0xa5a5_0008, 1, 0xa5a5_0008),
            (0xffff_fff7, 0, 0xffff_fff7),
            (0xffff_fff7, 1, 0xffff_ffff),
        ] {
            let mut element = UiElementFixture::new(initial_flags);
            let element_ptr = (&mut element as *mut UiElementFixture).cast::<u8>();

            assert_eq!(
                unsafe { ui_element_set_flag_bit_3(element_ptr, mode) },
                element_ptr,
                "initial flags {initial_flags:#010x}, mode {mode}"
            );
            assert_eq!(element.flags, expected_flags, "initial flags {initial_flags:#010x}, mode {mode}");
        }
    }

    #[test]
    fn non_boolean_modes_set_bit_and_do_not_normalize_comparison() {
        for &(initial_flags, mode) in &[
            (0x0000_0000, 2),
            (0x0000_0008, 2),
            (0xa5a5_a500, u32::MAX),
        ] {
            let mut element = UiElementFixture::new(initial_flags);
            let element_ptr = (&mut element as *mut UiElementFixture).cast::<u8>();

            assert_eq!(unsafe { ui_element_set_flag_bit_3(element_ptr, mode) }, element_ptr);
            assert_eq!(element.flags, initial_flags | FLAG_BIT_3, "initial flags {initial_flags:#010x}, mode {mode:#010x}");
        }
    }

    #[test]
    fn changed_mode_uses_a_live_suppressed_element_for_invalidation() {
        let mut element = UiElementFixture::new(0x800);
        let element_ptr = (&mut element as *mut UiElementFixture).cast::<u8>();

        assert_eq!(unsafe { ui_element_set_flag_bit_3(element_ptr, 1) }, element_ptr);
        assert_eq!(element.flags, 0x808);
    }
}
