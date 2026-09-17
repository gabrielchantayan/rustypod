//! Whether an element can accept a horizontal adjustment.
//!
//! `ui_element_horizontal_adjustment_available` — original:
//! `FUN_082a255c` @ **0x082a255c**, 64 bytes
//! (`0x082a255c..0x082a259c`; the next distinct function starts at
//! `0x082a259c`). Raw decoding finds four direct, unconditional `bl` call
//! sites and no predicated `bl` call sites.
//!
//! # Algorithm
//!
//! The element has a horizontal adjustment available when either its leading
//! or trailing target word is zero and that target's flag word has bit 0x20
//! set. The retail code reads the trailing pair first and only reads the
//! leading pair when the trailing pair does not qualify.
//!
//! # Deliberate deviations
//!
//! None.

use core::ptr;

const ADJUSTMENT_AVAILABLE: u32 = 0x20;
const LEADING_TARGET_OFFSET: usize = 0x50;
const LEADING_FLAGS_OFFSET: usize = 0x54;
const TRAILING_TARGET_OFFSET: usize = 0x68;
const TRAILING_FLAGS_OFFSET: usize = 0x6c;

/// Returns whether either horizontal adjustment target is absent and enabled.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_horizontal_adjustment_available(element: *const u8) -> i32 {
    let trailing_target = ptr::read(element.add(TRAILING_TARGET_OFFSET).cast::<u32>());
    if trailing_target == 0
        && (ptr::read(element.add(TRAILING_FLAGS_OFFSET).cast::<u32>()) & ADJUSTMENT_AVAILABLE) != 0
    {
        return 1;
    }

    let leading_target = ptr::read(element.add(LEADING_TARGET_OFFSET).cast::<u32>());
    if leading_target == 0
        && (ptr::read(element.add(LEADING_FLAGS_OFFSET).cast::<u32>()) & ADJUSTMENT_AVAILABLE) != 0
    {
        return 1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct ElementFixture {
        _before_leading_target: [u8; LEADING_TARGET_OFFSET],
        leading_target: u32,
        leading_flags: u32,
        _before_trailing_target: [u8; TRAILING_TARGET_OFFSET - LEADING_FLAGS_OFFSET - size_of::<u32>()],
        trailing_target: u32,
        trailing_flags: u32,
    }

    use core::mem::{offset_of, size_of};

    const _: [u8; TRAILING_FLAGS_OFFSET + size_of::<u32>()] = [0; size_of::<ElementFixture>()];
    const _: [u8; LEADING_TARGET_OFFSET] = [0; offset_of!(ElementFixture, leading_target)];
    const _: [u8; LEADING_FLAGS_OFFSET] = [0; offset_of!(ElementFixture, leading_flags)];
    const _: [u8; TRAILING_TARGET_OFFSET] = [0; offset_of!(ElementFixture, trailing_target)];
    const _: [u8; TRAILING_FLAGS_OFFSET] = [0; offset_of!(ElementFixture, trailing_flags)];

    fn fixture(leading_target: u32, leading_flags: u32, trailing_target: u32, trailing_flags: u32) -> ElementFixture {
        ElementFixture {
            _before_leading_target: [0xa5; LEADING_TARGET_OFFSET],
            leading_target,
            leading_flags,
            _before_trailing_target: [0xa5; TRAILING_TARGET_OFFSET - LEADING_FLAGS_OFFSET - size_of::<u32>()],
            trailing_target,
            trailing_flags,
        }
    }

    #[test]
    fn requires_an_absent_target_with_the_available_flag() {
        for (leading_target, leading_flags, trailing_target, trailing_flags, expected) in [
            (1, ADJUSTMENT_AVAILABLE, 1, ADJUSTMENT_AVAILABLE, 0),
            (0, 0, 1, ADJUSTMENT_AVAILABLE, 0),
            (1, ADJUSTMENT_AVAILABLE, 0, 0, 0),
            (0, ADJUSTMENT_AVAILABLE, 1, 0, 1),
            (1, 0, 0, ADJUSTMENT_AVAILABLE, 1),
            (0, ADJUSTMENT_AVAILABLE | 1, 0, ADJUSTMENT_AVAILABLE | 2, 1),
        ] {
            let mut element = fixture(leading_target, leading_flags, trailing_target, trailing_flags);
            assert_eq!(unsafe { ui_element_horizontal_adjustment_available((&mut element as *mut ElementFixture).cast()) }, expected);
        }
    }
}
