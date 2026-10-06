//! Invalidate a visible indexed rectangle — FUN_0816b2d0 @ 0x0816b2d0.
//!
//! True extent: 72 bytes [0x0816b2d0, 0x0816b318), ending in
//! `pop {r0-r6,pc}` before the next independent function's push.
//! Raw whole-image decoding finds two incoming plain BLs (0x0816b9a0,
//! 0x0816b9ac), zero predicated BLs, tail branches, or address data words.
//! The body has four plain BLs and zero predicated BLs. Test the signed
//! visible index range via 0x0816b1dc, copy the indexed rectangle with its
//! local origin, offset it by the element bounds origin, then invalidate it.
//!
//! Deliberate deviations: the unported range predicate executes at its verified
//! retail address on device; hosts evaluate its exact wrapping MLA and signed
//! comparisons. Existing Rust ports supply the other three callees. The stock
//! epilogue restores the overwritten stack rectangle into r0-r3 on success;
//! expose r0/r1 as a packed u64 (top/left), or element/index when out of range.
//! Host element addresses in this target-width result are truncated to u32.
//! r2/r3 restoration is omitted: both real callers discard all return registers,
//! and those registers are caller-saved under AAPCS.

use super::indexed_rect::indexed_rect_copy_offset;
use super::invalidate::ui_element_invalidate_region;
use super::rect::{rect_offset, Rect};

#[inline(always)]
unsafe fn indexed_rect_is_visible(element: *const u32, index: i32) -> u32 {
    #[cfg(target_os = "none")]
    {
        let predicate: unsafe extern "C" fn(*const u32, i32) -> u32 =
            core::mem::transmute(0x0816_b1dcusize);
        predicate(element, index)
    }
    #[cfg(not(target_os = "none"))]
    {
        let first = element.add(0xe8 / 4).read() as i32;
        if first > index {
            return 0;
        }
        let span = (element.add(0xb8 / 4).read() as i32)
            .wrapping_mul(element.add(0xbc / 4).read() as i32);
        u32::from(first.wrapping_add(span) > index)
    }
}

/// # Safety
/// `element` must be an aligned live UI object through +0xf4, with a valid
/// target-width rectangle table covering every index accepted by its range
/// predicate. Its rendering links must satisfy `ui_element_invalidate_region`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_rect_invalidate(element: *mut u8, index: i32) -> u64 {
    if indexed_rect_is_visible(element.cast(), index) == 0 {
        return (element as usize as u32 as u64) | ((index as u32 as u64) << 32);
    }
    let mut region = Rect::default();
    indexed_rect_copy_offset(element.cast(), index, &mut region);
    rect_offset(
        &mut region,
        element.add(0x84).cast::<i32>().read(),
        element.add(0x80).cast::<i32>().read(),
    );
    ui_element_invalidate_region(element, &region);
    (region.top as u32 as u64) | ((region.left as u32 as u64) << 32)
}
