//! Validation of a resource-range cursor against its requested bounds.
//!
//! The cursor's concrete class and virtual slot +0x28 target remain retailOS.
//! The slot is named only for its observed result: the ARM caller increments
//! its `u32` answer before comparing it with the requested range.

use crate::app::parse_result::parse_result_init;

/// Vtable slot +0x28 observed by [`resource_range_validate_position`].
pub type ResourceRangePositionFn = unsafe extern "C" fn(*mut ResourceRangeCursor) -> u32;

/// The portion of the cursor's vtable decoded by this function.
#[repr(C)]
pub struct ResourceRangeCursorVTable {
    /// Slots +0x00 through +0x24 are not decoded here.
    pub slots_before_position: [Option<unsafe extern "C" fn()>; 10],
    /// +0x28: returns the cursor position before the caller's `+1`.
    pub position: ResourceRangePositionFn,
}

/// The cursor object as seen through its vtable pointer.
#[repr(C)]
pub struct ResourceRangeCursor {
    /// +0x00 on the 32-bit target.
    pub vtable: *const ResourceRangeCursorVTable,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(ResourceRangeCursorVTable, position)];

/// resource_range_validate_position — original: `FUN_080f9de0` @
/// 0x080f9de0 (104 bytes; 5 inbound `bl` call sites, no predicated inbound
/// `bl` forms).
///
/// Initializes `out` as a cleared parser result, obtains the cursor position
/// through vtable slot +0x28, then validates `position + 1` within the
/// half-open requested range `[start, start + count)`. An out-of-range
/// position or wrapping range end replaces the result with `{2, 5, 0x2100}`.
/// The true extent is 0x080f9de0..0x080f9e48: 26 ARM instructions, no literal
/// pool; the `push` at 0x080f9e48 begins the next real function.
///
/// Verified call count: the body has one plain unconditional `bl` to
/// `parse_result_init`, no predicated `bl`, one `blx` virtual dispatch, and a
/// tail `b` to the byte-identical parser-result initializer at 0x08283134.
/// Deliberate deviations: Rust calls the canonical initializer for both
/// result writes because its 0x08283134 twin is behaviorally identical; the
/// virtual callee has no established identity, so this port preserves direct
/// slot dispatch rather than inventing a seam.
///
/// # Safety
/// `out` must cover four writable bytes. `cursor` and its vtable must be live,
/// and vtable slot +0x28 must use [`ResourceRangePositionFn`]'s ABI.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn resource_range_validate_position(
    out: *mut u8,
    cursor: *mut ResourceRangeCursor,
    start: u32,
    count: u32,
) {
    parse_result_init(out, 0, 0, 0);

    let position_after_current = ((*(*cursor).vtable).position)(cursor).wrapping_add(1);
    let range_end = start.wrapping_add(count);
    if position_after_current <= start || position_after_current > range_end || range_end < start {
        parse_result_init(out, 2, 5, 0x2100);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn position_zero(_: *mut ResourceRangeCursor) -> u32 { 0 }
    unsafe extern "C" fn position_three(_: *mut ResourceRangeCursor) -> u32 { 3 }
    unsafe extern "C" fn position_max(_: *mut ResourceRangeCursor) -> u32 { u32::MAX }

    const ZERO_VTABLE: ResourceRangeCursorVTable = ResourceRangeCursorVTable {
        slots_before_position: [None; 10], position: position_zero,
    };
    const THREE_VTABLE: ResourceRangeCursorVTable = ResourceRangeCursorVTable {
        slots_before_position: [None; 10], position: position_three,
    };
    const MAX_VTABLE: ResourceRangeCursorVTable = ResourceRangeCursorVTable {
        slots_before_position: [None; 10], position: position_max,
    };

    unsafe fn validate(vtable: *const ResourceRangeCursorVTable, start: u32, count: u32) -> [u8; 4] {
        let mut cursor = ResourceRangeCursor { vtable };
        let mut result = [0xff; 4];
        resource_range_validate_position(result.as_mut_ptr(), &mut cursor, start, count);
        result
    }

    #[test]
    fn accepts_position_strictly_inside_range() {
        unsafe { assert_eq!(validate(&THREE_VTABLE, 2, 2), [0, 0, 0, 0]); }
    }

    #[test]
    fn rejects_both_range_boundaries_and_empty_range() {
        unsafe {
            assert_eq!(validate(&ZERO_VTABLE, 1, 4), [2, 5, 0, 0x21]);
            assert_eq!(validate(&THREE_VTABLE, 0, 3), [2, 5, 0, 0x21]);
            assert_eq!(validate(&ZERO_VTABLE, 0, 0), [2, 5, 0, 0x21]);
        }
    }

    #[test]
    fn rejects_wrapping_range_or_position() {
        unsafe {
            assert_eq!(validate(&MAX_VTABLE, u32::MAX - 1, 2), [2, 5, 0, 0x21]);
            assert_eq!(validate(&ZERO_VTABLE, u32::MAX, 1), [2, 5, 0, 0x21]);
        }
    }
}
