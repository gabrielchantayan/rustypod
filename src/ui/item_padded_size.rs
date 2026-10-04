//! Item measurement with vertical padding: FUN_0820d6ac @ 0x0820d6ac.
//! True size: 68 bytes, ending at the next push at 0x0820d6f0.
//! Raw A32 decoding: one outgoing plain BL, zero predicated BLs; two
//! incoming plain BLs at 0x0820dea4 and 0x0820df88, zero predicated BLs.
//!
//! Seed a four-word rectangle from the incoming argument registers and let
//! 0x0820d6f0 compute its bottom/right coordinates for the selected item.
//! Write bottom-minus-left plus twice the view's +0xb8 padding as height,
//! then right-minus-top as width. All arithmetic wraps at 32 bits.
//!
//! Deviations: none in memory effects. The original restores r0/r1 from the
//! rectangle; the C ABI return preserves r0 (view), while r1 is not modeled
//! as a second return value. The helper only writes rectangle words 2/3.
//! The unported helper remains an exact-address firmware call, not a guessed
//! implementation. Host execution injects that dependency for arithmetic tests.

use core::ptr;

type MeasureItemBounds = unsafe extern "C" fn(*mut u32, u32, u32, *mut u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn measure_item_bounds(view: *mut u32, context: u32, item: u32, bounds: *mut u32) {
    core::mem::transmute::<usize, MeasureItemBounds>(0x0820_d6f0usize)(view, context, item, bounds);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn measure_item_bounds(_: *mut u32, _: u32, _: u32, _: *mut u32) {
    panic!("item_padded_size requires retailOS bounds helper 0x0820d6f0")
}

/// Measure an item's padded height and unpadded width.
///
/// # Safety
/// `view` must be word-aligned, readable through +0xbb and valid for the
/// retailOS helper (including its provider at +0xc0). `context` and `item`
/// must be valid helper inputs. Outputs must be writable aligned words;
/// they may alias one another or the view, as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_item_padded_size(
    view: *mut u32, context: u32, item: u32, height: *mut u32, width: *mut u32,
) -> *mut u32 {
    item_padded_size_with(view, context, item, height, width, measure_item_bounds)
}

unsafe fn item_padded_size_with(
    view: *mut u32, context: u32, item: u32, height: *mut u32, width: *mut u32,
    measure: MeasureItemBounds,
) -> *mut u32 {
    let mut bounds = [view as usize as u32, context, item, height as usize as u32];
    measure(view, context, item, bounds.as_mut_ptr());
    let padding = view.add(0xb8 / 4).read();
    ptr::write(height, bounds[3].wrapping_sub(bounds[1]).wrapping_add(padding.wrapping_mul(2)));
    ptr::write(width, bounds[2].wrapping_sub(bounds[0]));
    view
}

#[cfg(test)]
mod tests {
    use super::*;

    // Model the helper's recovered coordinate construction with independent
    // widened arithmetic. Context supplies height; item supplies width.
    unsafe extern "C" fn measured_bounds(_: *mut u32, context: u32, item: u32, bounds: *mut u32) {
        bounds.add(3).write((bounds.add(1).read() as u64 + context as u64) as u32);
        bounds.add(2).write((bounds.read() as u64 + item as u64) as u32);
    }

    #[test]
    fn zero_negative_and_overflowing_dimensions() {
        let mut view = [0u32; 0xc4 / 4];
        for (padding, height_value, width_value) in [
            (0, 0, 0), (3, 20, 40), (u32::MAX, 1, u32::MAX),
            (0x80000000, u32::MAX, 0x80000000), (u32::MAX, u32::MAX, 7),
        ] {
            view[0xb8 / 4] = padding;
            let mut height = 0;
            let mut width = 0;
            unsafe {
                let result = item_padded_size_with(view.as_mut_ptr(), height_value, width_value,
                    &mut height, &mut width, measured_bounds);
                assert_eq!(result, view.as_mut_ptr());
            }
            assert_eq!(height, (height_value as u64 + 2 * padding as u64) as u32);
            assert_eq!(width, width_value);
        }
    }

    #[test]
    fn aliased_outputs_keep_width_and_padding_is_read_before_height_write() {
        let mut view = [0u32; 0xc4 / 4];
        view[0xb8 / 4] = 9;
        unsafe {
            let padding = view.as_mut_ptr().add(0xb8 / 4);
            let mut width = 0;
            item_padded_size_with(view.as_mut_ptr(), 11, 17, padding, &mut width, measured_bounds);
            assert_eq!(padding.read(), 29);
            assert_eq!(width, 17);
            item_padded_size_with(view.as_mut_ptr(), 11, 17, padding, padding, measured_bounds);
            assert_eq!(padding.read(), 17);
        }
    }
}
