//! Transforming local rectangles into render-context coordinates.
//!
//! - `render_context_transform_rect` — original: `FUN_0828cb64` @
//!   **0x0828cb64** (52 bytes; 3 direct `bl` call sites).

use core::ptr;

use crate::ui::rect::{rect_offset, Rect};

/// render_context_transform_rect — original: `FUN_0828cb64` @ **0x0828cb64**
/// (52 bytes).
///
/// Raw ARM extends from `mov r2,r0` through `bx lr` at 0x0828cb94; the next
/// function begins at 0x0828cb98. Decoding every branch-with-link word finds
/// three direct unconditional `bl` call sites and no predicated `bl` forms.
///
/// If `render_context + 0x80` is non-zero, leave `rect` unchanged. Otherwise,
/// if its child context pointer at +0x78 is non-NULL, subtract that child's
/// horizontal and vertical origins (+0x80 and +0x84) from the rectangle via
/// the tail branch to [`rect_offset`] at 0x0826c574.
///
/// # Deliberate deviations
///
/// The ARM tail branch is an ordinary Rust call. Host fixtures hold native
/// pointers at +0x78, so their pointer load is unaligned and pointer-sized;
/// target builds use aligned 32-bit words matching retailOS.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn render_context_transform_rect(render_context: *mut u8, rect: *mut Rect) {
    let context_flag = ptr::read((render_context.add(0x80)).cast::<u32>());
    if context_flag != 0 {
        return;
    }
    let child_address = ptr::read((render_context.add(0x78)).cast::<u32>());
    if child_address == 0 {
        return;
    }
    let child = child_address as usize as *const u8;
    let horizontal = ptr::read(child.add(0x80).cast::<i32>());
    let vertical = ptr::read(child.add(0x84).cast::<i32>());
    rect_offset(rect, horizontal.wrapping_neg(), vertical.wrapping_neg());
}

/// Host form of [`render_context_transform_rect`].
#[cfg(not(target_os = "none"))]
#[inline(never)]
pub unsafe extern "C" fn render_context_transform_rect(render_context: *mut u8, rect: *mut Rect) {
    if ptr::read_unaligned((render_context.add(0x80)).cast::<u32>()) != 0 {
        return;
    }
    let child = ptr::read_unaligned((render_context.add(0x78)).cast::<*const u8>());
    if child.is_null() {
        return;
    }
    let horizontal = ptr::read_unaligned(child.add(0x80).cast::<i32>());
    let vertical = ptr::read_unaligned(child.add(0x84).cast::<i32>());
    rect_offset(rect, horizontal.wrapping_neg(), vertical.wrapping_neg());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    unsafe fn write_child(context: &mut [u8], child: *const u8) {
        ptr::write_unaligned(context.as_mut_ptr().add(0x78).cast::<*const u8>(), child);
    }

    #[test]
    fn skips_hidden_context_without_reading_child() {
        unsafe {
            let mut context = [0_u8; 0x84];
            let mut rect = Rect { top: 1, left: 2, bottom: 3, right: 4 };
            ptr::write_unaligned(context.as_mut_ptr().add(0x80).cast::<u32>(), 1);
            render_context_transform_rect(context.as_mut_ptr(), &mut rect);
            assert_eq!(rect, Rect { top: 1, left: 2, bottom: 3, right: 4 });
        }
    }

    #[test]
    fn leaves_rect_when_child_is_absent() {
        unsafe {
            let mut context = [0_u8; 0x84];
            let mut rect = Rect { top: 1, left: 2, bottom: 3, right: 4 };
            write_child(&mut context, ptr::null());
            render_context_transform_rect(context.as_mut_ptr(), &mut rect);
            assert_eq!(rect, Rect { top: 1, left: 2, bottom: 3, right: 4 });
        }
    }

    #[test]
    fn subtracts_child_origin_with_wrapping_coordinates() {
        unsafe {
            let mut context = [0_u8; 0x84];
            let mut child = [0_u8; 0x88];
            let mut rect = Rect { top: i32::MIN, left: i32::MAX, bottom: 4, right: 5 };
            ptr::write_unaligned(child.as_mut_ptr().add(0x80).cast::<i32>(), -1);
            ptr::write_unaligned(child.as_mut_ptr().add(0x84).cast::<i32>(), 2);
            write_child(&mut context, child.as_ptr());
            render_context_transform_rect(context.as_mut_ptr(), &mut rect);
            assert_eq!(rect, Rect { top: i32::MAX - 1, left: i32::MIN, bottom: 2, right: 6 });
        }
    }
}
