//! View RGB565 upload — `FUN_0828da34` @ 0x0828da34, **220 bytes**.
//!
//! Raw ARM words establish the extent [0x0828da34, 0x0828db10): the next
//! instruction is a distinct push. Two outgoing plain BLs call rect_width
//! (0x082a2320) and texture_upload_pixels (0x08281194); no predicated BLs.
//! Incoming calls are BLNE at 0x081584e0 and 0x0826ea90 (zero plain BLs).
//! Unless upload is disabled or either backing pointer is NULL, swap the
//! bytes of each pair of 16-bit pixels across the backing rectangle, then
//! upload using the view rectangle's width and height. The signed inner
//! count truncates width / 2 toward zero; the row adjustment is arithmetic
//! (stride - width) >> 1. Here stride and width come from the same rectangle,
//! so that adjustment is zero, including odd widths.
//!
//! Deliberate deviations: expose a void interface; the retail push/pop
//! restores r0/r1 (or the backing rectangle's top/left on the active path),
//! which both callers discard. Native pointer fields widen on the host;
//! repr(C) preserves the exact device offsets without truncated host pointers.

use super::rect::{rect_width, Rect};
use super::texture_upload::{texture_upload_pixels, Texture};

/// Backing image fields used by this operation (device offsets in comments).
#[repr(C)]
pub struct ViewPixelBacking {
    pub reserved_0: u32,
    pub pixels: *mut u32, // +0x04
    pub reserved_8: [u8; 0x90],
    pub bounds: Rect, // +0x98
}

/// View prefix through its texture pointer, with target-width layout.
#[repr(C)]
pub struct PixelUploadView {
    pub reserved_0: [u8; 0x20],
    pub bounds: Rect, // +0x20
    pub reserved_30: [u8; 0x0c],
    pub reserved_3c: u8,
    pub upload_disabled: u8, // +0x3d
    pub reserved_3e: [u8; 0x16],
    pub backing: *mut ViewPixelBacking, // +0x54
    pub reserved_58: [u8; 0x14],
    pub texture: *mut Texture, // +0x6c
}

/// Swap packed RGB565 bytes and upload the view's backing image.
///
/// # Safety
/// `view` must be a readable initialized prefix. On the active path its
/// backing and texture must be valid, and pixels must be aligned, writable
/// for max(height, 0) * max(width / 2, 0) words and valid for the GL upload.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_upload_pixels(view: *const PixelUploadView) {
    let view = &*view;
    if view.upload_disabled != 0 || view.texture.is_null() || view.backing.is_null() {
        return;
    }
    let backing = &*view.backing;
    let bounds = backing.bounds;
    let stride = rect_width(core::ptr::addr_of!(backing.bounds));
    let width = bounds.right.wrapping_sub(bounds.left);
    let height = bounds.bottom.wrapping_sub(bounds.top);
    let row_adjustment = stride.wrapping_sub(width) >> 1;
    let mut pixels = backing.pixels;
    for _ in 0..height {
        for _ in 0..width / 2 {
            let word = pixels.read();
            pixels.write(((word >> 8) & 0xffff00ff) | ((word << 8) & 0xff00ffff));
            pixels = pixels.wrapping_add(1);
        }
        pixels = pixels.wrapping_offset(row_adjustment as isize);
    }
    texture_upload_pixels(
        view.texture,
        (*view.backing).pixels.cast(),
        view.bounds.right.wrapping_sub(view.bounds.left) as u32,
        view.bounds.bottom.wrapping_sub(view.bounds.top) as u32,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(width: i32, height: i32) -> Rect {
        Rect { top: 7, left: 11, bottom: 7i32.wrapping_add(height), right: 11i32.wrapping_add(width) }
    }

    #[test]
    fn swaps_pairs_not_individual_rows_and_uploads_view_dimensions() {
        for (width, height, changed) in [(4, 2, 4), (3, 2, 2), (1, 3, 0), (0, 2, 0), (-4, 2, 0), (4, -2, 0)] {
            let original = [0x1234abcd, 0x00ff807f, 0xdeadbeef, 0x01020304, 0x99887766];
            let mut pixels = original;
            let mut backing = ViewPixelBacking { reserved_0: 0, pixels: pixels.as_mut_ptr(), reserved_8: [0; 0x90], bounds: rect(width, height) };
            let mut texture = Texture { gl_name: 0, pixel_format: 0, reserved_5: 0, width: 0, height: 0, reserved_a: [0; 2] };
            let _upload_lock = match super::super::texture_upload::TEXTURE_UPLOAD_TEST_LOCK.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let view = PixelUploadView { reserved_0: [0; 0x20], bounds: rect(9, 6), reserved_30: [0; 0x0c], reserved_3c: 0, upload_disabled: 0, reserved_3e: [0; 0x16], backing: &mut backing, reserved_58: [0; 0x14], texture: &mut texture };
            unsafe { view_upload_pixels(&view) };
            for i in 0..pixels.len() {
                let bytes = original[i].to_le_bytes();
                let expected = if i < changed { u32::from_le_bytes([bytes[1], bytes[0], bytes[3], bytes[2]]) } else { original[i] };
                assert_eq!(pixels[i], expected, "width={width} height={height} word={i}");
            }
            assert_eq!((texture.width, texture.height), (9, 6));
        }
    }

    #[test]
    fn disabled_and_missing_backing_do_not_dereference_or_upload() {
        let mut texture = Texture { gl_name: 0, pixel_format: 0, reserved_5: 0, width: 17, height: 23, reserved_a: [0; 2] };
        let mut view = PixelUploadView { reserved_0: [0; 0x20], bounds: rect(9, 6), reserved_30: [0; 0x0c], reserved_3c: 0, upload_disabled: 1, reserved_3e: [0; 0x16], backing: core::ptr::null_mut(), reserved_58: [0; 0x14], texture: &mut texture };
        unsafe { view_upload_pixels(&view) };
        view.upload_disabled = 0;
        unsafe { view_upload_pixels(&view) };
        view.backing = core::ptr::NonNull::<ViewPixelBacking>::dangling().as_ptr();
        view.texture = core::ptr::null_mut();
        unsafe { view_upload_pixels(&view) };
        assert_eq!((texture.width, texture.height), (17, 23));
    }
}
