//! Texture pixel upload — original: `FUN_08281194` @ 0x08281194.
//!
//! **116 bytes**, binary-verified from `push {r2-r8,lr}` at 0x08281194
//! through `pop {r2-r8,pc}` at 0x08281204; the separate sibling
//! `FUN_08281208` begins at 0x08281208. Decoding every ARM B/BL word in
//! `osos.dec` finds **six `bl` call sites**: five unconditional at
//! 0x0827bae8, 0x0827bb74, 0x0827bbe0, 0x0827bc64, and 0x0828db08, plus
//! the `blne` at 0x082727f4. There are no tail-`b` call sites or data-word
//! references, so this is not virtual dispatch.
//!
//! # Algorithm
//!
//! Bind the texture through `FUN_08281140`, then compare the full-width
//! requested dimensions with the texture's stored u16 dimensions. A change
//! stores the low 16 bits and invokes `FUN_08281208` to define the complete
//! image. Equal dimensions invoke `FUN_082812c4` to update the image at
//! origin (0, 0). The definition helper also receives the original u32
//! dimensions, a stack-argument detail Ghidra omitted from its four-argument
//! prototype.
//!
//! # Deliberate deviations
//!
//! The three GL helpers are still unported. Device builds reach their retail
//! bodies through volatile dispatch seams; host defaults are inert, while
//! tests install recording models. The original leaves an unobservable helper
//! value in r0; every one of the six callers overwrites or discards it, so the
//! port exposes the Ghidra-verified void interface.

#[cfg(test)]
extern crate std;

/// The 12-byte texture descriptor consumed by the retail GL adapter.
///
/// Its fields are fixed-width because the device is 32-bit and the helper
/// accesses format, width, and height at +0x04, +0x06, and +0x08.
#[repr(C)]
pub struct Texture {
    pub gl_name: u32,
    pub pixel_format: u8,
    pub reserved_5: u8,
    pub width: u16,
    pub height: u16,
    pub reserved_a: [u8; 2],
}

/// `FUN_08281208` @ 0x08281208: define a complete texture image.
///
/// `requested_width` and `requested_height` are stack arguments in the
/// retail call, retained before the u16 stores by `FUN_08281194`.
pub type TextureDefineImage = unsafe extern "C" fn(
    width: u16,
    height: u16,
    pixel_format: u8,
    pixels: *const u8,
    requested_width: u32,
    requested_height: u32,
);

/// `FUN_082812c4` @ 0x082812c4: replace a texture image region.
pub type TextureUpdateSubimage = unsafe extern "C" fn(
    x: u32,
    y: u32,
    width: u16,
    height: u16,
    pixel_format: u8,
    pixels: *const u8,
);



#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_texture_define_image(
    width: u16,
    height: u16,
    pixel_format: u8,
    pixels: *const u8,
    requested_width: u32,
    requested_height: u32,
) {
    let define_image: TextureDefineImage = unsafe { core::mem::transmute(0x0828_1208usize) };
    unsafe {
        define_image(
            width,
            height,
            pixel_format,
            pixels,
            requested_width,
            requested_height,
        )
    };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_texture_define_image(
    _width: u16,
    _height: u16,
    _pixel_format: u8,
    _pixels: *const u8,
    _requested_width: u32,
    _requested_height: u32,
) {
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_texture_update_subimage(
    x: u32,
    y: u32,
    width: u16,
    height: u16,
    pixel_format: u8,
    pixels: *const u8,
) {
    let update_subimage: TextureUpdateSubimage = unsafe { core::mem::transmute(0x0828_12c4usize) };
    unsafe { update_subimage(x, y, width, height, pixel_format, pixels) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_texture_update_subimage(
    _x: u32,
    _y: u32,
    _width: u16,
    _height: u16,
    _pixel_format: u8,
    _pixels: *const u8,
) {
}


/// Active `FUN_08281208` dispatch seam for full image definitions.
#[cfg(target_os = "none")]
pub static mut TEXTURE_DEFINE_IMAGE: TextureDefineImage = firmware_texture_define_image;
/// Host's inert full-image seam default.
#[cfg(not(target_os = "none"))]
pub static mut TEXTURE_DEFINE_IMAGE: TextureDefineImage = missing_texture_define_image;

/// Active `FUN_082812c4` dispatch seam for same-size image replacement.
#[cfg(target_os = "none")]
pub static mut TEXTURE_UPDATE_SUBIMAGE: TextureUpdateSubimage = firmware_texture_update_subimage;
/// Host's inert same-size replacement seam default.
#[cfg(not(target_os = "none"))]
pub static mut TEXTURE_UPDATE_SUBIMAGE: TextureUpdateSubimage = missing_texture_update_subimage;

/// texture_upload_pixels — original: `FUN_08281194` @ 0x08281194 (116 bytes).
///
/// Activates `texture`, defining its image when either full-width requested
/// dimension differs from the stored u16 size; otherwise updates the complete
/// existing image from origin. The original has no NULL checks.
///
/// # Safety
///
/// `texture` must point to a writable, 12-byte [`Texture`] and `pixels` must
/// be valid for the activated GL helper's format-dependent read.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn texture_upload_pixels(
    texture: *mut Texture,
    pixels: *const u8,
    width: u32,
    height: u32,
) {
    unsafe { crate::ui::texture_activate::texture_activate(texture) };

    let stored_width = unsafe { (*texture).width };
    let stored_height = unsafe { (*texture).height };
    if stored_width as u32 != width || stored_height as u32 != height {
        unsafe {
            (*texture).width = width as u16;
            (*texture).height = height as u16;
        }
        let define_image = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(TEXTURE_DEFINE_IMAGE))
        };
        unsafe {
            define_image(
                width as u16,
                height as u16,
                (*texture).pixel_format,
                pixels,
                width,
                height,
            )
        };
    } else {
        let update_subimage = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(TEXTURE_UPDATE_SUBIMAGE))
        };
        unsafe {
            update_subimage(
                0,
                0,
                stored_width,
                stored_height,
                (*texture).pixel_format,
                pixels,
            )
        };
    }
}

/// Serializes host tests that replace the process-global texture seams.
#[cfg(test)]
pub static TEXTURE_UPLOAD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::{offset_of, size_of};
    use core::ptr;

    static mut ACTIVATION_CALLS: u32 = 0;
    static mut DEFINE_CALLS: u32 = 0;
    static mut UPDATE_CALLS: u32 = 0;
    static mut DEFINITION: (u16, u16, u8, *const u8, u32, u32) = (0, 0, 0, ptr::null(), 0, 0);
    static mut UPDATE: (u32, u32, u16, u16, u8, *const u8) = (0, 0, 0, 0, 0, ptr::null());
    static mut ORDER: [u8; 4] = [0; 4];
    static mut ORDER_LEN: usize = 0;

    unsafe extern "C" fn record_activate(_flag: u32) {
        unsafe {
            ACTIVATION_CALLS += 1;
            ORDER[ORDER_LEN] = 1;
            ORDER_LEN += 1;
        }
    }

    unsafe extern "C" fn record_definition(
        width: u16,
        height: u16,
        pixel_format: u8,
        pixels: *const u8,
        requested_width: u32,
        requested_height: u32,
    ) {
        unsafe {
            DEFINE_CALLS += 1;
            DEFINITION = (width, height, pixel_format, pixels, requested_width, requested_height);
            ORDER[ORDER_LEN] = 2;
            ORDER_LEN += 1;
        }
    }

    unsafe extern "C" fn record_update(
        x: u32,
        y: u32,
        width: u16,
        height: u16,
        pixel_format: u8,
        pixels: *const u8,
    ) {
        unsafe {
            UPDATE_CALLS += 1;
            UPDATE = (x, y, width, height, pixel_format, pixels);
            ORDER[ORDER_LEN] = 3;
            ORDER_LEN += 1;
        }
    }

    struct SeamGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                crate::ui::texture_activate::reset_mock_texture_binding_cache();
                TEXTURE_DEFINE_IMAGE = missing_texture_define_image;
                TEXTURE_UPDATE_SUBIMAGE = missing_texture_update_subimage;
            }
        }
    }

    fn install_recorders() -> SeamGuard {
        let lock = TEXTURE_UPLOAD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            ACTIVATION_CALLS = 0;
            DEFINE_CALLS = 0;
            UPDATE_CALLS = 0;
            DEFINITION = (0, 0, 0, ptr::null(), 0, 0);
            UPDATE = (0, 0, 0, 0, 0, ptr::null());
            ORDER = [0; 4];
            ORDER_LEN = 0;
            crate::ui::texture_activate::reset_mock_texture_binding_cache();
            crate::ui::texture_activate::set_mock_texture_binding_refresh(record_activate);
            TEXTURE_DEFINE_IMAGE = record_definition;
            TEXTURE_UPDATE_SUBIMAGE = record_update;
        }
        SeamGuard { _lock: lock }
    }

    fn texture(width: u16, height: u16) -> Texture {
        Texture {
            gl_name: 0x1234_5678,
            pixel_format: 4,
            reserved_5: 0xa5,
            width,
            height,
            reserved_a: [0x5a, 0xc3],
        }
    }

    #[test]
    fn texture_layout_matches_the_retail_descriptor() {
        assert_eq!(size_of::<Texture>(), 12);
        assert_eq!(offset_of!(Texture, gl_name), 0);
        assert_eq!(offset_of!(Texture, pixel_format), 4);
        assert_eq!(offset_of!(Texture, width), 6);
        assert_eq!(offset_of!(Texture, height), 8);
    }

    #[test]
    fn changed_size_activates_then_defines_the_complete_image() {
        let _guard = install_recorders();
        let pixels = [0x5au8; 8];
        let mut texture = texture(12, 34);

        unsafe { texture_upload_pixels(&mut texture, pixels.as_ptr(), 640, 480) };

        assert_eq!(texture.width, 640);
        assert_eq!(texture.height, 480);
        unsafe {
            assert_eq!(ACTIVATION_CALLS, 1);
            assert_eq!(DEFINE_CALLS, 1);
            assert_eq!(UPDATE_CALLS, 0);
            assert_eq!(DEFINITION, (640, 480, 4, pixels.as_ptr(), 640, 480));
            assert_eq!(&ORDER[..ORDER_LEN], &[1, 2]);
        }
    }

    #[test]
    fn unchanged_size_activates_then_updates_from_origin() {
        let _guard = install_recorders();
        let pixels = [0x6bu8; 8];
        let mut texture = texture(320, 240);

        unsafe { texture_upload_pixels(&mut texture, pixels.as_ptr(), 320, 240) };

        unsafe {
            assert_eq!(DEFINE_CALLS, 0);
            assert_eq!(UPDATE_CALLS, 1);
            assert_eq!(UPDATE, (0, 0, 320, 240, 4, pixels.as_ptr()));
            assert_eq!(ACTIVATION_CALLS, 1);
            assert_eq!(&ORDER[..ORDER_LEN], &[1, 3]);
        }
    }

    #[test]
    fn wide_dimensions_redefine_on_every_call_after_u16_truncation() {
        let _guard = install_recorders();
        let pixels = [0x91u8; 8];
        let mut texture = texture(1, 2);

        unsafe {
            texture_upload_pixels(&mut texture, pixels.as_ptr(), 0x1_0001, 0x2_0002);
            texture_upload_pixels(&mut texture, pixels.as_ptr(), 0x1_0001, 0x2_0002);
            assert_eq!(DEFINE_CALLS, 2);
            assert_eq!(UPDATE_CALLS, 0);
            assert_eq!(DEFINITION, (1, 2, 4, pixels.as_ptr(), 0x1_0001, 0x2_0002));
            assert_eq!(&ORDER[..ORDER_LEN], &[1, 2, 2]);
        }
        assert_eq!(texture.width, 1);
        assert_eq!(texture.height, 2);
    }
}
