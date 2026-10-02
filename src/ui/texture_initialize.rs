//! Texture initialization — retailOS `FUN_08281378` @ `0x08281378`.
//!
//! True extent: 200 bytes, comprising 176 executable bytes ending in the
//! return at 0x08281424 and 24 literal bytes; next function is 0x08281440.
//! Raw aligned A32 decoding verifies two inbound plain BLs (0x082727b4,
//! 0x082727d8), eight outbound plain BLs, and no predicated BLs in either set.
//! Initializes the caller's 12-byte texture descriptor, registers it with
//! the video engine, binds its generated name, sets filtering/wrapping and
//! frame unpack properties, then defines the image and returns the descriptor.
//!
//! Deliberate deviations: reuse existing Rust video-engine wrappers and the
//! Rust image-definition port. Raw 0x08281208 consumes only four arguments.
//! The opaque registration word is a target-width address; host tests use a
//! NULL engine rather than trying to dereference a truncated host pointer.

use super::texture_upload::Texture;
use crate::util::video_engine::{
    video_engine_dispatch_opaque_two_words, video_engine_set_control_value,
    video_engine_set_property, video_engine_set_frame_property,
};

/// Initialize a writable texture descriptor and define its image.
///
/// # Safety
/// `texture` must be writable and aligned; `pixels` must satisfy the resident
/// image helper's format-dependent contract (NULL is allowed by the caller).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn texture_initialize(
    texture: *mut Texture,
    width: u16,
    height: u16,
    pixel_format: u8,
    pixels: *const u8,
) -> *mut Texture {
    (*texture).pixel_format = pixel_format;
    (*texture).reserved_a[0] = 0;
    (*texture).width = width;
    (*texture).height = height;
    (*texture).reserved_a[1] = 0;
    video_engine_dispatch_opaque_two_words(1, texture as usize as u32);
    video_engine_set_control_value(0x0de1, (*texture).gl_name);
    video_engine_set_property(0x0de1, 0x2801, 0x2600);
    video_engine_set_property(0x0de1, 0x2800, 0x2600);
    video_engine_set_property(0x0de1, 0x2802, 0x812f);
    video_engine_set_property(0x0de1, 0x2803, 0x812f);
    video_engine_set_frame_property(0x2300, 0x2200, 0x1e01);
    #[cfg(test)]
    let define_image = core::ptr::addr_of!(super::texture_upload::TEXTURE_DEFINE_IMAGE).read();
    #[cfg(not(test))]
    let define_image = super::texture_define_image::texture_define_image;
    define_image((*texture).width as u32, (*texture).height as u32,
        (*texture).pixel_format as u32, pixels);
    texture
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::video_engine::{LOCK, set_mock_instance};
    use super::super::texture_upload::TEXTURE_UPLOAD_TEST_LOCK;

    #[test]
    fn initializes_boundary_dimensions_preserving_name_padding_and_neighbors() {
        let _engine = LOCK.lock();
        let _texture = TEXTURE_UPLOAD_TEST_LOCK.lock().unwrap();
        unsafe { set_mock_instance(core::ptr::null_mut()); }
        #[repr(C)]
        struct Fixture { before: u32, texture: Texture, after: u32 }
        for (width, height, format) in [(0, 0, 0), (u16::MAX, 1, 5),
            (1, u16::MAX, u8::MAX), (u16::MAX, u16::MAX, 3)] {
            let mut fixture = Fixture {
                before: 0x12345678,
                texture: Texture { gl_name: 0x87654321, pixel_format: 9,
                    reserved_5: 0xa5, width: 12, height: 34, reserved_a: [0xff; 2] },
                after: 0xabcdef01,
            };
            let texture = &mut fixture.texture as *mut Texture;
            assert_eq!(unsafe { texture_initialize(texture, width, height, format,
                core::ptr::null()) }, texture);
            assert_eq!((fixture.texture.width, fixture.texture.height), (width, height));
            assert_eq!(fixture.texture.pixel_format, format);
            assert_eq!(fixture.texture.reserved_a, [0, 0]);
            assert_eq!(fixture.texture.reserved_5, 0xa5);
            assert_eq!(fixture.texture.gl_name, 0x87654321);
            assert_eq!((fixture.before, fixture.after), (0x12345678, 0xabcdef01));
        }
    }
}
