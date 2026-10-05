//! Image descriptor construction, retailOS `FUN_08197670` @ 0x08197670.
//! True extent: 108 bytes, through `bx lr` at 0x081976d8; the next real
//! function starts at 0x081976dc. Raw firmware scan: two inbound plain BLs
//! (0x080fe458, 0x0813e9d0), zero predicated BLs. Body has one `blne`
//! to the existing non-returning `heap_panic` @ 0x08030f44.
//!
//! Stores geometry, auxiliary values and bit depth, then maps pixel-format
//! tag 0x0565 to flag 0 and 0x2565 to flag 1. Other tags are fatal after
//! the preceding stores. Padding at +0x0e..0x0f and +0x1d..0x1f is untouched.
//! No deliberate behavioral deviations; Rust omits the argument-register
//! stack spill used by the original ARM ABI implementation.

#[repr(C)]
pub struct ImageDescriptor {
    pub width: u32,
    pub height: u32,
    pub height_bytes: u32,
    pub auxiliary_tag: u16,
    pub padding_0e: [u8; 2],
    pub auxiliary_10: u32,
    pub auxiliary_14: u32,
    pub bit_depth: u32,
    pub format_2565: u8,
    pub padding_1d: [u8; 3],
}

/// Initializes a writable, four-byte-aligned 32-byte descriptor.
///
/// # Safety
/// `dst` must point to valid writable storage for an `ImageDescriptor`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn image_descriptor_construct(
    dst: *mut ImageDescriptor,
    width: u32,
    height: u32,
    height_bytes: u32,
    // Retail callers pass stack words with potentially uninitialized high halves.
    auxiliary_tag: u32,
    auxiliary_10: u32,
    auxiliary_14: u32,
    bit_depth: u32,
    pixel_format_tag: u32,
) {
    (*dst).width = width;
    (*dst).height = height;
    (*dst).height_bytes = height_bytes;
    (*dst).auxiliary_tag = auxiliary_tag as u16;
    (*dst).auxiliary_10 = auxiliary_10;
    (*dst).auxiliary_14 = auxiliary_14;
    (*dst).bit_depth = bit_depth;
    (*dst).format_2565 = match pixel_format_tag as u16 {
        0x0565 => 0,
        0x2565 => 1,
        _ => crate::heap::veneers::heap_panic(),
    };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::string::ToString;
    use super::*;

    #[test]
    fn both_formats_preserve_padding_and_full_width_values() {
        for (tag, flag) in [(0x0565, 0), (0x2565, 1), (0xffff_0565, 0), (0x8000_2565, 1)] {
            let mut storage = [0xa5a5_a5a5u32; 10];
            unsafe {
                image_descriptor_construct(storage.as_mut_ptr().add(1).cast(),
                    0, u32::MAX, 0x8000_0000, u32::MAX,
                    0x1234_5678, 0xfedc_ba98, 32, tag);
            }
            assert_eq!(storage, [0xa5a5_a5a5, 0, u32::MAX, 0x8000_0000,
                0xa5a5_ffff, 0x1234_5678, 0xfedc_ba98, 32,
                0xa5a5_a500 | flag, 0xa5a5_a5a5]);
        }
    }

    unsafe extern "C" fn invalid_tag() -> ! {
        let mut storage = [0u32; 8];
        let tag = std::env::var("RUSTYPOD_IMAGE_INVALID_TAG").unwrap()
            .parse::<u16>().unwrap();
        image_descriptor_construct(storage.as_mut_ptr().cast(), 1, 2, 3, 4, 5, 6, 16, tag as u32);
        std::process::exit(5);
    }

    #[test]
    fn unsupported_formats_take_fatal_path() {
        for tag in [0u16, 0x0564, 0x0566, 0x2564, 0x2566, 0x1888, 0xffff] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "app::image_descriptor_construct::tests::fatal_child"])
                .env("RUSTYPOD_IMAGE_INVALID_TAG", tag.to_string())
                .status().unwrap();
            assert!(status.success(), "tag {tag:#x}: {status}");
        }
    }

    #[test]
    fn fatal_child() {
        if std::env::var_os("RUSTYPOD_IMAGE_INVALID_TAG").is_none() {
            return;
        }
        crate::heap::veneers::tests::assert_heap_panic_entry_fatal_path(
            "RUSTYPOD_IMAGE_INVALID_TAG",
            "app::image_descriptor_construct::tests::fatal_child",
            invalid_tag,
        );
    }
}
