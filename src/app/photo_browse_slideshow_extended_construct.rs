//! Extended slideshow constructor — retailOS `FUN_0822053c` @ `0x0822053c`.
//! True extent: **36 bytes**, `0x0822053c..0x08220560`; the next entry starts
//! with a separate push prologue at `0x08220560`. Raw ARM decoding finds two
//! incoming plain BL calls (`0x08142e38`, `0x0817da28`), zero predicated BL,
//! and one outgoing plain BL to `0x0822ba68` (zero predicated).
//!
//! Constructs the existing slideshow base, sets trailing words +0x89c and
//! +0x8a0 to all ones, clears byte +0x8a4 and word +0x8a8, and returns the
//! base constructor's pointer unchanged. Both Coverflow and TPodMediaPlayer
//! constructors embed this extended base. Field meanings remain unverified.
//! Deliberate deviations: none in behavior; LLVM may reorder independent
//! stores. Reuses the ported base constructor rather than a fixed-address seam.

use super::photo_browse_slideshow_construct::photo_browse_slideshow_construct;

#[inline(always)]
unsafe fn initialize_extension(object: *mut u8) -> *mut u8 {
    object.add(0x89c).cast::<u32>().write(u32::MAX);
    object.add(0x8a0).cast::<u32>().write(u32::MAX);
    object.add(0x8a4).write(0);
    object.add(0x8a8).cast::<u32>().write(0);
    object
}

/// Constructs the extended slideshow base in the supplied constructor context.
///
/// # Safety
/// The base constructor's preconditions apply. Its returned pointer must be
/// word-aligned and writable through +0x8ab. Retail does not check for NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn photo_browse_slideshow_extended_construct(
    context: *mut u8,
    descriptor: *const u8,
) -> *mut u8 {
    initialize_extension(photo_browse_slideshow_construct(context, descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_exact_fields_preserving_padding_and_neighboring_state() {
        for fill in [0u8, 0xa5, 0xff] {
            let mut words = [u32::from_ne_bytes([fill; 4]); 0x8b0 / 4];
            let object = words.as_mut_ptr().cast::<u8>();
            unsafe {
                assert_eq!(initialize_extension(object), object);
                let bytes = core::slice::from_raw_parts(object, 0x8b0);
                for (offset, &value) in bytes.iter().enumerate() {
                    let expected = match offset {
                        0x89c..=0x8a3 => 0xff,
                        0x8a4 | 0x8a8..=0x8ab => 0,
                        _ => fill,
                    };
                    assert_eq!(value, expected, "offset {offset:#x}, fill {fill:#x}");
                }
                initialize_extension(object);
                assert_eq!(words[0x89c / 4], u32::MAX);
                assert_eq!(words[0x8a0 / 4], u32::MAX);
                assert_eq!(words[0x8a8 / 4], 0);
            }
        }
    }
}
