//! FreeType size activation and character-size requests.
//!
//! This module covers the small state transition between `FT_New_Size` and
//! glyph loading: a successfully activated size becomes its face's current
//! size.

use core::ffi::c_void;

use crate::ft::glyph_slot::FtFace;

/// `FT_SizeRec` prefix. The owning face is the first word on the retail ARM
/// ABI and is the only member `FT_Activate_Size` reads.
#[repr(C)]
pub struct FtSize {
    pub face: *mut FtFace,
}

/// FreeType 2.3 `FT_Activate_Size` (`src/base/ftobjs.c`) — original:
/// `FUN_0804be6c` at load address 0x0804be6c, 36 bytes.
///
/// Checks `size`, `size->face`, and `size->face->driver`; if all are non-null,
/// stores `size` in `face->size` and returns zero. Otherwise it returns the
/// retail body's raw error value `0x84` without modifying the face. Raw
/// osos.dec disassembly confirms the next function starts at 0x0804be90, and
/// a complete ARM B/BL scan finds eight direct callers, all unconditional
/// `bl` at 0x08080f0c, 0x0808f35c, 0x08097a68, 0x0812e304, 0x0812e5c0,
/// 0x0829a7b8, 0x0829a9f0, and 0x0829ab40; there are no predicated calls or
/// aligned raw-pointer dispatch references. No deliberate deviations.
///
/// # Safety
/// A non-null `size` must point to a valid `FT_SizeRec` prefix. Its non-null
/// `face` must point to a writable retail `FT_FaceRec` through `driver`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_activate_size(size: *mut FtSize) -> i32 {
    if size.is_null() {
        return 0x84;
    }

    let face = (*size).face;
    if face.is_null() || (*face).driver.is_null() {
        return 0x84;
    }

    (*face).size = size.cast::<c_void>();
    0
}

/// Retail size-request layout; signed dimensions are 26.6 point values.
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct FtSizeRequest {
    pub kind: u8,
    pub width: i32,
    pub height: i32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
}

fn character_size_request(
    mut width: i32, mut height: i32, horizontal_resolution: u32, vertical_resolution: u32,
) -> FtSizeRequest {
    if width == 0 { width = height; }
    else if height == 0 { height = width; }
    FtSizeRequest {
        kind: 0,
        width: width.max(64),
        height: height.max(64),
        horizontal_resolution: if horizontal_resolution == 0 { 72 } else { horizontal_resolution },
        vertical_resolution: if vertical_resolution == 0 { 72 } else { vertical_resolution },
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_size_request(_face: *mut FtFace, _request: *const FtSizeRequest) -> i32 {
    panic!("install FT_Request_Size host seam")
}

/// Host replacement for the unported stock FT_Request_Size at 0x0804e980.
#[cfg(not(target_os = "none"))]
pub static mut FT_REQUEST_SIZE: unsafe extern "C" fn(*mut FtFace, *const FtSizeRequest) -> i32 =
    missing_size_request;

/// `FT_Set_Char_Size` — FUN_0804ec00 at 0x0804ec00, 100 bytes.
///
/// Raw extent [0x0804ec00,0x0804ec64): one plain outgoing BL to
/// FT_Request_Size (0x0804e980), no predicated BLs; two plain incoming BLs
/// at 0x0812e31c and 0x0812e5d8, no predicated incoming BLs.
/// Copy a zero dimension from the other, clamp each signed 26.6 dimension
/// to at least 64, default each zero resolution independently to 72 dpi,
/// and submit a nominal (kind zero) request. Return the callee's error.
/// No behavioral deviations. Request padding is unspecified in stock;
/// the u8 kind preserves its byte-only access rather than assuming an enum.
/// Host builds replace only the stock call through FT_REQUEST_SIZE.
///
/// # Safety
/// `face` must meet the stock FT_Request_Size contract (NULL is accepted
/// and returns error 0x23). Host callers must install a valid request seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ft_set_char_size(
    face: *mut FtFace, width: i32, height: i32,
    horizontal_resolution: u32, vertical_resolution: u32,
) -> i32 {
    let request = character_size_request(width, height, horizontal_resolution, vertical_resolution);
    #[cfg(target_os = "none")]
    let request_size: unsafe extern "C" fn(*mut FtFace, *const FtSizeRequest) -> i32 =
        core::mem::transmute(0x0804_e980usize);
    #[cfg(not(target_os = "none"))]
    let request_size = FT_REQUEST_SIZE;
    request_size(face, &request)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{ft_activate_size, FtSize};
    use crate::ft::glyph_slot::FtFace;
    use core::ffi::c_void;

    #[test]
    fn character_request_normalizes_signed_dimensions_and_independent_dpi() {
        let dimensions = [i32::MIN, -65, -1, 0, 1, 63, 64, 65, 128, i32::MAX];
        for width in dimensions {
            for height in dimensions {
                for (horizontal, vertical) in [(0, 0), (0, 96), (96, 0), (1, u32::MAX)] {
                    let request = super::character_size_request(width, height, horizontal, vertical);
                    let copied_width = if width == 0 { height } else { width };
                    let copied_height = if height == 0 { width } else { height };
                    assert_eq!(request, super::FtSizeRequest {
                        kind: 0,
                        width: if copied_width < 64 { 64 } else { copied_width },
                        height: if copied_height < 64 { 64 } else { copied_height },
                        horizontal_resolution: if horizontal == 0 { 72 } else { horizontal },
                        vertical_resolution: if vertical == 0 { 72 } else { vertical },
                    });
                }
            }
        }
    }

    #[test]
    fn request_fields_retain_retail_word_offsets() {
        assert_eq!(core::mem::offset_of!(super::FtSizeRequest, width), 4);
        assert_eq!(core::mem::offset_of!(super::FtSizeRequest, height), 8);
        assert_eq!(core::mem::offset_of!(super::FtSizeRequest, horizontal_resolution), 12);
        assert_eq!(core::mem::offset_of!(super::FtSizeRequest, vertical_resolution), 16);
        assert_eq!(core::mem::size_of::<super::FtSizeRequest>(), 20);
    }

    #[test]
    fn rejects_null_size() {
        assert_eq!(unsafe { ft_activate_size(core::ptr::null_mut()) }, 0x84);
    }

    #[test]
    fn rejects_missing_face() {
        let mut size = FtSize { face: core::ptr::null_mut() };

        assert_eq!(unsafe { ft_activate_size(&mut size) }, 0x84);
    }

    #[test]
    fn rejects_missing_driver_without_replacing_active_size() {
        let mut face: FtFace = unsafe { core::mem::zeroed() };
        let previous = core::ptr::NonNull::<u8>::dangling().as_ptr().cast::<c_void>();
        face.size = previous;
        let mut size = FtSize { face: &mut face };

        assert_eq!(unsafe { ft_activate_size(&mut size) }, 0x84);
        assert_eq!(face.size, previous);
    }

    #[test]
    fn installs_size_when_face_has_driver() {
        let mut face: FtFace = unsafe { core::mem::zeroed() };
        face.driver = core::ptr::NonNull::<u8>::dangling().as_ptr().cast::<c_void>();
        let mut size = FtSize { face: &mut face };

        assert_eq!(unsafe { ft_activate_size(&mut size) }, 0);
        assert_eq!(face.size, (&mut size as *mut FtSize).cast::<c_void>());
    }
}
