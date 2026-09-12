//! FreeType size activation.
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{ft_activate_size, FtSize};
    use crate::ft::glyph_slot::FtFace;
    use core::ffi::c_void;

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
