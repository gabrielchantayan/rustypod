//! Named FreeType face owner teardown.

use crate::cxx::string_object::{string_object_destroy, StringObject};
use crate::ft::face::ft_done_face;
use crate::ft::glyph_slot::FtFace;

/// The 16-byte retailOS cache entry: a name, face, and reference count.
/// Native host pointers widen; repr(C) preserves the embedded string layout.
#[repr(C)]
pub struct FontFaceOwner {
    pub name: StringObject,
    pub face: *mut FtFace,
    pub references: u32,
}

/// `font_face_owner_destroy` — FUN_0819d9b8 @ 0x0819d9b8, 28 bytes
/// (0x0819d9b8..0x0819d9d4). Raw ARM words verify two incoming plain BL
/// calls (0x0819d840, 0x0819d910), no predicated incoming BL; the body
/// contains one plain BL to ft_done_face @ 0x0804c360, no predicated BL,
/// and a tail B to string_object_destroy @ 0x08277484. The next function
/// begins with `sub ip,r1,#0x8000` at 0x0819d9d4.
///
/// Release the face at target offset +8, discard its error, then destroy
/// the embedded name and return this. Neither the face word nor reference
/// count is cleared; callers separately delete the owner. Deliberate
/// deviations: reuse both Rust ports and widen pointer fields on hosts.
/// Ghidra's apparent direct vtable store/payload release belongs to the
/// tail-called string destructor, not this function.
///
/// # Safety
/// `this` must be a writable owner with a valid name payload and a null
/// or valid FreeType face satisfying ft_done_face's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn font_face_owner_destroy(this: *mut FontFaceOwner) -> *mut FontFaceOwner {
    let _ = ft_done_face((*this).face);
    string_object_destroy(core::ptr::addr_of_mut!((*this).name));
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;
    use core::ptr;

    #[test]
    fn absent_face_and_empty_name_preserve_owner_storage() {
        unsafe {
            let mut owner = FontFaceOwner {
                name: StringObject { vtable: ptr::null(), payload: ptr::null_mut() },
                face: ptr::null_mut(),
                references: u32::MAX,
            };
            let address = &mut owner as *mut FontFaceOwner;
            assert_eq!(font_face_owner_destroy(address), address);
            assert_eq!(owner.name.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert!(owner.name.payload.is_null());
            assert!(owner.face.is_null());
            assert_eq!(owner.references, u32::MAX);
        }
    }

    #[test]
    fn invalid_face_error_does_not_skip_name_destruction() {
        unsafe {
            let mut face: FtFace = core::mem::zeroed();
            let face_address = &mut face as *mut FtFace;
            let mut owner = FontFaceOwner {
                name: StringObject { vtable: ptr::null(), payload: ptr::null_mut() },
                face: face_address,
                references: 0,
            };
            let address = &mut owner as *mut FontFaceOwner;
            assert_eq!(font_face_owner_destroy(address), address);
            assert_eq!(owner.name.vtable, &STRING_OBJECT_VTABLE as *const _);
            assert!(owner.name.payload.is_null());
            assert_eq!(owner.face, face_address);
            assert_eq!(owner.references, 0);
            assert!(face.driver.is_null());
        }
    }
}
