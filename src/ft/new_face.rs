use super::error::FT_ERR_INVALID_ARGUMENT;
use super::stream::{FtLibrary, FtOpenArgs, FT_OPEN_PATHNAME};
use core::ffi::c_void;

/// Verified retailOS FT_Open_Face @ 0x0804d6b8; not yet ported.
pub type OpenFace = unsafe extern "C" fn(*mut FtLibrary, *const FtOpenArgs, i32, *mut u32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_open_face(_: *mut FtLibrary, _: *const FtOpenArgs, _: i32, _: *mut u32) -> i32 {
    panic!("ft_new_face requires retailOS FT_Open_Face at 0x0804d6b8")
}

/// Host dependency seam; callers replacing it must serialize access.
#[cfg(not(target_os = "none"))]
pub static mut NEW_FACE_OPEN_FACE: OpenFace = unavailable_open_face;

/// FT_New_Face — original FUN_0804d348 @ 0x0804d348, 48 bytes,
/// ending at the independently entered FT_New_GlyphSlot @ 0x0804d378.
/// Verified raw A32: two incoming plain BLs, one outgoing plain BL
/// (0x0804d36c -> 0x0804d6b8), zero predicated BLs in either direction.
///
/// Reject a null pathname with Invalid_Argument (6), without touching the
/// library or output. Otherwise construct pathname-only FT_Open_Args and
/// return FT_Open_Face(library, args, face_index, face_out) unchanged.
/// All four register arguments are live, despite Ghidra's two-argument void
/// prototype. Negative face indices and null outputs are passed to the callee.
///
/// Deliberate deviations: initialize inactive argument fields instead of
/// leaving stack garbage; flags ensure the callee ignores those fields.
/// Target calls the verified retail address; host uses a replaceable seam.
/// Pointer-bearing fields use repr(C) FtOpenArgs, not host byte offsets.
///
/// # Safety
/// For a nonnull pathname, arguments must satisfy retail FT_Open_Face's
/// contracts; face_out stores a target-width face address, not a host pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_new_face(
    library: *mut FtLibrary, pathname: *mut c_void, face_index: i32, face_out: *mut u32,
) -> i32 {
    if pathname.is_null() {
        return FT_ERR_INVALID_ARGUMENT;
    }
    let args = FtOpenArgs {
        flags: FT_OPEN_PATHNAME,
        memory_base: core::ptr::null(),
        memory_size: 0,
        pathname,
        stream: core::ptr::null_mut(),
        driver: core::ptr::null_mut(),
        num_params: 0,
        params: core::ptr::null_mut(),
    };
    #[cfg(target_os = "none")]
    let open: OpenFace = core::mem::transmute(0x0804d6b8usize);
    #[cfg(not(target_os = "none"))]
    let open = core::ptr::read_volatile(core::ptr::addr_of!(NEW_FACE_OPEN_FACE));
    open(library, &args, face_index, face_out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_path_rejects_without_accessing_other_arguments() {
        let mut output = 0xdeadbeef;
        unsafe {
            assert_eq!(ft_new_face(core::ptr::null_mut(), core::ptr::null_mut(), i32::MIN, &mut output), 6);
            assert_eq!(ft_new_face(core::ptr::null_mut(), core::ptr::null_mut(), i32::MAX, core::ptr::null_mut()), 6);
        }
        assert_eq!(output, 0xdeadbeef);
    }
}
