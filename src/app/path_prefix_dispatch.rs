//! Cumulative path-prefix facade dispatch.
//!
//! Original FUN_08149e38 @ 0x08149e38; true extent 216 bytes through
//! 0x08149f10 (212 code bytes and the 0x089a60d8 literal). Whole-image
//! aligned A32 decoding verifies two incoming plain BLs at 0x0809b6c8 and
//! 0x08278444, zero predicated BLs. Body: ten plain BLs, zero predicated
//! BLs, one BLX through facade slot +0x58.
//! Copies the input path, installs the path vtable, normalizes to '/', and
//! consumes components into a cumulative path. Dispatches each prefix until
//! an error other than 0, 13 or 53; exhaustion returns zero. All temporaries
//! are destroyed on both exits. Ghidra's missing r1 argument is corrected.
//! Deliberate deviations: host pointer fields widen; existing allocation and
//! separator-normalization boundaries remain in use. No new callee seam.

use core::mem::MaybeUninit;
use crate::app::path_probe::FacadeObject;
use crate::app::path_object_construct::PATH_OBJECT_VTABLE_ADDRESS;
use crate::app::path_object_join::path_object_join;
use crate::app::path_object_take_component::path_object_take_component;
use crate::cxx::string_object::{StringObject, StringObjectVtable,
    string_object_copy_construct, string_object_destroy_veneer,
    string_object_path_component_count};
use crate::cxx::string_object_normalize_volume_path::STRING_OBJECT_PATH_OPS;

/// # Safety
/// Both objects, their payloads and the facade's slot +0x58 must be valid.
/// The string helpers' allocation, padding and release contracts apply.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_prefix_dispatch(
    facade: *mut FacadeObject, path: *const StringObject,
) -> u32 {
    let mut remaining = MaybeUninit::<StringObject>::uninit();
    let remaining = string_object_copy_construct(remaining.as_mut_ptr(), path);
    (*remaining).vtable = PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable;
    let mut prefix = StringObject {
        vtable: PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable,
        payload: core::ptr::null_mut(),
    };
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(STRING_OBJECT_PATH_OPS));
    (ops.normalize_separators)(remaining, b'/' as u32, 0);
    let status = loop {
        if string_object_path_component_count(remaining, 0) < 1 { break 0; }
        let mut component = MaybeUninit::<StringObject>::uninit();
        path_object_take_component(component.as_mut_ptr(), remaining, 0);
        path_object_join(&mut prefix, component.as_ptr());
        string_object_destroy_veneer(component.as_mut_ptr());
        let dispatch: unsafe extern "C" fn(*mut FacadeObject, *mut StringObject) -> u32 =
            core::mem::transmute((*(*facade).vtable).slots[0x58 / 4]);
        let status = dispatch(facade, &mut prefix);
        if status != 0 && status != 13 && status != 53 { break status; }
    };
    string_object_destroy_veneer(&mut prefix);
    string_object_destroy_veneer(remaining);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::app::path_probe::FacadeVtable;
    use crate::cxx::string_object::*;
    use crate::cxx::string_object_normalize_volume_path::*;
    use std::{boxed::Box, vec::Vec};

    static mut BUFFERS: Vec<Box<[u8; 256]>> = Vec::new();
    static mut PREFIXES: Vec<Vec<u8>> = Vec::new();
    static mut STATUSES: Vec<u32> = Vec::new();
    static mut RELEASES: usize = 0;

    unsafe extern "C" fn allocate(this: *mut StringObject, size: usize, flags: u32) -> *mut u8 {
        assert!(size <= 256);
        if flags == 1 && !(*this).payload.is_null() { return (*this).payload; }
        let mut buffer = Box::new([0u8; 256]);
        let pointer = buffer.as_mut_ptr();
        (*this).payload = pointer;
        (*core::ptr::addr_of_mut!(BUFFERS)).push(buffer);
        pointer
    }
    unsafe extern "C" fn clear(this: *mut StringObject) { (*this).payload = core::ptr::null_mut(); }
    unsafe extern "C" fn release(this: *mut StringObject) {
        RELEASES += 1;
        clear(this);
    }
    // Model the existing unported normalizer boundary for ordinary ASCII paths.
    unsafe extern "C" fn normalize(this: *mut StringObject, separator: u32, escaped: u32) {
        assert_eq!((separator, escaped), (47, 0));
        let bytes = std::ffi::CStr::from_ptr(string_object_c_str(this).cast()).to_bytes();
        let bytes = bytes.to_vec();
        let trimmed = bytes.as_slice();
        let start = trimmed.iter().position(|b| !b":/\\".contains(b)).unwrap_or(trimmed.len());
        let end = trimmed.iter().rposition(|b| !b":/\\".contains(b)).map_or(start, |i| i + 1);
        let out = (*this).payload;
        if out.is_null() { return; }
        for (i, &byte) in trimmed[start..end].iter().enumerate() {
            out.add(i).write(if b":/\\".contains(&byte) { b'/' } else { byte });
        }
        out.add(end - start).write(0);
    }
    unsafe extern "C" fn dispatch(_: *mut FacadeObject, path: *mut StringObject) -> u32 {
        let text = std::ffi::CStr::from_ptr(string_object_c_str(path).cast()).to_bytes().to_vec();
        let index = (*core::ptr::addr_of!(PREFIXES)).len();
        (*core::ptr::addr_of_mut!(PREFIXES)).push(text);
        (&*core::ptr::addr_of!(STATUSES))[index]
    }
    struct Restore(StringObjectAssignCstrOps, StringObjectOps, StringObjectPathOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            STRING_OBJECT_ASSIGN_CSTR_OPS = self.0;
            STRING_OBJECT_OPS = self.1;
            STRING_OBJECT_PATH_OPS = self.2;
            (*core::ptr::addr_of_mut!(BUFFERS)).clear();
        } }
    }

    #[test]
    fn cumulative_prefixes_tolerate_expected_statuses_and_stop_on_error() {
        let _assign = crate::testing::STRING_OBJECT_ASSIGN_CSTR_TEST_LOCK.lock().unwrap();
        let _release = crate::cxx::string_object::tests::STRING_OBJECT_OPS_TEST_LOCK.lock().unwrap();
        let _normalize = crate::cxx::string_object_normalize_volume_path::tests::OPS_LOCK.lock();
        unsafe {
            let _restore = Restore(STRING_OBJECT_ASSIGN_CSTR_OPS, STRING_OBJECT_OPS, STRING_OBJECT_PATH_OPS);
            STRING_OBJECT_ASSIGN_CSTR_OPS = StringObjectAssignCstrOps { allocate_payload: allocate, clear_payload: clear };
            STRING_OBJECT_OPS = StringObjectOps { release_payload: release };
            STRING_OBJECT_PATH_OPS.normalize_separators = normalize;
            let mut vtable: FacadeVtable = core::mem::zeroed();
            vtable.slots[0x58 / 4] = dispatch as *const () as usize;
            let mut facade = FacadeObject { vtable: &vtable };
            for (input, statuses, expected, result) in [
                ("", &[][..], &[][..], 0),
                ("///", &[][..], &[][..], 0),
                ("a/b/c", &[0, 13, 53][..], &["a", "a/b", "a/b/c"][..], 0),
                ("a/b/c", &[13, 7][..], &["a", "a/b"][..], 7),
                ("é\\中:z", &[53, 0, u32::MAX][..], &["é", "é/中", "é/中/z"][..], u32::MAX),
            ] {
                PREFIXES = Vec::new(); STATUSES = statuses.to_vec(); RELEASES = 0;
                let mut bytes = [0u8; 256];
                bytes[..input.len()].copy_from_slice(input.as_bytes());
                let source = StringObject { vtable: core::ptr::null(), payload: bytes.as_mut_ptr() };
                assert_eq!(path_prefix_dispatch(&mut facade, &source), result);
                let actual = &*core::ptr::addr_of!(PREFIXES);
                assert_eq!(actual, &expected.iter().map(|s| s.as_bytes().to_vec()).collect::<Vec<_>>());
                assert_eq!(&bytes[..input.len()], input.as_bytes());
                // Each component uses a prefix temporary; each later join uses a suffix.
                assert_eq!(core::ptr::addr_of!(RELEASES).read(), 2 + expected.len() * 2 + expected.len().saturating_sub(1));
            }
        }
    }
}
