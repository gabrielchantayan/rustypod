//! Counted UTF-16 relative path resolver wrapper.
//!
//! Port: [`path_facade_resolve_relative`] — original: `FUN_0805a770` @
//! **0x0805a770** (216 bytes, `0x0805a770..0x0805a848`). Raw `osos.dec`
//! decoding establishes seven plain `bl` instructions and one predicated
//! `blne` in the body; three inbound direct call sites are plain `bl`s.
//!
//! Algorithm: reject a NULL base, relative path, or destination by returning
//! `-50`; convert the counted UTF-16 relative path to a bounded counted UTF-8
//! temporary; copy the base's u16 prefix and form `base[/]relative` in the
//! destination's cstr tail; then hand the counted result and a 0x4c-byte
//! workspace to the unresolved path-facade worker at 0x0805a8e4. The worker's
//! status is returned unchanged.
//!
//! Deliberate deviations: Rust zero-initializes the stack workspace whose
//! unused words are indeterminate in stock, and represents its first target
//! pointer as a `u32`; the worker initializes the workspace before consuming
//! it. The unported worker is a fixed-address seam on-device and fails closed
//! on hosts.

use crate::cxx::string_encoding::utf16_to_utf8_capped;
use crate::libc::{strcat::strcat, strcpy::strcpy, strlen::strlen};

/// Load address of the unresolved path-facade worker (`FUN_0805a8e4`).
pub const PATH_FACADE_RESOLVE_COUNTED_IMPL_ADDRESS: usize = 0x0805_a8e4;

/// Stock NULL-argument status (`mvn r0,#0x31`).
pub const PATH_FACADE_RESOLVE_RELATIVE_ERROR: i32 = -0x32;

/// The unresolved worker accepts the completed counted path, a 0x4c-byte
/// workspace, and an optional result pointer.
pub type PathFacadeResolveCountedImpl = unsafe extern "C" fn(*mut u8, *mut u32, *mut u16) -> i32;

unsafe extern "C" fn firmware_path_facade_resolve_counted(
    path: *mut u8, workspace: *mut u32, result: *mut u16,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let worker: PathFacadeResolveCountedImpl =
            core::mem::transmute(PATH_FACADE_RESOLVE_COUNTED_IMPL_ADDRESS);
        worker(path, workspace, result)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (path, workspace, result);
        PATH_FACADE_RESOLVE_RELATIVE_ERROR
    }
}

/// Replaceable boundary for the unresolved worker at 0x0805a8e4.
pub static mut PATH_FACADE_RESOLVE_COUNTED_IMPL: PathFacadeResolveCountedImpl =
    firmware_path_facade_resolve_counted;

#[inline(always)]
unsafe fn path_facade_resolve_counted_impl() -> PathFacadeResolveCountedImpl {
    PATH_FACADE_RESOLVE_COUNTED_IMPL
}

/// Builds a counted UTF-8 path by appending `relative_counted_utf16` to
/// `base_counted_path`, then returns the path-facade worker's status.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn path_facade_resolve_relative(
    base_counted_path: *const u8,
    relative_counted_utf16: *const u8,
    destination_counted_path: *mut u8,
    workspace: *mut u32,
) -> i32 {
    if base_counted_path.is_null() || relative_counted_utf16.is_null() || destination_counted_path.is_null() {
        return PATH_FACADE_RESOLVE_RELATIVE_ERROR;
    }

    let mut relative = [0u8; 257];
    let mut relative_len = 0u32;
    utf16_to_utf8_capped(
        relative_counted_utf16.add(2) as *const u16,
        (relative_counted_utf16 as *const u16).read() as i32,
        relative.as_mut_ptr().add(1),
        0xff,
        &mut relative_len,
    );
    relative[0] = relative_len as u8;

    (destination_counted_path as *mut u16).write((base_counted_path as *const u16).read());
    let destination = destination_counted_path.add(2);
    let base = base_counted_path.add(2);
    if base.read() == 0 {
        strcpy(destination, relative.as_ptr().add(1));
    } else {
        strcpy(destination, base);
        let end = destination.add(strlen(destination));
        if end.read() != b'\\' {
            strcat(destination, b"\\\0".as_ptr());
        }
        strcat(destination, relative.as_ptr().add(1));
    }

    let mut local_workspace = [0u32; 19];
    let workspace = if workspace.is_null() {
        local_workspace[0] = relative.as_ptr() as usize as u32;
        local_workspace.as_mut_ptr()
    } else {
        workspace
    };
    path_facade_resolve_counted_impl()(destination_counted_path, workspace, core::ptr::null_mut())
}
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::MutexGuard;

    #[repr(align(2))]
    struct Aligned<const N: usize>([u8; N]);

    static mut RECORD: Option<std::vec::Vec<u8>> = None;
    static mut STATUS: i32 = 0;

    unsafe extern "C" fn recording_worker(path: *mut u8, _workspace: *mut u32, _result: *mut u16) -> i32 {
        let mut bytes = std::vec::Vec::new();
        let mut p = path;
        loop {
            let byte = p.read();
            bytes.push(byte);
            if byte == 0 { break; }
            p = p.add(1);
        }
        RECORD = Some(bytes);
        STATUS
    }

    struct SeamGuard;
    impl SeamGuard {
        fn lock() -> (MutexGuard<'static, ()>, Self) {
            let lock = crate::testing::PATH_FACADE_RESOLVE_RELATIVE_TEST_LOCK.lock();
            unsafe {
                PATH_FACADE_RESOLVE_COUNTED_IMPL = recording_worker;
                RECORD = None;
                STATUS = 0;
            }
            (lock, Self)
        }
    }
    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe { PATH_FACADE_RESOLVE_COUNTED_IMPL = firmware_path_facade_resolve_counted; }
        }
    }

    #[test]
    fn joins_nonempty_base_with_one_separator_and_returns_worker_status() {
        let (_lock, _seam) = SeamGuard::lock();
        let base = Aligned([3u8, 0, b'f', b'o', b'o', 0]);
        let relative = Aligned([0u8, 0]);
        let mut destination = Aligned([0u8; 32]);
        unsafe {
            STATUS = -7;
            assert_eq!(path_facade_resolve_relative(base.0.as_ptr(), relative.0.as_ptr(), destination.0.as_mut_ptr(), core::ptr::null_mut()), -7);
            assert_eq!(&destination.0[..7], &[3, 0, b'f', b'o', b'o', b'\\', 0]);
            assert_eq!(RECORD.as_ref().unwrap(), &[3, 0]);
        }
    }

    #[test]
    fn preserves_existing_separator_and_empty_base_uses_relative() {
        let (_lock, _seam) = SeamGuard::lock();
        let relative = Aligned([0u8, 0]);
        let mut destination = Aligned([0u8; 16]);
        unsafe {
            let slash_base = Aligned([4u8, 0, b'f', b'o', b'o', b'\\', 0]);
            assert_eq!(path_facade_resolve_relative(slash_base.0.as_ptr(), relative.0.as_ptr(), destination.0.as_mut_ptr(), core::ptr::null_mut()), 0);
            let empty_base = Aligned([0u8, 0, 0]);
            path_facade_resolve_relative(empty_base.0.as_ptr(), relative.0.as_ptr(), destination.0.as_mut_ptr(), core::ptr::null_mut());
            assert_eq!(&destination.0[..3], &[0, 0, 0]);
        }
    }

    #[test]
    fn rejects_each_null_argument_without_calling_worker() {
        let (_lock, _seam) = SeamGuard::lock();
        let base = Aligned([0u8, 0, 0]);
        let relative = Aligned([0u8, 0]);
        let mut destination = Aligned([0u8; 3]);
        unsafe {
            assert_eq!(path_facade_resolve_relative(core::ptr::null(), relative.0.as_ptr(), destination.0.as_mut_ptr(), core::ptr::null_mut()), -50);
            assert_eq!(path_facade_resolve_relative(base.0.as_ptr(), core::ptr::null(), destination.0.as_mut_ptr(), core::ptr::null_mut()), -50);
            assert_eq!(path_facade_resolve_relative(base.0.as_ptr(), relative.0.as_ptr(), core::ptr::null_mut(), core::ptr::null_mut()), -50);
            assert!(RECORD.is_none());
        }
    }
}
