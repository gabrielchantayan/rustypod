//! iTunes-relative path resolution — FUN_080bd7f8 at 0x080bd7f8.
//!
//! Raw extent: 168 code bytes (0x080bd7f8..0x080bd8a0), followed by
//! 28 literal bytes; next function starts at 0x080bd8bc. Eight plain BLs
//! and one BLNE in the body; two inbound plain BLs, no predicated BLs.
//! Append the filename to `iPod_Control\\iTunes\\`, store the resulting
//! C string after a zero u16 prefix, optionally copy 258 bytes to the caller,
//! then resolve the path using a 76-byte workspace and return its status.
//! Deliberate deviations: initialize unused stack bytes; use existing Rust
//! string ports and the shared fixed-address resolver seam rather than IRAM
//! veneers. The filename must fit the stock 64-byte temporary (43 bytes).

//! ARM match.py reports 71 versus 42 instructions: LLVM inlines both length
//! scans, emits runtime clears for initialized buffers, and uses BLX for the
//! shared resolver seam. Append, bounded copy, conditional 258-byte snapshot,
//! and resolver return remain in the original order.
use crate::app::path_facade_resolve_relative::PATH_FACADE_RESOLVE_COUNTED_IMPL;
use crate::libc::{bounded_copy::strcpy_bounded_nul, cstr_append_bounded::cstr_append_bounded,
    strlen::strlen_byte_loop};

/// # Safety
/// `filename` must be NUL-terminated, at most 43 bytes long. A non-NULL
/// `destination` must permit 258 writable bytes. The resolver seam must obey
/// its documented ABI; the copied path precedes any resolver mutation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn itunes_path_resolve(destination: *mut u8, filename: *const u8) -> i32 {
    let mut text = [0u8; 64];
    text[..21].copy_from_slice(b"iPod_Control\\iTunes\\\0");
    let length = strlen_byte_loop(text.as_ptr()).wrapping_add(strlen_byte_loop(filename)).wrapping_add(1);
    cstr_append_bounded(filename, text.as_mut_ptr(), length as usize);
    let mut path = [0u32; 65];
    let path_bytes = path.as_mut_ptr() as *mut u8;
    strcpy_bounded_nul(text.as_ptr(), path_bytes.add(2), length as i32);
    if !destination.is_null() {
        crate::libc::rt_memcpy::__rt_memcpy(destination, path_bytes, 258);
    }
    let mut workspace = [0u32; 19];
    let resolver = core::ptr::read_volatile(core::ptr::addr_of!(PATH_FACADE_RESOLVE_COUNTED_IMPL));
    resolver(path_bytes, workspace.as_mut_ptr(), core::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn mutate_and_fail(path: *mut u8, _: *mut u32, _: *mut u16) -> i32 {
        path.add(2).write(b'X');
        -43
    }

    #[test]
    fn empty_and_maximum_filename_copy_before_resolution() {
        let _lock = crate::testing::PATH_FACADE_RESOLVE_RELATIVE_TEST_LOCK.lock();
        unsafe {
            let original = PATH_FACADE_RESOLVE_COUNTED_IMPL;
            struct Restore(crate::app::path_facade_resolve_relative::PathFacadeResolveCountedImpl);
            impl Drop for Restore {
                fn drop(&mut self) { unsafe { PATH_FACADE_RESOLVE_COUNTED_IMPL = self.0; } }
            }
            let _restore = Restore(original);
            PATH_FACADE_RESOLVE_COUNTED_IMPL = mutate_and_fail;
            for length in [0, 1, 43] {
                let mut filename = [b'f'; 44];
                filename[length] = 0;
                let mut output = [0xa5u8; 260];
                assert_eq!(itunes_path_resolve(output.as_mut_ptr().add(1), filename.as_ptr()), -43);
                assert_eq!(output[0], 0xa5);
                assert_eq!(output[259], 0xa5);
                assert_eq!(&output[1..3], &[0, 0]);
                assert_eq!(&output[3..23], b"iPod_Control\\iTunes\\");
                assert_eq!(&output[23..23 + length], &filename[..length]);
                assert!(output[23 + length..259].iter().all(|&byte| byte == 0));
            }
            assert_eq!(itunes_path_resolve(core::ptr::null_mut(), b"\0".as_ptr()), -43);
        }
    }
}
