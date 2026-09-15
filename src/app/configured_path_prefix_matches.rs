//! configured_path_prefix_matches — original: `FUN_080a83c0` @ 0x080a83c0 (48 bytes).
//!
//! Raw ARM extent is 0x080a83c0..0x080a83f0; 0x080a83f0 is its literal-pool
//! word and the next distinct function begins at 0x080a83f4. Five incoming
//! plain `bl` calls were verified, with no incoming predicated `bl` calls.
//! The function skips one leading slash, then returns one exactly when that
//! path begins with the configured prefix held at offsets +4 (pointer) and
//! +0x10 (length) of the live configuration record. It otherwise returns
//! zero. The only deliberate deviation is the host configuration seam, which
//! substitutes native-width pointers for the target's 32-bit record fields.

use core::ptr;

const CONFIGURED_PATH_PREFIX_RECORD: *const u32 = 0x089c_a3a4 as *const u32;

#[cfg(not(target_os = "none"))]
static mut HOST_CONFIGURED_PATH_PREFIX: *const u8 = ptr::null();
#[cfg(not(target_os = "none"))]
static mut HOST_CONFIGURED_PATH_PREFIX_LENGTH: usize = 0;

#[inline(always)]
unsafe fn configured_prefix() -> (*const u8, usize) {
    #[cfg(target_os = "none")]
    {
        let prefix = ptr::read_volatile(CONFIGURED_PATH_PREFIX_RECORD.add(1)) as *const u8;
        let length = ptr::read_volatile(CONFIGURED_PATH_PREFIX_RECORD.add(4)) as usize;
        (prefix, length)
    }

    #[cfg(not(target_os = "none"))]
    {
        (
            ptr::read_volatile(ptr::addr_of!(HOST_CONFIGURED_PATH_PREFIX)),
            ptr::read_volatile(ptr::addr_of!(HOST_CONFIGURED_PATH_PREFIX_LENGTH)),
        )
    }
}

/// Returns whether `path`, after one optional leading slash, starts with the configured prefix.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn configured_path_prefix_matches(path: *const u8) -> i32 {
    let path = if ptr::read_volatile(path) == b'/' {
        path.add(1)
    } else {
        path
    };
    let (prefix, length) = configured_prefix();
    let compare = ptr::read_volatile(
        &(crate::libc::strncmp::strncmp as unsafe extern "C" fn(*const u8, *const u8, usize) -> i32),
    );
    let comparison = compare(prefix, path, length);
    let result = 1i32.wrapping_sub(comparison);
    if (comparison as u32) > 1 { 0 } else { result }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn set_prefix(prefix: *const u8, length: usize) {
        HOST_CONFIGURED_PATH_PREFIX = prefix;
        HOST_CONFIGURED_PATH_PREFIX_LENGTH = length;
    }

    #[test]
    fn matches_prefix_with_or_without_one_leading_slash() {
        let _guard = TEST_LOCK.lock();
        let prefix = b"music/";
        unsafe {
            set_prefix(prefix.as_ptr(), prefix.len());
            assert_eq!(configured_path_prefix_matches(b"music/album\0".as_ptr()), 1);
            assert_eq!(configured_path_prefix_matches(b"/music/album\0".as_ptr()), 1);
        }
    }

    #[test]
    fn rejects_mismatch_and_only_skips_one_slash() {
        let _guard = TEST_LOCK.lock();
        let prefix = b"music/";
        unsafe {
            set_prefix(prefix.as_ptr(), prefix.len());
            assert_eq!(configured_path_prefix_matches(b"videos/clip\0".as_ptr()), 0);
            assert_eq!(configured_path_prefix_matches(b"//music/album\0".as_ptr()), 0);
        }
    }

    #[test]
    fn compares_only_the_configured_prefix_length() {
        let _guard = TEST_LOCK.lock();
        let prefix = b"music";
        unsafe {
            set_prefix(prefix.as_ptr(), prefix.len());
            assert_eq!(configured_path_prefix_matches(b"music-library\0".as_ptr()), 1);
        }
    }
}
