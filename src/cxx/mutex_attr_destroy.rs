//! `cxx_mutexattr_destroy` — `FUN_08261d30` @ 0x08261d30.
//!
//! True extent: 20 bytes, 0x08261d30..0x08261d44, five raw A32 words;
//! the next function begins with mov r1,#0. Whole-image word decoding finds
//! two plain inbound BLs (0x08261e48, 0x082621d0), no predicated inbound
//! BLs, and one plain outbound BL to 0x082e8474, no predicated outbound BLs.
//! Save attr, call pthread_mutexattr_destroy, discard status, return attr.
//!
//! Deliberate deviations: the unported pthread callee remains a fixed-address
//! firmware seam on target. Hosts model its verified magic check and aligned
//! first-word clear; NULL or invalid magic leaves storage untouched. The raw
//! callee has 44 code bytes plus its MTXA literal at 0x082e84a0. Pointer-sized
//! scope storage matches existing constructors; only its first u32 is accessed.

#[cfg(not(target_os = "none"))]
use super::mutex_attr_init::MUTEXATTR_MAGIC;

unsafe fn call_pthread_mutexattr_destroy(attr: *mut usize) {
    #[cfg(target_os = "none")]
    {
        let destroy: unsafe extern "C" fn(*mut usize) -> u32 =
            core::mem::transmute(0x082e8474usize);
        let _ = destroy(attr);
    }
    #[cfg(not(target_os = "none"))]
    {
        if !attr.is_null() && attr.cast::<u32>().read() == MUTEXATTR_MAGIC {
            attr.cast::<u32>().write(0);
        }
    }
}

/// Return the attribute pointer, not the wrapped pthread status.
///
/// # Safety
/// A non-NULL attr must point to a readable, writable, aligned u32.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutexattr_destroy(attr: *mut usize) -> *mut usize {
    call_pthread_mutexattr_destroy(attr);
    attr
}

/// Unit-returning constructor dispatch adapter; the original callers overwrite r0.
pub(super) unsafe extern "C" fn attr_destroy_port(attr: *mut usize) {
    cxx_mutexattr_destroy(attr);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_only_valid_magic_and_preserves_type_and_guards() {
        for magic in [MUTEXATTR_MAGIC, 0, MUTEXATTR_MAGIC ^ 1, u32::MAX] {
            let mut words = [magic, 0xdead_beef, 0xa5a5_5a5a, 0x1234_5678];
            let mut expected = words;
            if magic == MUTEXATTR_MAGIC { expected[0] = 0; }
            let attr = words.as_mut_ptr().cast::<usize>();
            assert_eq!(unsafe { cxx_mutexattr_destroy(attr) }, attr);
            assert_eq!(words, expected);
            // Destroying an already-invalidated attr must leave every word intact.
            unsafe { cxx_mutexattr_destroy(attr); }
            assert_eq!(words, expected);
        }
    }

    #[test]
    fn null_is_returned_without_access() {
        assert_eq!(unsafe { cxx_mutexattr_destroy(core::ptr::null_mut()) }, core::ptr::null_mut());
    }
}
