//! C++ mutex-destroy wrappers.
//!
//! `cxx_mutex_destroy` is `FUN_08261e54` @ `0x08261e54`; its sibling
//! `mutex_destroy_return_this` is `FUN_082621dc` @ `0x082621dc`. Both are
//! 20-byte wrappers that destroy the POSIX mutex embedded at `this`, discard
//! the native status, and return `this`. They remain distinct hook targets.
//!
//! ```text
//! push {r4, lr}
//! mov  r4, r0
//! bl   0x082e82a4       ; pthread_mutex_destroy
//! mov  r0, r4
//! pop  {r4, pc}
//! ```
//!
//! `FUN_082621dc` has six direct unconditional `bl` callers and no direct
//! tail branches or predicated call forms. No aligned image word equals its
//! address, so it is not a data-dispatched virtual target.
//!
//! pthread_mutex_destroy is now ported directly in
//! [`crate::pthread_mutex_destroy`].

/// cxx_mutex_destroy — original: `FUN_08261e54` @ 0x08261e54
/// (20 bytes; 19 unconditional `bl` call sites, no predicated calls, and
/// four tail `b` callers, binary-scanned).
///
/// Destroys the embedded POSIX mutex at `this` through pthread_mutex_destroy,
/// ignores its status, and returns `this` unchanged. No NULL guard, matching
/// the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_mutex_destroy(this: *mut u8) -> *mut u8 {
    crate::cxx::pthread_mutex_destroy::pthread_mutex_destroy(this);
    this
}

/// mutex_destroy_return_this — original: `FUN_082621dc` @ `0x082621dc`
/// (20 bytes; six unconditional `bl` call sites, no predicated calls or
/// direct tail branches, binary-scanned).
///
/// Calls pthread_mutex_destroy on the mutex at `this`, discards its status,
/// and returns `this` unchanged. Like the raw ARM body, this wrapper has no
/// guard: NULL reaches the native destroy entry. Its unique target text
/// section preserves this separately linked wrapper's hook identity despite
/// its byte-identical sibling [`cxx_mutex_destroy`].
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.mutex_destroy_return_this")]
#[inline(never)]
pub unsafe extern "C" fn mutex_destroy_return_this(this: *mut u8) -> *mut u8 {
    crate::cxx::pthread_mutex_destroy::pthread_mutex_destroy(this);
    this
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn destroy_returns_this_without_writing_wrapper_storage() {
        let mut wrapper = [0xa5u8; 0x1c];
        let this = wrapper.as_mut_ptr();

        let returned = unsafe { cxx_mutex_destroy(this) };

        assert_eq!(returned, this, "the native status is discarded and mov r0, r4 returns this");
        assert_eq!(wrapper, [0xa5u8; 0x1c], "the wrapper itself performs no writes");
    }

    #[test]
    fn destroy_forwards_null_without_a_wrapper_guard() {
        let returned = unsafe { cxx_mutex_destroy(core::ptr::null_mut()) };

        assert!(returned.is_null(), "the unchanged NULL this pointer is returned");
    }

    #[test]
    fn sibling_destroy_returns_this_without_writing_wrapper_storage() {
        let mut wrapper = [0xa5u8; 0x1c];
        let this = wrapper.as_mut_ptr();

        let returned = unsafe { mutex_destroy_return_this(this) };

        assert_eq!(returned, this, "the native status is discarded and mov r0, r4 returns this");
        assert_eq!(wrapper, [0xa5u8; 0x1c], "the wrapper itself performs no writes");
    }

    #[test]
    fn sibling_destroy_forwards_null_without_a_wrapper_guard() {
        let returned = unsafe { mutex_destroy_return_this(core::ptr::null_mut()) };

        assert!(returned.is_null(), "the unchanged NULL this pointer is returned");
    }
}
