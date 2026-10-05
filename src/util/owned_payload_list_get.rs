//! Lazy owned-payload list head — `FUN_081e6c38` @ 0x081e6c38.
//!
//! True extent: 92 bytes, [0x081e6c38, 0x081e6c94): 76 instruction bytes
//! and four literal words. Verified raw-word count: three plain outbound BLs,
//! zero predicated BLs; two plain inbound BLs, zero predicated inbound BLs.
//! Test guard bit zero, acquire the ADS guard, zero the fixed list-head word,
//! register its opaque shutdown handler, release the guard, and return the
//! head address on every path. Registration failure does not undo initialization.
//!
//! Deliberate deviations: host statics replace fixed firmware words. The handler
//! literal 0x081dbf80 is inside existing code, not a recovered function entry;
//! target builds preserve it verbatim, while host invocation explicitly fails.
//! Volatile runtime bindings retain registration/release calls despite LLVM's
//! knowledge that the ported release body is empty.

use core::ffi::c_void;
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::{cxa_atexit, ShutdownHandlerFn};

type Register = unsafe extern "C" fn(*mut c_void, ShutdownHandlerFn, i32) -> i32;
type Release = unsafe extern "C" fn(*mut u32);
static mut REGISTER: Register = cxa_atexit;
static mut RELEASE: Release = cxa_guard_release;

#[cfg(not(target_os = "none"))]
static mut GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut HEAD: u32 = 0;

#[inline(always)]
unsafe fn guard() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x089d_05e4 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(GUARD) }
}

#[inline(always)]
unsafe fn head() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x089d_05e8 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of_mut!(HEAD) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_host_handler(_object: *mut c_void) {
    panic!("opaque firmware shutdown handler 0x081dbf80 cannot run on host");
}

#[inline(always)]
unsafe fn handler() -> ShutdownHandlerFn {
    #[cfg(target_os = "none")]
    { core::mem::transmute(0x081d_bf80usize) }
    #[cfg(not(target_os = "none"))]
    { unavailable_host_handler }
}

/// Returns the fixed ARM-width list-head cell, initializing it once.
///
/// # Safety
/// Firmware guard/head addresses must be valid; callers must serialize access.
/// List links are u32 target addresses, including on a 64-bit host.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_payload_list_get() -> *mut u32 {
    let guard = guard();
    let head = head();
    if core::ptr::read_volatile(guard) & 1 == 0 && cxa_guard_acquire(guard) != 0 {
        head.write(0);
        core::ptr::read_volatile(core::ptr::addr_of!(REGISTER))(
            head.cast(), handler(), 0x089c_a09c,
        );
        core::ptr::read_volatile(core::ptr::addr_of!(RELEASE))(guard);
    }
    head
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::shutdown_chain::{shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC};
    use std::boxed::Box;

    unsafe extern "C" fn allocate(_size: usize) -> *mut u8 {
        Box::into_raw(Box::new(ShutdownNode {
            next: core::ptr::null_mut(), arg: core::ptr::null_mut(),
            handler: unavailable_host_handler, key: 0,
        })).cast()
    }

    unsafe extern "C" fn fail_allocate(_size: usize) -> *mut u8 { core::ptr::null_mut() }

    #[test]
    fn initializes_once_and_preserves_inserted_head() {
        unsafe {
            let old_alloc = SHUTDOWN_ALLOC;
            let old_chain = shutdown_chain_head().read();
            SHUTDOWN_ALLOC = allocate;
            GUARD = 0;
            HEAD = 0xdead_beef;
            assert_eq!(owned_payload_list_get(), head());
            assert_eq!(HEAD, 0);
            assert_eq!(GUARD, 1);
            let node = shutdown_chain_head().read();
            assert_eq!((*node).arg, head().cast());
            assert_eq!((*node).key, 0x089c_a09c);
            HEAD = 0x1234_5678;
            assert_eq!(owned_payload_list_get(), head());
            assert_eq!(HEAD, 0x1234_5678);
            assert_eq!(shutdown_chain_head().read(), node);
            shutdown_chain_head().write(old_chain);
            drop(Box::from_raw(node));
            SHUTDOWN_ALLOC = old_alloc;
            GUARD = 0;
            HEAD = 0;
        }
    }

    #[test]
    fn nonzero_guards_preserve_head_even_when_low_bit_clear() {
        unsafe {
            for value in [1, 2, 3, 0x8000_0000, u32::MAX] {
                GUARD = value;
                HEAD = 0xabcd_1234;
                assert_eq!(owned_payload_list_get(), head());
                assert_eq!(HEAD, 0xabcd_1234);
                assert_eq!(GUARD, value);
            }
            GUARD = 0;
            HEAD = 0;
        }
    }

    #[test]
    fn registration_failure_still_publishes_initialization() {
        unsafe {
            let old_alloc = SHUTDOWN_ALLOC;
            let old_chain = shutdown_chain_head().read();
            SHUTDOWN_ALLOC = fail_allocate;
            GUARD = 0;
            HEAD = u32::MAX;
            assert_eq!(owned_payload_list_get(), head());
            assert_eq!(HEAD, 0);
            assert_eq!(GUARD, 1);
            assert_eq!(shutdown_chain_head().read(), old_chain);
            HEAD = 17;
            owned_payload_list_get();
            assert_eq!(HEAD, 17);
            SHUTDOWN_ALLOC = old_alloc;
            GUARD = 0;
            HEAD = 0;
        }
    }
}
