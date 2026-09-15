//! Temporary-buffer replacement helper.
//!
//! `temporary_buffer_replace` — original: `FUN_0826756c` @ **0x0826756c**
//! (156 bytes, `0x0826756c..0x08267607`). Raw ARM has five inbound direct
//! calls: four plain `bl` and one predicated `bl`; its body makes four direct
//! calls, one predicated: `cxa_guard_acquire` @ 0x082ab31c,
//! `cxa_guard_release` @ 0x082ab338, `operator_delete` @ 0x082aad24, and
//! `operator_new` @ 0x082aadd4.
//!
//! Algorithm: count this replacement operation, lazily publish the fixed
//! 4 KiB temporary buffer, release the prior buffer unless it is that fixed
//! buffer, then return the fixed buffer for a request at most 0x1000 bytes
//! when this is the outermost operation. Nested or larger requests allocate
//! an exact-size replacement. The allocated path performs the original's
//! second counter decrement. Deliberate deviation: host globals model the
//! three firmware words; target builds access their fixed retailOS addresses.

use core::ptr;

use crate::heap::veneers::{operator_delete, operator_new};
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};

type CxaGuardRelease = unsafe extern "C" fn(*mut u32);

/// Volatile binding preserves the predicated retail `bl cxa_guard_release`;
/// its empty body would otherwise be folded away.
static mut TEMPORARY_BUFFER_CXA_GUARD_RELEASE: CxaGuardRelease = cxa_guard_release;

#[inline(always)]
unsafe fn temporary_buffer_cxa_guard_release() -> CxaGuardRelease {
    unsafe { ptr::read_volatile(ptr::addr_of!(TEMPORARY_BUFFER_CXA_GUARD_RELEASE)) }
}

const TEMPORARY_BUFFER_DEPTH_ADDRESS: usize = 0x08a0_fc34;
const TEMPORARY_BUFFER_ADDRESS: usize = 0x08a0_fc38;
const TEMPORARY_BUFFER_GUARD_ADDRESS: usize = 0x08a0_fc3c;
const FIXED_TEMPORARY_BUFFER: *mut u8 = 0x08b3_1950 as *mut u8;
const FIXED_TEMPORARY_BUFFER_SIZE: u32 = 0x1000;

#[cfg(not(target_os = "none"))]
static mut TEMPORARY_BUFFER_DEPTH: u32 = 0;
#[cfg(not(target_os = "none"))]
static mut TEMPORARY_BUFFER: *mut u8 = ptr::null_mut();
#[cfg(not(target_os = "none"))]
static mut TEMPORARY_BUFFER_GUARD: u32 = 0;

#[inline(always)]
unsafe fn temporary_buffer_depth() -> *mut u32 {
    #[cfg(target_os = "none")]
    { TEMPORARY_BUFFER_DEPTH_ADDRESS as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(TEMPORARY_BUFFER_DEPTH) }
}

#[inline(always)]
unsafe fn temporary_buffer_slot() -> *mut *mut u8 {
    #[cfg(target_os = "none")]
    { TEMPORARY_BUFFER_ADDRESS as *mut *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(TEMPORARY_BUFFER) }
}

#[inline(always)]
unsafe fn temporary_buffer_guard() -> *mut u32 {
    #[cfg(target_os = "none")]
    { TEMPORARY_BUFFER_GUARD_ADDRESS as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(TEMPORARY_BUFFER_GUARD) }
}

/// Replaces `old_buffer` with a temporary buffer suitable for `requested_size`.
///
/// # Safety
///
/// `old_buffer` is either null, the fixed temporary buffer, or a live block
/// returned by the tag-2 C++ allocator. `out` must name two writable u32-sized
/// target words: buffer pointer followed by byte count.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn temporary_buffer_replace(out: *mut u32, old_buffer: *mut u8, requested_size: u32) {
    let depth = unsafe { temporary_buffer_depth() };
    let buffer = unsafe { temporary_buffer_slot() };
    let guard = unsafe { temporary_buffer_guard() };
    let operation_depth = unsafe { ptr::read_volatile(depth).wrapping_add(1) };
    unsafe { ptr::write_volatile(depth, operation_depth) };

    if unsafe { ptr::read_volatile(guard) } & 1 == 0 && unsafe { cxa_guard_acquire(guard) } != 0 {
        unsafe {
            ptr::write_volatile(buffer, FIXED_TEMPORARY_BUFFER);
            temporary_buffer_cxa_guard_release()(guard);
        }
    }

    let fixed_buffer = unsafe { ptr::read_volatile(buffer) };
    if old_buffer != fixed_buffer {
        unsafe { operator_delete(old_buffer) };
    }

    unsafe { ptr::write_volatile(depth, ptr::read_volatile(depth).wrapping_sub(1)) };
    let (replacement, replacement_size) = if requested_size <= FIXED_TEMPORARY_BUFFER_SIZE && operation_depth <= 1 {
        (fixed_buffer, 0)
    } else {
        let replacement = unsafe { operator_new(requested_size as usize) };
        unsafe { ptr::write_volatile(depth, ptr::read_volatile(depth).wrapping_sub(1)) };
        (replacement, requested_size)
    };
    unsafe {
        ptr::write_volatile(out, replacement as u32);
        ptr::write_volatile(out.add(1), replacement_size);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static STATE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    unsafe fn reset(depth: u32, buffer: *mut u8, guard: u32) {
        TEMPORARY_BUFFER_DEPTH = depth;
        TEMPORARY_BUFFER = buffer;
        TEMPORARY_BUFFER_GUARD = guard;
    }

    #[test]
    fn initializes_and_returns_fixed_buffer_at_capacity() {
        let _lock = STATE_LOCK.lock();
        unsafe {
            reset(0, ptr::null_mut(), 0);
            let mut out = [0; 2];
            temporary_buffer_replace(out.as_mut_ptr(), ptr::null_mut(), FIXED_TEMPORARY_BUFFER_SIZE);
            assert_eq!(out, [FIXED_TEMPORARY_BUFFER as u32, 0]);
            assert_eq!(TEMPORARY_BUFFER_GUARD, 1);
            assert_eq!(TEMPORARY_BUFFER, FIXED_TEMPORARY_BUFFER);
            assert_eq!(TEMPORARY_BUFFER_DEPTH, 0);
        }
    }

    #[test]
    fn nested_small_request_allocates_and_double_decrements_depth() {
        let _state_lock = STATE_LOCK.lock();
        let _heap_lock = crate::heap::veneers::tests::mock_heap();
        unsafe {
            reset(2, FIXED_TEMPORARY_BUFFER, 1);
            let mut out = [0; 2];
            temporary_buffer_replace(out.as_mut_ptr(), FIXED_TEMPORARY_BUFFER, 1);
            assert_eq!(out, [crate::heap::veneers::tests::mock_block() as u32, 1]);
            assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 1, 2));
            assert_eq!(TEMPORARY_BUFFER_DEPTH, 1);
        }
    }

    #[test]
    fn oversized_request_allocates_exact_size() {
        let _state_lock = STATE_LOCK.lock();
        let _heap_lock = crate::heap::veneers::tests::mock_heap();
        unsafe {
            reset(0, FIXED_TEMPORARY_BUFFER, 1);
            let mut out = [0; 2];
            temporary_buffer_replace(out.as_mut_ptr(), FIXED_TEMPORARY_BUFFER, FIXED_TEMPORARY_BUFFER_SIZE + 1);
            assert_eq!(out, [crate::heap::veneers::tests::mock_block() as u32, FIXED_TEMPORARY_BUFFER_SIZE + 1]);
            assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 0x1001, 2));
            assert_eq!(TEMPORARY_BUFFER_DEPTH, u32::MAX);
        }
    }
}
