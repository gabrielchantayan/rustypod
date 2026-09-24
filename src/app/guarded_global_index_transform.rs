//! `guarded_global_index_transform` — original: `FUN_080aac70` @
//! `0x080aac70` (Ghidra: 172 bytes; raw executable body: 72 bytes,
//! `0x080aac70..0x080aacb7`).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM words establish three plain unconditional direct `bl` instructions
//! (`cxa_guard_acquire` @ `0x082ab31c`, the unidentified allocator thunk @
//! `0x0805b0cc`, and `cxa_guard_release` @ `0x082ab338`) and no predicated
//! `bl` forms. It has three plain inbound `bl` callers and no predicated
//! inbound calls. When the guard word is clear, it claims the guard, calls the
//! allocator thunk, stores its result in the adjacent global word, and releases
//! the guard. It then tail-dispatches the input through `0x080633f0` with that
//! global state.
//!
//! # Deliberate deviations
//!
//! The allocator thunk and tail target have no recovered semantic identities.
//! Target builds call their verified retailOS addresses; host builds use narrow
//! callback seams. The tail branch is an ordinary Rust return. LLVM folds the
//! verified `cxa_guard_release` call because the already-ported helper is a
//! deliberate no-op, preserving its observable behavior.
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};

/// ABI of the allocator thunk at `0x0805b0cc`.
pub type GuardedGlobalAllocate = unsafe extern "C" fn() -> *mut u32;
/// ABI of the tail target at `0x080633f0`.
pub type GuardedGlobalTransform = unsafe extern "C" fn(*mut u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate() -> *mut u32 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_transform(_state: *mut u32, value: u32) -> u32 { value }

#[cfg(not(target_os = "none"))]
pub static mut GUARDED_GLOBAL_ALLOCATE: GuardedGlobalAllocate = missing_allocate;
#[cfg(not(target_os = "none"))]
pub static mut GUARDED_GLOBAL_TRANSFORM: GuardedGlobalTransform = missing_transform;
#[cfg(not(target_os = "none"))]
pub static mut GUARDED_GLOBAL_GUARD: u32 = 0;
#[cfg(not(target_os = "none"))]
pub static mut GUARDED_GLOBAL_STATE: *mut u32 = core::ptr::null_mut();

/// Initializes the global state on first use, then transforms `value`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn guarded_global_index_transform(value: u32) -> u32 {
    #[cfg(target_os = "none")]
    let (guard, state) = (0x089c_b19cusize as *mut u32, 0x089c_b1a0usize as *mut *mut u32);
    #[cfg(not(target_os = "none"))]
    let (guard, state) = unsafe { (core::ptr::addr_of_mut!(GUARDED_GLOBAL_GUARD), core::ptr::addr_of_mut!(GUARDED_GLOBAL_STATE)) };

    #[cfg(target_os = "none")]
    let (allocate, transform): (GuardedGlobalAllocate, GuardedGlobalTransform) = unsafe {
        (core::mem::transmute(0x0805_b0ccusize), core::mem::transmute(0x0806_33f0usize))
    };
    #[cfg(not(target_os = "none"))]
    let (allocate, transform) = unsafe { (GUARDED_GLOBAL_ALLOCATE, GUARDED_GLOBAL_TRANSFORM) };

    if unsafe { guard.read_volatile() } & 1 == 0 && unsafe { cxa_guard_acquire(guard) } != 0 {
        unsafe { state.write(allocate()) };
        unsafe { cxa_guard_release(guard) };
    }
    unsafe { transform(state.read(), value) }
}


#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut ALLOCATIONS: u32 = 0;
    static mut TRANSFORM_STATE: *mut u32 = core::ptr::null_mut();
    static mut TRANSFORM_VALUE: u32 = 0;
    static mut ALLOCATED_STATE: u32 = 0;

    unsafe extern "C" fn allocate() -> *mut u32 {
        unsafe { ALLOCATIONS += 1; core::ptr::addr_of_mut!(ALLOCATED_STATE) }
    }
    unsafe extern "C" fn transform(state: *mut u32, value: u32) -> u32 {
        unsafe { TRANSFORM_STATE = state; TRANSFORM_VALUE = value; }
        value.wrapping_add(1)
    }

    #[test]
    fn initializes_once_and_forwards_the_value() {
        let _lock = TEST_LOCK.lock();
        unsafe {
            ALLOCATIONS = 0; TRANSFORM_STATE = core::ptr::null_mut(); TRANSFORM_VALUE = 0;
            GUARDED_GLOBAL_GUARD = 0; GUARDED_GLOBAL_STATE = core::ptr::null_mut();
            GUARDED_GLOBAL_ALLOCATE = allocate; GUARDED_GLOBAL_TRANSFORM = transform;
            assert_eq!(guarded_global_index_transform(u32::MAX), 0);
            assert_eq!(ALLOCATIONS, 1);
            assert_eq!(TRANSFORM_STATE, core::ptr::addr_of_mut!(ALLOCATED_STATE));
            assert_eq!(TRANSFORM_VALUE, u32::MAX);
            assert_eq!(guarded_global_index_transform(9), 10);
            assert_eq!(ALLOCATIONS, 1);
        }
    }
}
