//! `locked_callback_predicate` — original: `FUN_0814decc` @ `0x0814decc`
//! (60 bytes, `0x0814decc..0x0814df08`; five unconditional `bl` callers,
//! zero predicated forms).
//!
//! # Algorithm
//!
//! Acquires the [`CountedMutex`] in word 4 of the opaque object, invokes the
//! vtable slot `+0x18` of the target in word 1, releases the same lock, and
//! normalizes the callback's integer result to a boolean. The lock is held
//! across the virtual call and is released before the result is returned.
//!
//! # Deliberate deviations
//!
//! Host pointers cannot inhabit retailOS's 32-bit object words. Host builds
//! therefore use an operation seam which receives the target and lock words;
//! target builds read and dispatch the recovered target-width vtable directly.

use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted, CountedMutex};

/// Host ABI for the virtual callback and counted-lock pair.
#[derive(Clone, Copy)]
pub struct LockedCallbackPredicateOps {
    pub lock: unsafe extern "C" fn(u32),
    pub invoke: unsafe extern "C" fn(u32) -> i32,
    pub unlock: unsafe extern "C" fn(u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lock(_lock: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_invoke(_target: u32) -> i32 { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_unlock(_lock: u32) {}

#[cfg(not(target_os = "none"))]
pub static mut LOCKED_CALLBACK_PREDICATE_OPS: LockedCallbackPredicateOps = LockedCallbackPredicateOps {
    lock: missing_lock,
    invoke: missing_invoke,
    unlock: missing_unlock,
};

#[cfg(target_os = "none")]
unsafe fn locked_callback_predicate_target(object: *mut u32) -> bool {
    let lock = object.add(4).cast::<CountedMutex>();
    mutex_lock_counted(lock);
    let target = *object.add(1) as usize;
    let vtable = *(target as *const u32) as usize;
    let callback: unsafe extern "C" fn(*mut u8) -> i32 =
        core::mem::transmute(*((vtable + 0x18) as *const u32) as usize);
    let result = callback(target as *mut u8);
    mutex_unlock_counted(lock);
    result != 0
}

/// `locked_callback_predicate` — original: `FUN_0814decc` @ `0x0814decc`
/// (60 bytes; five direct unconditional `bl` callers, zero predicated).
///
/// `object` is a target-width word-addressed object: word 1 is the callback
/// target and word 4 begins its [`CountedMutex`]. Neither pointer is checked,
/// matching the stock `ldr` sequence. The callback receives its target in r0;
/// any nonzero return value becomes `true`.
///
/// Deliberate deviation: the host operation seam preserves call ordering and
/// result normalization without treating 64-bit host pointers as firmware
/// words.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn locked_callback_predicate(object: *mut u32) -> bool {
    #[cfg(target_os = "none")]
    { locked_callback_predicate_target(object) }

    #[cfg(not(target_os = "none"))]
    {
        let target = *object.add(1);
        let lock = *object.add(4);
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(LOCKED_CALLBACK_PREDICATE_OPS));
        (ops.lock)(lock);
        let result = (ops.invoke)(target);
        (ops.unlock)(lock);
        result != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u32; 3] = [0; 3];
    static mut RESULT: i32 = 0;

    unsafe extern "C" fn lock(lock: u32) { EVENTS[0] = lock; }
    unsafe extern "C" fn invoke(target: u32) -> i32 { EVENTS[1] = target; RESULT }
    unsafe extern "C" fn unlock(lock: u32) { EVENTS[2] = lock; }

    #[test]
    fn holds_the_word_four_lock_across_callback_and_normalizes_results() {
        let _guard = TEST_LOCK.lock();
        let mut object = [0u32; 7];
        object[1] = 0x1234_5678;
        object[4] = 0x8765_4321;
        unsafe {
            LOCKED_CALLBACK_PREDICATE_OPS = LockedCallbackPredicateOps { lock, invoke, unlock };
            EVENTS = [0; 3];
            RESULT = -7;
            assert!(locked_callback_predicate(object.as_mut_ptr()));
            assert_eq!(EVENTS, [0x8765_4321, 0x1234_5678, 0x8765_4321]);
            RESULT = 0;
            EVENTS = [0; 3];
            assert!(!locked_callback_predicate(object.as_mut_ptr()));
            assert_eq!(EVENTS, [0x8765_4321, 0x1234_5678, 0x8765_4321]);
        }
    }
}
