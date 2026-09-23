//! Calls a context lifecycle object's vtable slot while holding its guard.
//!
//! `context_lifecycle_slot_0x2c` — original: `FUN_081f0270` @ **0x081f0270**
//! (**80 bytes exactly**, `0x081f0270..0x081f02c0`; the `push {r4-r6,lr}` at
//! `0x081f02c0` starts the next real function). Raw A32 decoding finds three
//! inbound direct plain `bl` calls (`0x0814ac50`, `0x0814af40`, and
//! `0x0814b0a8`) and no predicated inbound BL forms. The body contains two
//! plain direct `bl` instructions (`mutex_lock` @ `0x0807f5c4` and
//! `mutex_unlock` @ `0x0807f6a0`) plus one indirect `blx` through slot `+0x2c`.
//!
//! Algorithm: lock the lifecycle guard at context `+0x50`; if the lifecycle
//! object at `+0x48` is NULL, unlock and return one. Otherwise invoke that
//! object's vtable slot `+0x2c` with the object as `r0`, unlock, and return the
//! slot result.
//!
//! Deliberate deviation: the physical target-width vtable dispatch is retained
//! on device; host builds use a narrow slot seam because host pointers cannot
//! share the firmware's four-byte object fields.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const LIFECYCLE_OBJECT_OFFSET: usize = 0x48;
const LIFECYCLE_GUARD_OFFSET: usize = 0x50;
const LIFECYCLE_SLOT_0X2C: usize = 0x2c / 4;

type ContextLifecycleSlot0x2c = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context_lifecycle_slot_0x2c(_object: *mut u8) -> u32 { 0 }

/// Host seam for the lifecycle object's unresolved vtable slot `+0x2c`.
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_LIFECYCLE_SLOT_0X2C: ContextLifecycleSlot0x2c = missing_context_lifecycle_slot_0x2c;

#[cfg(target_os = "none")]
unsafe fn context_lifecycle_slot_0x2c(context: *mut u8) -> u32 {
    let object = context.add(LIFECYCLE_OBJECT_OFFSET).cast::<u32>().read_volatile() as usize as *mut u8;
    if object.is_null() {
        return 1;
    }
    let vtable = object.cast::<u32>().read_volatile() as usize as *const u32;
    let slot: ContextLifecycleSlot0x2c = core::mem::transmute(vtable.add(LIFECYCLE_SLOT_0X2C).read_volatile() as usize);
    slot(object)
}

/// Invokes a context lifecycle object's slot `+0x2c`, returning one for no object.
///
/// `context` must be valid through its `Mutex` at `+0x50`; retailOS performs no
/// NULL or bounds checks on non-NULL objects or their vtables.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_lifecycle_slot_0x2c")]
pub unsafe extern "C" fn context_lifecycle_slot_0x2c_dispatch(context: *mut u8) -> u32 {
    let guard = context.add(LIFECYCLE_GUARD_OFFSET).cast::<Mutex>();
    mutex_lock(guard);

    #[cfg(target_os = "none")]
    let result = context_lifecycle_slot_0x2c(context);
    #[cfg(not(target_os = "none"))]
    let object = context.add(LIFECYCLE_OBJECT_OFFSET).cast::<usize>().read_unaligned() as *mut u8;
    #[cfg(not(target_os = "none"))]
    let result = if object.is_null() { 1 } else { CONTEXT_LIFECYCLE_SLOT_0X2C(object) };

    mutex_unlock(guard);
    result
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as StdMutex;

    static TEST_LOCK: StdMutex<()> = StdMutex::new(());
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static mut RESULT: u32 = 0;
    static mut SEEN_CONTEXT: usize = 0;

    unsafe extern "C" fn record_slot(context: *mut u8) -> u32 {
        CALLS.fetch_add(1, Ordering::SeqCst);
        SEEN_CONTEXT = context as usize;
        RESULT
    }

    unsafe fn install_slot(result: u32) {
        CALLS.store(0, Ordering::SeqCst);
        RESULT = result;
        SEEN_CONTEXT = 0;
        CONTEXT_LIFECYCLE_SLOT_0X2C = record_slot;
    }

    #[test]
    fn forwards_the_slot_result_after_calling_the_lifecycle_object_slot() {
        let _test_lock = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut context = [0u8; LIFECYCLE_GUARD_OFFSET + core::mem::size_of::<Mutex>()];
        let mut object = 0u8;
        unsafe {
            install_slot(0x9a_bc_de_f0);
            context.as_mut_ptr().add(LIFECYCLE_OBJECT_OFFSET).cast::<usize>().write_unaligned((&mut object as *mut u8) as usize);
        }

        assert_eq!(unsafe { context_lifecycle_slot_0x2c_dispatch(context.as_mut_ptr()) }, 0x9a_bc_de_f0);
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(unsafe { SEEN_CONTEXT }, (&mut object as *mut u8) as usize);
    }

    #[test]
    fn absent_lifecycle_object_returns_one_without_calling_the_slot() {
        let _test_lock = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut context = [0u8; LIFECYCLE_GUARD_OFFSET + core::mem::size_of::<Mutex>()];
        unsafe { install_slot(0); }

        assert_eq!(unsafe { context_lifecycle_slot_0x2c_dispatch(context.as_mut_ptr()) }, 1);
        assert_eq!(CALLS.load(Ordering::SeqCst), 0);
    }
}
