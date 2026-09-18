//! Reset an opaque state record while holding its mutex handoff.
//!
//! Original: `FUN_08208578` @ **0x08208578** (36 bytes,
//! 0x08208578..0x0820859c). Raw ARM is `push {r4,lr}; mov r4,r0; bl
//! mutex_handoff_lock; mov r0,r4; bl 0x0820840c; mov r0,r4; bl
//! mutex_handoff_unlock; mov r0,#1; pop {r4,pc}`. It has four plain,
//! unconditional inbound `bl` call sites and no predicated inbound `bl` calls.
//!
//! The wrapper retains the mutex handoff across the opaque reset and returns
//! one. `0x0820840c` clears and replaces private state through still-unported
//! helpers, so its identity is not inferred; device builds call that verified
//! retail entry directly, while host builds expose a replacement seam.
//!
//! Deliberate deviation: the retail reset body remains a fixed-address seam
//! rather than duplicating its unported private-state operations.

use crate::kernel::mutex_handoff::{mutex_handoff_lock, mutex_handoff_unlock, MutexHandoff};

type GuardedReset = unsafe extern "C" fn(*mut MutexHandoff);

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn retail_guarded_reset() -> GuardedReset {
    core::mem::transmute(0x0820_840cusize)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_guarded_reset(_handoff: *mut MutexHandoff) {}

#[cfg(not(target_arch = "arm"))]
static mut GUARDED_RESET: GuardedReset = missing_guarded_reset;

#[inline(always)]
unsafe fn guarded_reset() -> GuardedReset {
    #[cfg(target_arch = "arm")]
    { retail_guarded_reset() }
    #[cfg(not(target_arch = "arm"))]
    { core::ptr::addr_of!(GUARDED_RESET).read_volatile() }
}

/// Locks `handoff`, resets its private state, unlocks it, and returns one.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_handoff_guarded_reset(handoff: *mut MutexHandoff) -> u32 {
    mutex_handoff_lock(handoff);
    guarded_reset()(handoff);
    mutex_handoff_unlock(handoff);
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::sync_mutex::Mutex;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex as HostMutex;

    static SEAM_LOCK: HostMutex<()> = HostMutex::new(());
    static RESET_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RESET_ARGUMENT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_reset(handoff: *mut MutexHandoff) {
        RESET_ARGUMENT.store(handoff as usize, Ordering::SeqCst);
        RESET_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    fn mutex(cell: *mut u32) -> Mutex {
        Mutex { sem_cell: cell, unused: 0 }
    }

    #[test]
    fn resets_once_for_embedded_and_distinct_mutex_selection() {
        let _guard = SEAM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = unsafe { core::ptr::addr_of!(GUARDED_RESET).read_volatile() };
        unsafe { core::ptr::addr_of_mut!(GUARDED_RESET).write_volatile(record_reset) };
        RESET_CALLS.store(0, Ordering::SeqCst);

        let mut bootstrap_cell = 1;
        let mut selected_cell = 2;
        let mut handoff = MutexHandoff {
            opaque: 0,
            bootstrap_mutex: mutex(&mut bootstrap_cell),
            current_mutex: core::ptr::null_mut(),
        };
        handoff.current_mutex = core::ptr::addr_of_mut!(handoff.bootstrap_mutex);
        assert_eq!(unsafe { mutex_handoff_guarded_reset(&mut handoff) }, 1);
        assert_eq!(RESET_ARGUMENT.load(Ordering::SeqCst), (&mut handoff as *mut MutexHandoff) as usize);

        let mut selected = mutex(&mut selected_cell);
        handoff.current_mutex = &mut selected;
        assert_eq!(unsafe { mutex_handoff_guarded_reset(&mut handoff) }, 1);
        assert_eq!(RESET_CALLS.load(Ordering::SeqCst), 2);

        unsafe { core::ptr::addr_of_mut!(GUARDED_RESET).write_volatile(saved) };
    }
}
