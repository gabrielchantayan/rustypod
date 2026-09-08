//! Lock handoff between an embedded bootstrap mutex and a selected mutex.
//!
//! `mutex_handoff_lock` — original: `FUN_081fca10` @ **0x081fca10**
//! (**48 bytes**, 0x081fca10..0x081fca40; the following `ldr r0,[r0,#12]`
//! starts the separately entered unlock helper). Eighteen direct callers,
//! all unconditional `bl`: 0x081fcb78, 0x08208204, 0x0820823c, 0x0820839c,
//! 0x0820845c, 0x08208494, 0x082084f4, 0x08208580, 0x082085ac, 0x08214620,
//! 0x08214658, 0x0821499c, 0x08214a2c, 0x08214ae4, 0x08214b1c, 0x08214b64,
//! 0x08214dc4, and 0x08214e88. Raw ARM B/BL scanning finds no predicated
//! forms, tail `b` callers, or aligned data words equal to the entry address.
//!
//! The function first acquires the embedded mutex at +0x04. It then reads the
//! selected mutex pointer at +0x0c. If it is the embedded mutex, that acquire
//! remains held. Otherwise it acquires the selected mutex before releasing the
//! embedded one, atomically handing the caller from bootstrap protection to
//! the selected lock. The companion at 0x081fca40 releases the selected mutex.
//!
//! Deliberate deviation: the stock body directly `bl`s the canonical kernel
//! mutex ports. This port calls those already-ported functions directly, so
//! target code may inline their ROM-dispatch guards rather than retain the two
//! retail call boundaries.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// The three words addressed by the original handoff helper.
///
/// The target layout is a leading opaque word, an 8-byte [`Mutex`] at +0x04,
/// and the selected mutex pointer at +0x0c. `repr(C)` named fields retain the
/// intended members on 64-bit hosts without unsafe literal byte offsets.
#[repr(C)]
pub struct MutexHandoff {
    pub opaque: u32,
    pub bootstrap_mutex: Mutex,
    pub current_mutex: *mut Mutex,
}

/// Acquires the mutex currently selected by `handoff`.
///
/// Original: `FUN_081fca10` @ 0x081fca10 (48 bytes; 18 unconditional `bl`
/// call sites, binary-verified).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_handoff_lock(handoff: *mut MutexHandoff) {
    let bootstrap = core::ptr::addr_of_mut!((*handoff).bootstrap_mutex);
    mutex_lock(bootstrap);

    let current = (*handoff).current_mutex;
    if current == bootstrap {
        return;
    }

    mutex_lock(current);
    mutex_unlock(bootstrap);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::sync_mutex::{RomKernelOps, ROM_KERNEL};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::Mutex as HostMutex;

    /// Serializes this module's temporary replacement of the global ROM table.
    static ROM_LOCK: HostMutex<()> = HostMutex::new(());
    static EVENT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static EVENTS: [AtomicU32; 3] = [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

    unsafe extern "C" fn record_wait(handle: u32) {
        let slot = EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
        EVENTS[slot].store(handle, Ordering::SeqCst);
    }

    unsafe extern "C" fn record_signal(handle: u32) {
        let slot = EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
        EVENTS[slot].store(handle | 0x8000_0000, Ordering::SeqCst);
    }

    fn mutex(cell: *mut u32) -> Mutex {
        Mutex { sem_cell: cell, unused: 0 }
    }

    fn events() -> [u32; 3] {
        [
            EVENTS[0].load(Ordering::SeqCst),
            EVENTS[1].load(Ordering::SeqCst),
            EVENTS[2].load(Ordering::SeqCst),
        ]
    }

    #[test]
    fn distinct_selected_mutex_is_acquired_before_bootstrap_releases() {
        let _guard = ROM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = unsafe { core::ptr::addr_of!(ROM_KERNEL).read_volatile() };
        let patched = RomKernelOps { sema_wait: record_wait, sema_signal: record_signal, ..saved };
        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(patched) };
        EVENT_COUNT.store(0, Ordering::SeqCst);

        let mut bootstrap_handle = 0x11;
        let mut selected_handle = 0x22;
        let mut handoff = MutexHandoff {
            opaque: 0,
            bootstrap_mutex: mutex(&mut bootstrap_handle),
            current_mutex: core::ptr::null_mut(),
        };
        let mut selected = mutex(&mut selected_handle);
        handoff.current_mutex = &mut selected;

        unsafe { mutex_handoff_lock(&mut handoff) };
        assert_eq!(EVENT_COUNT.load(Ordering::SeqCst), 3);
        assert_eq!(events(), [0x11, 0x22, 0x8000_0011]);

        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(saved) };
    }

    #[test]
    fn embedded_selection_keeps_bootstrap_acquired() {
        let _guard = ROM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = unsafe { core::ptr::addr_of!(ROM_KERNEL).read_volatile() };
        let patched = RomKernelOps { sema_wait: record_wait, sema_signal: record_signal, ..saved };
        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(patched) };
        EVENT_COUNT.store(0, Ordering::SeqCst);

        let mut bootstrap_handle = 0x33;
        let mut handoff = MutexHandoff {
            opaque: 0,
            bootstrap_mutex: mutex(&mut bootstrap_handle),
            current_mutex: core::ptr::null_mut(),
        };
        handoff.current_mutex = core::ptr::addr_of_mut!(handoff.bootstrap_mutex);

        unsafe { mutex_handoff_lock(&mut handoff) };
        assert_eq!(EVENT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(EVENTS[0].load(Ordering::SeqCst), 0x33);

        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(saved) };
    }
}
