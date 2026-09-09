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
//! `mutex_handoff_unlock` — original: `FUN_081fca40` @ **0x081fca40**
//! (**8 bytes**, `ldr r0,[r0,#12]; b mutex_unlock`). Thirteen direct callers
//! use unconditional `bl`: 0x08208218, 0x08208380, 0x082084bc, 0x08208564,
//! 0x08208590, 0x08208608, 0x08214634, 0x082147dc, 0x08214a78, 0x08214b3c,
//! 0x08214bac, 0x08214dd4, and 0x08214ea4. Four unconditional direct `b`
//! tail callers are 0x082083d8, 0x0820847c, 0x082149d8, and 0x08214b04.
//! Raw ARM B/BL scanning finds no predicated forms and no aligned image data
//! word equal to the entry address.
//!
//! `mutex_handoff_lock` first acquires the embedded mutex at +0x04. It then
//! reads the selected mutex pointer at +0x0c. If it is the embedded mutex,
//! that acquire remains held. Otherwise it acquires the selected mutex before
//! releasing the embedded one, atomically handing the caller from bootstrap
//! protection to the selected lock. `mutex_handoff_unlock` releases the
//! selected mutex at +0x0c without a pointer guard; its selected pointer must
//! name a valid [`Mutex`].
//!
//! Deliberate deviation: the stock bodies directly branch to the canonical
//! kernel mutex ports. These ports call the already-ported functions directly,
//! so target code may inline their ROM-dispatch guards rather than retain the
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
/// call sites, binary-verified). Acquires the bootstrap mutex at +0x04, then
/// retains it for an embedded selection or hands off to the selected +0x0c
/// mutex before releasing bootstrap protection.
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

/// Releases the mutex currently selected by `handoff`.
///
/// Original: `FUN_081fca40` @ 0x081fca40 (8 bytes; 13 unconditional `bl`
/// call sites, four unconditional direct `b` tail callers, no predicated
/// forms or data dispatch). Loads `current_mutex` at +0x0c, then tail-branches
/// to `mutex_unlock`; neither function guards a NULL mutex pointer.

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mutex_handoff_unlock(handoff: *mut MutexHandoff) {
    mutex_unlock((*handoff).current_mutex);
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

    #[test]
    fn unlock_releases_the_selected_mutex_not_the_bootstrap_mutex() {
        let _guard = ROM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = unsafe { core::ptr::addr_of!(ROM_KERNEL).read_volatile() };
        let patched = RomKernelOps { sema_signal: record_signal, ..saved };
        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(patched) };
        EVENT_COUNT.store(0, Ordering::SeqCst);

        let mut bootstrap_handle = 0x44;
        let mut selected_handle = 0x55;
        let mut selected = mutex(&mut selected_handle);
        let mut handoff = MutexHandoff {
            opaque: 0,
            bootstrap_mutex: mutex(&mut bootstrap_handle),
            current_mutex: &mut selected,
        };

        unsafe { mutex_handoff_unlock(&mut handoff) };
        assert_eq!(EVENT_COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(EVENTS[0].load(Ordering::SeqCst), 0x8000_0055);

        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(saved) };
    }

    #[test]
    fn unlock_skips_selected_mutex_without_a_semaphore_cell() {
        let _guard = ROM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = unsafe { core::ptr::addr_of!(ROM_KERNEL).read_volatile() };
        let patched = RomKernelOps { sema_signal: record_signal, ..saved };
        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(patched) };
        EVENT_COUNT.store(0, Ordering::SeqCst);

        let mut bootstrap_handle = 0x66;
        let mut selected = mutex(core::ptr::null_mut());
        let mut handoff = MutexHandoff {
            opaque: 0,
            bootstrap_mutex: mutex(&mut bootstrap_handle),
            current_mutex: &mut selected,
        };

        unsafe { mutex_handoff_unlock(&mut handoff) };
        assert_eq!(EVENT_COUNT.load(Ordering::SeqCst), 0);

        unsafe { core::ptr::addr_of_mut!(ROM_KERNEL).write_volatile(saved) };
    }
}
