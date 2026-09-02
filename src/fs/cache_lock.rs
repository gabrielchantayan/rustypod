//! Filesystem/disk cache lock acquire and release.
//!
//! The cache subsystem's lock is a kernel semaphore whose id lives in the
//! single BSS word at `0x08a096f8` (the only two literal references to that
//! address in osos are the wait/signal thunk pair at `0x082d7924` and
//! `0x082d7944`; the word is BSS, so its initial value is supplied outside
//! the decrypted image). This module ports both halves: `cache_lock_wait`
//! acquires the id through the rom_sem_wait veneer and `cache_lock_signal`
//! releases it through the rom_sem_signal veneer.

use crate::kernel::task_lock;

const CACHE_LOCK_SEM_ID: *const u32 = 0x08a0_96f8 as *const u32;

/// Host model of the firmware BSS word. Device builds access the original
/// writable word at `CACHE_LOCK_SEM_ID` instead.
#[cfg(not(target_os = "none"))]
static mut HOST_CACHE_LOCK_SEM_ID: u32 = 0;

#[inline(always)]
unsafe fn cache_lock_semaphore_id() -> u32 {
    #[cfg(target_os = "none")]
    {
        CACHE_LOCK_SEM_ID.read_volatile()
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of!(HOST_CACHE_LOCK_SEM_ID).read_volatile()
    }
}

/// cache_lock_wait — original: `FUN_082d7924` @ `0x082d7924` (12 bytes,
/// plus the 4-byte BSS-address literal at `0x082d7930`; the next separately
/// entered function is the ATA-table wait sibling at `0x082d7934`, so
/// Ghidra's 12-byte code extent is exact).
///
/// ```text
/// 082d7924:  ldr r0, [0x82d7930]   ; r0 = 0x08a096f8
/// 082d7928:  ldr r0, [r0, #0x0]    ; r0 = cache lock semaphore id
/// 082d792c:  b   0x08037e08        ; rom_sem_wait veneer -> ROM 0x22003fd0
/// ```
///
/// Loads the cache lock's kernel semaphore id from the BSS word at
/// `0x08a096f8`, then tail-branches to the ROM semaphore wait veneer @
/// `0x08037e08` (`0x22003fd0`), whose r0 result word passes back through
/// the tail branch. The load is intentionally unguarded.
///
/// Call sites: 23 branch references, verified by decoding every ARM B/BL
/// word in osos.dec for every condition code: all 23 are unconditional
/// `bl`, zero predicated forms, zero tail `b` — callers never flag-gate
/// the acquire. No data word in osos references `0x082d7924` — the thunk
/// is never dispatched virtually. Callers are the fs/disk cache family:
/// cache_entry_release @ 0x082e18bc brackets its refcount/owner mutation
/// with this acquire and the ported signal half @ `0x082d7944`
/// (cache_lock_signal); the rest sit in the cache descriptor family
/// 0x082dfe18..0x082e48d8 and the disk cache code @ 0x082b1974.
///
/// Deviation: dispatches through the ported rom_sem_wait (the ROM_KERNEL
/// hook) instead of branching to the 8-byte ROM veneer — the ata_semaphore
/// family pattern, so match.py shows the expected structural diff (indirect
/// call through the hook slot); the original tail-branch becomes a call
/// whose r0 result is returned verbatim.
///
/// Device builds read the original BSS word directly. Host builds use the
/// private word above so tests can exercise the load without mapping the
/// firmware address.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cache_lock_wait() -> usize {
    task_lock::rom_sem_wait(cache_lock_semaphore_id() as usize)
}

/// cache_lock_signal — original: `FUN_082d7944` @ `0x082d7944` (12 bytes,
/// plus the 4-byte BSS-address literal at `0x082d7950`; the next separately
/// entered function is the ATA-table sibling at `0x082d7954`, so Ghidra's
/// 12-byte code extent is exact).
///
/// ```text
/// 082d7944:  ldr r0, [0x82d7950]   ; r0 = 0x08a096f8
/// 082d7948:  ldr r0, [r0, #0x0]    ; r0 = cache lock semaphore id
/// 082d794c:  b   0x08037e10        ; rom_sem_signal veneer -> ROM 0x220042b4
/// ```
///
/// Loads the cache lock's kernel semaphore id from the BSS word at
/// `0x08a096f8`, then tail-branches to the ROM semaphore signal veneer @
/// `0x08037e10` (`0x220042b4`), whose r0 result word passes back through the
/// tail branch. The load is intentionally unguarded.
///
/// Call sites: 28 branch references, verified by decoding every ARM B/BL
/// word in osos.dec (Ghidra reports only the 24 `bl` forms): 24
/// unconditional `bl`, 3 unconditional tail `b` (0x082e1800, 0x082e18f4,
/// 0x082e2ee8) and 1 conditional tail `bne` @
/// 0x082e1988 — that one site flag-gates the release on a compare. No data
/// word in osos references `0x082d7944` — the thunk is never dispatched
/// virtually. Callers are the fs/disk cache family: cache_entry_release @
/// 0x082e18bc brackets its refcount/owner mutation with this release and
/// the ported wait sibling @ `0x082d7924` (cache_lock_wait; same global,
/// rom_sem_wait veneer); the rest sit in the cache descriptor family 0x082dfe68..0x082e2fc8
/// and the disk cache code @ 0x082b1994/9c.
///
/// Deviation: dispatches through the ported rom_sem_signal (the ROM_KERNEL
/// hook) instead of branching to the 8-byte ROM veneer — the ata_semaphore
/// family pattern, so match.py shows the expected structural diff (indirect
/// call through the hook slot); the original tail-branch becomes a call
/// whose r0 result is returned verbatim.
///
/// Device builds read the original BSS word directly. Host builds use the
/// private word above so tests can exercise the load without mapping the
/// firmware address.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cache_lock_signal() -> usize {
    task_lock::rom_sem_signal(cache_lock_semaphore_id() as usize)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::task_lock::{tests::OPS_LOCK, RomThunkOps, ROM_KERNEL};
    use core::ptr::{addr_of, addr_of_mut};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::MutexGuard;

    static LAST_WAIT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static WAIT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static LAST_SIGNAL: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SIGNAL_COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_wait(sem: usize) -> usize {
        LAST_WAIT.store(sem, Ordering::SeqCst);
        WAIT_COUNT.fetch_add(1, Ordering::SeqCst);
        0xdead_beef
    }

    unsafe extern "C" fn record_signal(sem: usize) -> usize {
        LAST_SIGNAL.store(sem, Ordering::SeqCst);
        SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
        0xfeed_cafe
    }

    fn install() -> (MutexGuard<'static, ()>, RomThunkOps, u32) {
        let rom_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved_rom = addr_of!(ROM_KERNEL).read_volatile();
            let saved_id = addr_of!(HOST_CACHE_LOCK_SEM_ID).read_volatile();
            let mut patched = saved_rom;
            patched.rom_sem_wait = record_wait;
            patched.rom_sem_signal = record_signal;
            addr_of_mut!(ROM_KERNEL).write_volatile(patched);
            (rom_guard, saved_rom, saved_id)
        }
    }

    fn restore(state: (MutexGuard<'static, ()>, RomThunkOps, u32)) {
        unsafe {
            addr_of_mut!(ROM_KERNEL).write_volatile(state.1);
            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(state.2);
        }
        drop(state);
    }

    #[test]
    fn wait_loads_bss_id_and_returns_rom_result() {
        let state = install();
        unsafe {
            LAST_WAIT.store(usize::MAX, Ordering::SeqCst);
            WAIT_COUNT.store(0, Ordering::SeqCst);

            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(0x2a);
            assert_eq!(cache_lock_wait(), 0xdead_beef);
            assert_eq!(LAST_WAIT.load(Ordering::SeqCst), 0x2a);

            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(0xffff_ffff);
            assert_eq!(cache_lock_wait(), 0xdead_beef);
            assert_eq!(LAST_WAIT.load(Ordering::SeqCst), 0xffff_ffff);
            assert_eq!(WAIT_COUNT.load(Ordering::SeqCst), 2);
        }
        restore(state);
    }

    #[test]
    fn wait_rereads_id_every_call() {
        let state = install();
        unsafe {
            WAIT_COUNT.store(0, Ordering::SeqCst);
            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(1);
            cache_lock_wait();
            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(2);
            cache_lock_wait();
            assert_eq!(LAST_WAIT.load(Ordering::SeqCst), 2);
            assert_eq!(WAIT_COUNT.load(Ordering::SeqCst), 2);
        }
        restore(state);
    }

    #[test]
    fn wait_does_not_touch_signal_hook() {
        let state = install();
        unsafe {
            SIGNAL_COUNT.store(0, Ordering::SeqCst);
            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(7);
            cache_lock_wait();
            assert_eq!(SIGNAL_COUNT.load(Ordering::SeqCst), 0);
        }
        restore(state);
    }

    #[test]
    fn signal_loads_bss_id_and_returns_rom_result() {
        let state = install();
        unsafe {
            LAST_SIGNAL.store(usize::MAX, Ordering::SeqCst);
            SIGNAL_COUNT.store(0, Ordering::SeqCst);

            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(0x2a);
            assert_eq!(cache_lock_signal(), 0xfeed_cafe);
            assert_eq!(LAST_SIGNAL.load(Ordering::SeqCst), 0x2a);

            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(0xffff_ffff);
            assert_eq!(cache_lock_signal(), 0xfeed_cafe);
            assert_eq!(LAST_SIGNAL.load(Ordering::SeqCst), 0xffff_ffff);
            assert_eq!(SIGNAL_COUNT.load(Ordering::SeqCst), 2);
        }
        restore(state);
    }

    #[test]
    fn signal_rereads_id_every_call() {
        let state = install();
        unsafe {
            SIGNAL_COUNT.store(0, Ordering::SeqCst);
            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(1);
            cache_lock_signal();
            addr_of_mut!(HOST_CACHE_LOCK_SEM_ID).write_volatile(2);
            cache_lock_signal();
            assert_eq!(LAST_SIGNAL.load(Ordering::SeqCst), 2);
            assert_eq!(SIGNAL_COUNT.load(Ordering::SeqCst), 2);
        }
        restore(state);
    }
}
