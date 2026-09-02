//! ATA controller semaphore lookup and release.
//!
//! The firmware's eight-word, writable semaphore-id table is at
//! `0x08adb66c..0x08adb68c`, immediately before the ATA error-record pool.
//! The table has only two literal references in osos: the wait/signal lookup
//! siblings at `0x082d7934` and `0x082d7954`. It is BSS, so its initial values
//! are supplied outside the decrypted image.

use crate::kernel::task_lock;

const ATA_SEMAPHORE_TABLE: *const u32 = 0x08ad_b66c as *const u32;

/// Host model of the firmware BSS table. Device builds access the original
/// writable table at `ATA_SEMAPHORE_TABLE` instead.
#[cfg(not(target_os = "none"))]
static mut HOST_ATA_SEMAPHORE_IDS: [u32; 8] = [0; 8];

#[inline(always)]
unsafe fn ata_semaphore_id(index: usize) -> u32 {
    #[cfg(target_os = "none")]
    {
        ATA_SEMAPHORE_TABLE.add(index).read_volatile()
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of!(HOST_ATA_SEMAPHORE_IDS).cast::<u32>().add(index).read_volatile()
    }
}

/// ata_semaphore_wait — original: `FUN_082d7934` @ `0x082d7934` (12 bytes).
///
/// Loads the kernel semaphore id from the ATA controller's eight-word BSS
/// table at `0x08adb66c[index]`, then tail-branches to the ROM semaphore
/// wait veneer @ `0x08037e08` (`0x22003fd0`), whose result word passes back
/// through the tail branch. The table access and wait are intentionally
/// unguarded: callers load `index` from their controller object's halfword
/// at `+0x78`; all 22 `bl` sites are unconditional, with zero predicated
/// forms, zero tail `b` sites and no data word in osos referencing this
/// entry — it is never dispatched virtually.
///
/// Device builds read the original BSS table directly. Host builds use the
/// private table above so tests can exercise the lookup without mapping the
/// firmware address; both retain the original unchecked word-index access.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_semaphore_wait(index: usize) -> usize {
    task_lock::rom_sem_wait(ata_semaphore_id(index) as usize)
}

/// ata_semaphore_signal — original: `FUN_082d7954` @ `0x082d7954` (12 bytes).
///
/// Loads the kernel semaphore id from the ATA controller's eight-word BSS
/// table at `0x08adb66c[index]`, then tail-branches to the ROM semaphore
/// signal veneer @ `0x08037e10` (`0x220042b4`). The table access and signal
/// are intentionally unguarded: callers load `index` from their controller
/// object's halfword at `+0x78`; all 27 `bl` sites are unconditional, and
/// the one additional unconditional tail `b` site returns the ROM result to
/// its caller. No predicated branches target this entry.
///
/// Device builds read the original BSS table directly. Host builds use the
/// private table above so tests can exercise the lookup without mapping the
/// firmware address; both retain the original unchecked word-index access.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ata_semaphore_signal(index: usize) -> usize {
    task_lock::rom_sem_signal(ata_semaphore_id(index) as usize)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::task_lock::{tests::OPS_LOCK, RomThunkOps, ROM_KERNEL};
    use core::ptr::{addr_of, addr_of_mut};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static TABLE_LOCK: Mutex<()> = Mutex::new(());
    static LAST_SIGNAL: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SIGNAL_COUNT: AtomicUsize = AtomicUsize::new(0);
    static LAST_WAIT: AtomicUsize = AtomicUsize::new(usize::MAX);
    static WAIT_COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_signal(sem: usize) -> usize {
        LAST_SIGNAL.store(sem, Ordering::SeqCst);
        SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
        0xfeed_cafe
    }

    unsafe extern "C" fn record_wait(sem: usize) -> usize {
        LAST_WAIT.store(sem, Ordering::SeqCst);
        WAIT_COUNT.fetch_add(1, Ordering::SeqCst);
        0x0bad_f00d
    }

    fn install() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, RomThunkOps, [u32; 8]) {
        let table_guard = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let rom_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved_rom = addr_of!(ROM_KERNEL).read_volatile();
            let saved_table = addr_of!(HOST_ATA_SEMAPHORE_IDS).read_volatile();
            let mut patched = saved_rom;
            patched.rom_sem_signal = record_signal;
            patched.rom_sem_wait = record_wait;
            addr_of_mut!(ROM_KERNEL).write_volatile(patched);
            (table_guard, rom_guard, saved_rom, saved_table)
        }
    }

    fn restore(state: (MutexGuard<'static, ()>, MutexGuard<'static, ()>, RomThunkOps, [u32; 8])) {
        unsafe {
            addr_of_mut!(ROM_KERNEL).write_volatile(state.2);
            addr_of_mut!(HOST_ATA_SEMAPHORE_IDS).write_volatile(state.3);
        }
        drop(state);
    }

    #[test]
    fn signal_uses_each_table_word_and_returns_rom_result() {
        let state = install();
        unsafe {
            addr_of_mut!(HOST_ATA_SEMAPHORE_IDS).write_volatile([
                0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
            ]);
            LAST_SIGNAL.store(usize::MAX, Ordering::SeqCst);
            SIGNAL_COUNT.store(0, Ordering::SeqCst);

            assert_eq!(ata_semaphore_signal(0), 0xfeed_cafe);
            assert_eq!(LAST_SIGNAL.load(Ordering::SeqCst), 0x10);
            assert_eq!(ata_semaphore_signal(7), 0xfeed_cafe);
            assert_eq!(LAST_SIGNAL.load(Ordering::SeqCst), 0x87);
            assert_eq!(SIGNAL_COUNT.load(Ordering::SeqCst), 2);
        }
        restore(state);
    }

    #[test]
    fn wait_uses_each_table_word_and_returns_rom_result() {
        let state = install();
        unsafe {
            addr_of_mut!(HOST_ATA_SEMAPHORE_IDS).write_volatile([
                0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
            ]);
            LAST_WAIT.store(usize::MAX, Ordering::SeqCst);
            WAIT_COUNT.store(0, Ordering::SeqCst);
            SIGNAL_COUNT.store(0, Ordering::SeqCst);

            assert_eq!(ata_semaphore_wait(0), 0x0bad_f00d);
            assert_eq!(LAST_WAIT.load(Ordering::SeqCst), 0x10);
            assert_eq!(ata_semaphore_wait(6), 0x0bad_f00d);
            assert_eq!(LAST_WAIT.load(Ordering::SeqCst), 0x76);
            assert_eq!(ata_semaphore_wait(7), 0x0bad_f00d);
            assert_eq!(LAST_WAIT.load(Ordering::SeqCst), 0x87);
            assert_eq!(WAIT_COUNT.load(Ordering::SeqCst), 3);
            // The wait hook slot must not be confused with the signal slot.
            assert_eq!(SIGNAL_COUNT.load(Ordering::SeqCst), 0);
        }
        restore(state);
    }
}
