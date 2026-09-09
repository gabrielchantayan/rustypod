//! Drive-slot table lookup.
//!
//! The filesystem keeps four drive slots, 508 bytes each, behind the BSS
//! pointer at `0x08a0a724`. The table's first word is a live/refcount word:
//! a slot is usable only when it is nonzero. This module ports the guarded
//! lookup used by the drive-letter and cache-entry families.

use crate::fs::cache_lock;

/// BSS word holding the four drive-slot table's base pointer.
const DRIVE_SLOT_TABLE_PTR: *const u32 = 0x08a0_a724 as *const u32;

/// `FUN_082e4b3c` accepts only drive slots 0 through 3.
const DRIVE_SLOT_CAPACITY: u32 = 4;

/// Slot stride from `rsb r0, r5, r5, lsl #7; add r0, r1, r0, lsl #2`:
/// `index * (128 - 1) * 4`.
const DRIVE_SLOT_STRIDE: usize = 0x1fc;

/// Host model of the firmware BSS word. Device builds access the original
/// writable word at `DRIVE_SLOT_TABLE_PTR` instead.
#[cfg(not(target_os = "none"))]
static mut HOST_DRIVE_SLOT_TABLE_PTR: u32 = 0;

/// Loads the drive-slot table base: the original BSS word on device, the host
/// model word in test builds.
#[inline(always)]
unsafe fn drive_slot_table_base() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        core::ptr::read_volatile(DRIVE_SLOT_TABLE_PTR) as *mut u8
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_DRIVE_SLOT_TABLE_PTR)) as *mut u8
    }
}

/// drive_slot_lookup — original: `FUN_082e06f4` @ `0x082e06f4` (68 code
/// bytes, plus the 4-byte BSS-address literal `0x08a0a724` at `0x082e0738`;
/// the next separately entered function opens `push {r4,r5,r6,lr}` at
/// `0x082e073c`, so Ghidra's 68-byte code extent is exact).
///
/// ```text
/// 082e06f4:  push  {r4, r5, r6, lr}
/// 082e06f8:  mov   r5, r0
/// 082e06fc:  bl    0x082d7924          ; cache_lock_wait
/// 082e0700:  mov   r4, #0
/// 082e0704:  mov   r0, r5
/// 082e0708:  bl    0x082e4b3c          ; index < 4
/// 082e070c:  cmp   r0, #0
/// 082e0710:  ldrne r1, [0x082e0738]    ; r1 = 0x08a0a724
/// 082e0714:  rsbne r0, r5, r5, lsl #7  ; index * 127
/// 082e0718:  ldrne r1, [r1]
/// 082e071c:  addne r0, r1, r0, lsl #2  ; base + index * 508
/// 082e0720:  ldrne r1, [r0]
/// 082e0724:  cmpne r1, #0
/// 082e0728:  movne r4, r0
/// 082e072c:  bl    0x082d7944          ; cache_lock_signal
/// 082e0730:  mov   r0, r4
/// 082e0734:  pop   {r4, r5, r6, pc}
/// ```
///
/// Acquires the fs/disk cache lock, accepts only `index < 4`, and returns
/// `base + index * 508` only when that slot's first word is nonzero; otherwise
/// returns NULL. The table-base and slot-word loads have no NULL guard, and
/// the release runs on every path.
///
/// Call sites: 12 branch references, verified by decoding every ARM B/BL word
/// in osos.dec for every condition code: all 12 are unconditional `bl`
/// (0x081bd38c, 0x081bdb0c, 0x082c3040, 0x082e0628, 0x082e0748,
/// 0x082e14a0, 0x082e15f8, 0x082e1760, 0x082e1ce8, 0x082e23bc,
/// 0x082e2470, 0x082e24a8), zero predicated forms, zero tail `b` — callers
/// never flag-gate the lookup. No data word in osos references `0x082e06f4`,
/// so it is not dispatched virtually.
///
/// Deviation: inlines the 8-byte `index < 4` validator `FUN_082e4b3c` rather
/// than introducing a dispatch seam. The cache lock pair dispatches through
/// ported `cache_lock_wait` / `cache_lock_signal`; host builds read the table
/// base from the private BSS model above.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn drive_slot_lookup(index: u32) -> *mut u8 {
    cache_lock::cache_lock_wait();
    let mut result = core::ptr::null_mut();
    if index < DRIVE_SLOT_CAPACITY {
        let slot = drive_slot_table_base().wrapping_add(index as usize * DRIVE_SLOT_STRIDE);
        if core::ptr::read_volatile(slot as *const u32) != 0 {
            result = slot;
        }
    }
    cache_lock::cache_lock_signal();
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::task_lock::{tests::OPS_LOCK, RomThunkOps, ROM_KERNEL};
    use core::ptr::{addr_of, addr_of_mut};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::MutexGuard;

    const FIXTURE_LEN: usize = DRIVE_SLOT_CAPACITY as usize * DRIVE_SLOT_STRIDE;

    static WAIT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static SIGNAL_COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_wait(_sem: usize) -> usize {
        WAIT_COUNT.fetch_add(1, Ordering::SeqCst);
        0
    }

    unsafe extern "C" fn record_signal(_sem: usize) -> usize {
        SIGNAL_COUNT.fetch_add(1, Ordering::SeqCst);
        0
    }

    struct Fixture {
        _guard: MutexGuard<'static, ()>,
        rom: RomThunkOps,
        table: *mut u8,
    }

    impl Fixture {
        fn new() -> Option<Fixture> {
            let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let table = crate::testing::try_map_u32_slab(
                crate::testing::hints::DRIVE_SLOT_LOOKUP,
                FIXTURE_LEN,
            )?;
            unsafe {
                core::ptr::write_bytes(table, 0, FIXTURE_LEN);
            }
            let rom = unsafe { addr_of!(ROM_KERNEL).read_volatile() };
            unsafe {
                let mut patched = rom;
                patched.rom_sem_wait = record_wait;
                patched.rom_sem_signal = record_signal;
                addr_of_mut!(ROM_KERNEL).write_volatile(patched);
                addr_of_mut!(HOST_DRIVE_SLOT_TABLE_PTR).write_volatile(table as u32);
                WAIT_COUNT.store(0, Ordering::SeqCst);
                SIGNAL_COUNT.store(0, Ordering::SeqCst);
            }
            Some(Fixture {
                _guard: guard,
                rom,
                table,
            })
        }

        fn slot(&self, index: usize) -> *mut u8 {
            unsafe { self.table.add(index * DRIVE_SLOT_STRIDE) }
        }

        fn set_live_word(&self, index: usize, value: u32) {
            unsafe {
                core::ptr::write_volatile(self.slot(index) as *mut u32, value);
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(ROM_KERNEL).write_volatile(self.rom);
                addr_of_mut!(HOST_DRIVE_SLOT_TABLE_PTR).write_volatile(0);
            }
        }
    }

    #[test]
    fn returns_each_live_drive_slot() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/drive_slot"));
            return;
        };
        unsafe {
            for index in 0..DRIVE_SLOT_CAPACITY as usize {
                fx.set_live_word(index, index as u32 + 1);
                assert_eq!(drive_slot_lookup(index as u32), fx.slot(index), "index {index}");
            }
        }
    }

    #[test]
    fn rejects_empty_slots_and_invalid_indexes() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/drive_slot"));
            return;
        };
        unsafe {
            fx.set_live_word(2, 0xffff_ffff);
            assert!(drive_slot_lookup(0).is_null(), "zero first word rejects slot");
            assert_eq!(drive_slot_lookup(2), fx.slot(2));
            assert!(drive_slot_lookup(DRIVE_SLOT_CAPACITY).is_null());
            assert!(drive_slot_lookup(u32::MAX).is_null());
        }
    }

    #[test]
    fn cache_lock_brackets_success_and_all_rejections() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/drive_slot"));
            return;
        };
        unsafe {
            fx.set_live_word(1, 1);
            assert_eq!(drive_slot_lookup(1), fx.slot(1));
            assert!(drive_slot_lookup(0).is_null());
            assert!(drive_slot_lookup(DRIVE_SLOT_CAPACITY).is_null());
            assert_eq!(WAIT_COUNT.load(Ordering::SeqCst), 3);
            assert_eq!(SIGNAL_COUNT.load(Ordering::SeqCst), 3);
        }
    }
}
