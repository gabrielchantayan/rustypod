//! Mounted-volume table slot lookup.
//!
//! The filesystem keeps a fixed table of 64 volume descriptors, 36 bytes
//! each, whose base pointer lives in the BSS word at `0x08a0a72c` (only
//! four literal references in osos: the slot-destroy scan @ `0x082e0094`,
//! the disk-cache code @ `0x082b1710`, the descriptor family @
//! `0x082db600`, and this lookup). The immediately following sibling @
//! `0x082e377c` parses `"X:"` drive-letter prefixes through toupper @
//! `0x082e0180` and accepts only letters mapping to slots 0..3 (`index <
//! 4` check @ `0x082e4b3c`), which identifies the table as the
//! mounted-volume registry. This module ports the table's index accessor:
//! under the fs/disk cache lock it returns the descriptor for `index`,
//! rejecting out-of-range indices, slots flagged at word +0x18, and —
//! when a nonzero mask is given — slots whose +0x04 flags share no bit
//! with the mask.

use crate::fs::cache_lock;

/// BSS word holding the volume descriptor table base.
const VOLUME_TABLE_PTR: *const u32 = 0x08a0_a72c as *const u32;

/// Slot count returned by the original capacity getter (`FUN_082e3774` @
/// `0x082e3774`, 8 bytes: `mov r0, #64; bx lr`).
const VOLUME_TABLE_CAPACITY: i32 = 64;

/// Descriptor stride in bytes (`add r0, r4, r4, lsl #3` then `lsl #2`:
/// index * 9 * 4).
const DESCRIPTOR_STRIDE: usize = 36;

/// Host model of the firmware BSS word. Device builds access the original
/// writable word at `VOLUME_TABLE_PTR` instead.
#[cfg(not(target_os = "none"))]
static mut HOST_VOLUME_TABLE_PTR: u32 = 0;

/// Loads the table base pointer: the original BSS word on device, the
/// host model word in test builds.
#[inline(always)]
unsafe fn volume_table_base() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        core::ptr::read_volatile(VOLUME_TABLE_PTR) as *mut u8
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_VOLUME_TABLE_PTR)) as *mut u8
    }
}

/// volume_table_lookup — original: `FUN_082e0e1c` @ `0x082e0e1c` (108
/// bytes, plus the 4-byte BSS-address literal `0x08a0a72c` at
/// `0x082e0e88`; the next separately entered function opens `push
/// {r4,r5,r6,r7,r8,lr}` at `0x082e0e8c`, so Ghidra's 108-byte extent is
/// exact).
///
/// ```text
/// 082e0e1c:  push {r4, r5, r6, lr}
/// 082e0e20:  mov  r5, r1            ; r5 = flags mask
/// 082e0e24:  mov  r4, r0            ; r4 = index (signed)
/// 082e0e28:  bl   0x082d7924        ; cache_lock_wait
/// 082e0e2c:  cmp  r4, #0
/// 082e0e30:  mov  r6, #0
/// 082e0e34:  blt  0x082e0e7c        ; index < 0 -> NULL
/// 082e0e38:  bl   0x082e3774        ; capacity getter -> 64
/// 082e0e3c:  cmp  r0, r4
/// 082e0e40:  blt  0x082e0e7c        ; 64 < index -> NULL
/// 082e0e44:  ldr  r1, [0x082e0e88]  ; r1 = 0x08a0a72c
/// 082e0e48:  add  r0, r4, r4, lsl #3
/// 082e0e4c:  ldr  r1, [r1]          ; r1 = table base
/// 082e0e50:  adds r0, r1, r0, lsl #2 ; entry = base + index*36
/// 082e0e54:  beq  0x082e0e7c        ; entry == NULL -> NULL
/// 082e0e58:  ldr  r1, [r0, #24]
/// 082e0e5c:  cmp  r1, #0
/// 082e0e60:  bne  0x082e0e7c        ; word +0x18 set -> NULL
/// 082e0e64:  cmp  r5, #0
/// 082e0e68:  beq  0x082e0e78        ; no mask -> accept
/// 082e0e6c:  ldrh r1, [r0, #4]
/// 082e0e70:  tst  r1, r5
/// 082e0e74:  beq  0x082e0e7c        ; no shared flag bit -> NULL
/// 082e0e78:  mov  r6, r0
/// 082e0e7c:  bl   0x082d7944        ; cache_lock_signal
/// 082e0e80:  mov  r0, r6
/// 082e0e84:  pop  {r4, r5, r6, pc}
/// ```
///
/// Acquires the fs/disk cache lock, then returns `base + index*36` when
/// `0 <= index <= 64`, the slot's word at +0x18 is clear, and either
/// `flags` is zero or the slot's u16 flags at +0x04 share at least one
/// bit with `flags`; returns NULL otherwise. The lock release runs on
/// every path, including every rejection.
///
/// Bounds note: the comparison is `capacity < index -> fail`, so `index
/// == 64` is ACCEPTED even though both table iterators (the slot-destroy
/// scan @ `0x082e0094` and the walker `FUN_082e0b34` @ `0x082e0b34`) loop
/// strictly below 64 — the original admits one slot past the table. Ported
/// faithfully.
///
/// Call sites: 12 branch references, verified by decoding every ARM B/BL
/// word in osos.dec for every condition code: all 12 are unconditional
/// `bl` (0x081bd694, 0x082b194c, 0x082b1c2c, 0x082e0b54, 0x082e193c,
/// 0x082e19fc, 0x082e5de0, 0x082e5e90, 0x082e6240, 0x082e62a4,
/// 0x082e636c, 0x082e660c), zero predicated forms, zero tail `b` —
/// callers never flag-gate the lookup. No data word in osos references
/// `0x082e0e1c` — it is never dispatched virtually.
///
/// Deviations: the capacity getter `FUN_082e3774` (an 8-byte `return 64`)
/// is the constant `VOLUME_TABLE_CAPACITY` instead of a `bl`; the lock
/// pair dispatches through the ported `cache_lock_wait` /
/// `cache_lock_signal`. Host builds read the table base from the private
/// model word so tests exercise the lookup without mapping the firmware
/// BSS address.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_table_lookup(index: i32, flags: u32) -> *mut u8 {
    cache_lock::cache_lock_wait();
    let mut result = core::ptr::null_mut();
    if index >= 0 && VOLUME_TABLE_CAPACITY >= index {
        let entry = volume_table_base().wrapping_add(index as usize * DESCRIPTOR_STRIDE);
        if !entry.is_null() {
            let flagged = core::ptr::read_volatile(entry.add(0x18) as *const u32) != 0;
            let masked = flags != 0
                && (u32::from(core::ptr::read_volatile(entry.add(4) as *const u16)) & flags) == 0;
            if !flagged && !masked {
                result = entry;
            }
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

    /// Table size in the fixture: capacity plus one slot, so the
    /// original's `index == 64` acceptance can be observed without
    /// running off the mapping.
    const FIXTURE_SLOTS: usize = 65;
    const FIXTURE_LEN: usize = FIXTURE_SLOTS * DESCRIPTOR_STRIDE;

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
                crate::testing::hints::VOLUME_TABLE_LOOKUP,
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
                addr_of_mut!(HOST_VOLUME_TABLE_PTR).write_volatile(table as u32);
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
            unsafe { self.table.add(index * DESCRIPTOR_STRIDE) }
        }

        fn set_flags(&self, index: usize, flags: u16) {
            unsafe {
                core::ptr::write_volatile(self.slot(index).add(4) as *mut u16, flags);
            }
        }

        fn set_word_18(&self, index: usize, value: u32) {
            unsafe {
                core::ptr::write_volatile(self.slot(index).add(0x18) as *mut u32, value);
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(ROM_KERNEL).write_volatile(self.rom);
                addr_of_mut!(HOST_VOLUME_TABLE_PTR).write_volatile(0);
            }
        }
    }

    #[test]
    fn returns_slot_pointer_for_plain_index() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/volume_table"));
            return;
        };
        unsafe {
            for index in [0i32, 1, 3, 32, 63] {
                let got = volume_table_lookup(index, 0);
                assert_eq!(got, fx.slot(index as usize), "index {index}");
            }
        }
    }

    #[test]
    fn bracket_runs_on_every_path() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/volume_table"));
            return;
        };
        unsafe {
            fx.set_word_18(5, 1);
            assert!(!volume_table_lookup(0, 0).is_null());
            assert!(volume_table_lookup(-1, 0).is_null());
            assert!(volume_table_lookup(65, 0).is_null());
            assert!(volume_table_lookup(5, 0).is_null());
            assert_eq!(WAIT_COUNT.load(Ordering::SeqCst), 4);
            assert_eq!(SIGNAL_COUNT.load(Ordering::SeqCst), 4);
        }
    }

    #[test]
    fn rejects_negative_and_past_capacity() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/volume_table"));
            return;
        };
        unsafe {
            assert!(volume_table_lookup(-1, 0).is_null());
            assert!(volume_table_lookup(i32::MIN, 0).is_null());
            assert!(volume_table_lookup(65, 0).is_null());
            assert!(volume_table_lookup(i32::MAX, 0).is_null());
        }
    }

    #[test]
    fn accepts_index_equal_to_capacity_like_the_original() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/volume_table"));
            return;
        };
        unsafe {
            // Original quirk: `capacity < index` fails, so index == 64
            // addresses one slot past the 64-entry table.
            assert_eq!(volume_table_lookup(64, 0), fx.slot(64));
        }
    }

    #[test]
    fn rejects_slot_with_word_18_set() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/volume_table"));
            return;
        };
        unsafe {
            fx.set_word_18(7, 1);
            assert!(volume_table_lookup(7, 0).is_null());
            assert!(volume_table_lookup(7, 0xffff).is_null());
            fx.set_word_18(7, 0x8000_0000);
            assert!(volume_table_lookup(7, 0).is_null());
            fx.set_word_18(7, 0);
            assert_eq!(volume_table_lookup(7, 0), fx.slot(7));
        }
    }

    #[test]
    fn flag_mask_filters_on_shared_bits() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/volume_table"));
            return;
        };
        unsafe {
            fx.set_flags(9, 0x0005);
            // Mask with a shared bit accepts.
            assert_eq!(volume_table_lookup(9, 0x0001), fx.slot(9));
            assert_eq!(volume_table_lookup(9, 0x0004), fx.slot(9));
            assert_eq!(volume_table_lookup(9, 0x0005), fx.slot(9));
            // Mask with no shared bit rejects.
            assert!(volume_table_lookup(9, 0x0002).is_null());
            assert!(volume_table_lookup(9, 0xfff8).is_null());
            // High mask bits can never match a zero-extended u16 field.
            assert!(volume_table_lookup(9, 0x0001_0000).is_null());
            // Zero mask accepts regardless of the field.
            fx.set_flags(9, 0);
            assert_eq!(volume_table_lookup(9, 0), fx.slot(9));
        }
    }

    #[test]
    fn null_table_base_yields_null() {
        let Some(fx) = Fixture::new() else {
            assert!(crate::testing::note_missing_u32_fixture("fs/volume_table"));
            return;
        };
        unsafe {
            addr_of_mut!(HOST_VOLUME_TABLE_PTR).write_volatile(0);
            // base NULL + index 0 makes the entry pointer itself NULL.
            assert!(volume_table_lookup(0, 0).is_null());
            // Nonzero index off a NULL base is still dereferenced by the
            // original; only the index-0 case is a defined host path.
        }
    }
}
