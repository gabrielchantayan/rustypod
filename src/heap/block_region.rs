//! Ports of the block-deque element -> region accessors used by
//! `pool_seed_regions` (heap/pool.rs) to place each seeded block:
//!
//! - `region_ref_lock` — original: `FUN_082801f8` @ 0x082801f8
//!   (20 bytes; 14 `bl` call sites): loads the element's region object
//!   (elem + 0x4); a NULL region returns immediately (r0 = 0), otherwise
//!   tail-branches to the C++ mutex lock @ 0x082e8390 (via the alias
//!   thunk `b` @ 0x082621a8) on the region's mutex (region + 0x8),
//!   returning the lock result.
//! - `region_ref_unlock` — original: `FUN_082802cc` @ 0x082802cc
//!   (20 bytes; 10 `bl` + 1 tail `b` call sites): identical shape,
//!   tail-branching to the mutex unlock @ 0x082e83d8 (thunk @
//!   0x082621ac).
//! - `block_to_region_start` — original: `FUN_08280430` @ 0x08280430
//!   (48 bytes; 9 `bl` call sites, binary-verified — osos.asm drops
//!   one): locks the element's region, reads the region start address
//!   (region + 0x4), substitutes the fallback address (the literal
//!   0x089cb1b8 — see below) when the region or its start is NULL,
//!   unlocks, and returns the start. This is the POOL_OPS `region_start`
//!   hook of pool.rs: the address the seeded heap block begins at.
//!
//! Layouts (element stride 0x28, all fields 32-bit on target):
//! `elem + 0x4` = region object pointer; `region + 0x4` = region start
//! address; `region + 0x8` = mutex object pointer.
//!
//! The fallback: the original returns the *address* 0x089cb1b8 — the
//! word right after the block-manager global @ 0x089cb1b4 (block_mgr.rs)
//! in the runtime-initialized 0x089cb1xx page — when the element has no
//! live region. Modeled as the address of [`REGION_START_FALLBACK`]
//! (only its address identity is ever used; nothing dereferences it in
//! this cluster).
//!
//! Deviations:
//! - The mutex pair @ 0x082e8390 / 0x082e83d8 is unported C++ recursive-
//!   mutex machinery (magic-word fast path + kernel slow path @
//!   0x080cdd6c); it is the [`REGION_MUTEX_OPS`] dispatch boundary. The
//!   defaults are documented no-ops returning 0: they provide NO mutual
//!   exclusion — sound for the current single-threaded/pre-manager use,
//!   and the slots take the real ports when they land (the free_path.rs
//!   HEAP_MUTEX_HOOKS pattern). Host tests install recording mocks and
//!   prove the lock -> read -> unlock protocol, not exclusion.
//! - Pointer fields are addressed by WORD INDEX, not by the literal
//!   target byte offset: on the 32-bit target `index * WORD` reproduces
//!   the original offsets exactly (0x4, 0x8), while on a 64-bit host the
//!   fields stay disjoint. Using the literal byte offsets on a 64-bit
//!   host would make `region + 0x4` and `region + 0x8` overlap by four
//!   bytes, so a start-address read would return
//!   `(mutex << 32) | start`. Reads stay unaligned-safe because the test
//!   fixtures are plain `u8` arrays with no pointer alignment guarantee.

/// Width of a pointer field: 4 on the ARMv5TE target (matching the
/// original layout), 8 on a 64-bit test host.
const WORD: usize = core::mem::size_of::<*mut u8>();

/// Word index of the region object pointer in a deque element
/// (byte offset 0x4 on the 32-bit target).
pub const ELEM_REGION_INDEX: usize = 1;

/// Word index of the region start address in a region object
/// (byte offset 0x4 on the 32-bit target).
pub const REGION_START_INDEX: usize = 1;

/// Word index of the mutex object pointer in a region object
/// (byte offset 0x8 on the 32-bit target).
pub const REGION_MUTEX_INDEX: usize = 2;

/// The word @ 0x089cb1b8 whose *address* is the fallback "region start"
/// (see the module header). Lives here next to its on-device neighbor
/// `block_mgr::BLOCK_MANAGER` (0x089cb1b4) in spirit; the two are
/// separate statics, which is harmless because only this one's address
/// and only that one's value are ever used.
pub static mut REGION_START_FALLBACK: u32 = 0;

/// Indirect dispatch pair for the unported C++ mutex @ 0x082e8390 /
/// 0x082e83d8 (see the module header for the default-stub contract).
#[derive(Clone, Copy)]
pub struct RegionMutexOps {
    /// Mutex lock @ 0x082e8390 (thunk @ 0x082621a8). Returns the lock
    /// status word (0x1a on NULL mutex in the original).
    pub lock: unsafe extern "C" fn(mutex: *mut u8) -> u32,
    /// Mutex unlock @ 0x082e83d8 (thunk @ 0x082621ac).
    pub unlock: unsafe extern "C" fn(mutex: *mut u8) -> u32,
}

/// Default stub: no mutex implementation — no-op, no mutual exclusion
/// (documented in the module header).
unsafe extern "C" fn missing_mutex_lock(_mutex: *mut u8) -> u32 {
    0
}

/// Default stub: see [`missing_mutex_lock`].
unsafe extern "C" fn missing_mutex_unlock(_mutex: *mut u8) -> u32 {
    0
}

/// Wired defaults (documented no-ops until the mutex cluster is ported).
pub(crate) const DEFAULT_REGION_MUTEX_OPS: RegionMutexOps = RegionMutexOps {
    lock: missing_mutex_lock,
    unlock: missing_mutex_unlock,
};

/// The active mutex implementation. Host tests install recording mocks;
/// the real ports replace the defaults when they exist.
pub static mut REGION_MUTEX_OPS: RegionMutexOps = DEFAULT_REGION_MUTEX_OPS;

/// Reads one mutex op (volatile — same rationale as every dispatch
/// table: the slot is meant to be swapped at runtime).
macro_rules! mutex_op {
    ($field:ident) => {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(REGION_MUTEX_OPS.$field)) }
    };
}

/// Reads the pointer field at `base + offset` (unaligned — see the
/// module header's host deviation).
#[inline(always)]
unsafe fn ptr_field(base: *const u8, index: usize) -> *mut u8 {
    (base.add(index * WORD) as *const *mut u8).read_unaligned()
}

/// region_ref_lock — original: `FUN_082801f8` @ 0x082801f8 (20 bytes).
///
/// Locks the region of a deque element. NULL region: returns 0 without
/// touching the mutex (exactly the original's early `bx lr` with the
/// NULL load in r0); otherwise returns the mutex lock result.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn region_ref_lock(elem: *const u8) -> u32 {
    let region = ptr_field(elem, ELEM_REGION_INDEX);
    if region.is_null() {
        return 0;
    }
    (mutex_op!(lock))(ptr_field(region, REGION_MUTEX_INDEX))
}

/// region_ref_unlock — original: `FUN_082802cc` @ 0x082802cc (20 bytes).
///
/// Unlock twin of [`region_ref_lock`].
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn region_ref_unlock(elem: *const u8) -> u32 {
    let region = ptr_field(elem, ELEM_REGION_INDEX);
    if region.is_null() {
        return 0;
    }
    (mutex_op!(unlock))(ptr_field(region, REGION_MUTEX_INDEX))
}

/// block_to_region_start — original: `FUN_08280430` @ 0x08280430
/// (48 bytes).
///
/// Maps a block-deque element to the start address of its region, under
/// the region's mutex. Elements without a live region (or with a NULL
/// start) map to the fallback address (see the module header).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn block_to_region_start(elem: *const u8) -> *mut u8 {
    region_ref_lock(elem);
    let region = ptr_field(elem, ELEM_REGION_INDEX);
    let mut start = core::ptr::null_mut();
    if !region.is_null() {
        start = ptr_field(region, REGION_START_INDEX);
    }
    if region.is_null() || start.is_null() {
        start = core::ptr::addr_of_mut!(REGION_START_FALLBACK) as *mut u8;
    }
    region_ref_unlock(elem);
    start
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the global mutex ops.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Mutex-op event log: (is_lock, mutex address).
    static mut EVENTS: Vec<(bool, usize)> = Vec::new();

    unsafe extern "C" fn recording_lock(mutex: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push((true, mutex as usize));
        0
    }

    unsafe extern "C" fn recording_unlock(mutex: *mut u8) -> u32 {
        (*core::ptr::addr_of_mut!(EVENTS)).push((false, mutex as usize));
        0
    }

    fn mock_mutex() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            REGION_MUTEX_OPS = RegionMutexOps {
                lock: recording_lock,
                unlock: recording_unlock,
            };
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
        }
        guard
    }

    fn restore_mutex() {
        unsafe { REGION_MUTEX_OPS = DEFAULT_REGION_MUTEX_OPS };
    }

    fn events() -> Vec<(bool, usize)> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    /// Builds a deque element (0x28 raw bytes) pointing at a region
    /// object (0x10 raw bytes) with the given start/mutex fields.
    /// Writes a pointer field by word index, matching [`ptr_field`].
    unsafe fn write_ptr_field(base: *mut u8, index: usize, value: *mut u8) {
        (base.add(index * WORD) as *mut *mut u8).write_unaligned(value);
    }

    unsafe fn write_elem(elem: *mut u8, region: *mut u8) {
        write_ptr_field(elem, ELEM_REGION_INDEX, region);
    }

    unsafe fn write_region(region: *mut u8, start: *mut u8, mutex: *mut u8) {
        write_ptr_field(region, REGION_START_INDEX, start);
        write_ptr_field(region, REGION_MUTEX_INDEX, mutex);
    }

    fn fallback() -> *mut u8 {
        unsafe { core::ptr::addr_of_mut!(REGION_START_FALLBACK) as *mut u8 }
    }

    #[test]
    fn live_region_maps_to_its_start_under_the_lock() {
        let _guard = mock_mutex();
        let mut elem = [0u8; 0x28];
        let mut region = [0u8; 0x18];
        let mutex = 0x5000usize as *mut u8;
        unsafe {
            write_region(region.as_mut_ptr(), 0x2_0000 as *mut u8, mutex);
            write_elem(elem.as_mut_ptr(), region.as_mut_ptr());
            let start = block_to_region_start(elem.as_ptr());
            assert_eq!(start, 0x2_0000 as *mut u8);
        }
        // Lock on the region's mutex, then unlock — in that order.
        assert_eq!(
            events(),
            std::vec![(true, 0x5000), (false, 0x5000)],
            "lock -> read -> unlock protocol"
        );
        restore_mutex();
    }

    #[test]
    fn null_region_returns_fallback_without_mutex_traffic() {
        let _guard = mock_mutex();
        let mut elem = [0u8; 0x28];
        unsafe {
            write_elem(elem.as_mut_ptr(), core::ptr::null_mut());
            assert_eq!(block_to_region_start(elem.as_ptr()), fallback());
        }
        assert!(
            events().is_empty(),
            "NULL region: neither helper reaches the mutex"
        );
        restore_mutex();
    }

    #[test]
    fn null_start_returns_fallback_but_still_locks() {
        let _guard = mock_mutex();
        let mut elem = [0u8; 0x28];
        let mut region = [0u8; 0x18];
        unsafe {
            write_region(region.as_mut_ptr(), core::ptr::null_mut(), 0x6000 as *mut u8);
            write_elem(elem.as_mut_ptr(), region.as_mut_ptr());
            assert_eq!(block_to_region_start(elem.as_ptr()), fallback());
        }
        assert_eq!(events(), std::vec![(true, 0x6000), (false, 0x6000)]);
        restore_mutex();
    }

    #[test]
    fn lock_helper_returns_zero_on_null_region_else_lock_result() {
        let _guard = mock_mutex();
        let mut elem = [0u8; 0x28];
        let mut region = [0u8; 0x18];
        unsafe {
            write_elem(elem.as_mut_ptr(), core::ptr::null_mut());
            assert_eq!(region_ref_lock(elem.as_ptr()), 0);
            assert!(events().is_empty());

            write_region(region.as_mut_ptr(), 0x1000 as *mut u8, 0x7000 as *mut u8);
            write_elem(elem.as_mut_ptr(), region.as_mut_ptr());
            assert_eq!(region_ref_lock(elem.as_ptr()), 0);
            assert_eq!(events(), std::vec![(true, 0x7000)]);
            assert_eq!(region_ref_unlock(elem.as_ptr()), 0);
            assert_eq!(events(), std::vec![(true, 0x7000), (false, 0x7000)]);
        }
        restore_mutex();
    }

    #[test]
    fn default_mutex_ops_are_noops() {
        let _guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore_mutex();
        let mut elem = [0u8; 0x28];
        let mut region = [0u8; 0x18];
        unsafe {
            write_region(region.as_mut_ptr(), 0x3_0000 as *mut u8, 0x8000 as *mut u8);
            write_elem(elem.as_mut_ptr(), region.as_mut_ptr());
            assert_eq!(
                block_to_region_start(elem.as_ptr()),
                0x3_0000 as *mut u8,
                "defaults must not disturb the mapping"
            );
        }
    }
}
