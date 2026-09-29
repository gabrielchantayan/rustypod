//! Drive sector-count reader.
//!
//! Reads the total and data-area sector counts from the drive slot selected by
//! a pathname.

use crate::drivers::ata_semaphore;
use crate::fs::{drive_slot, path_drive_index};

/// Resident capacity refresh at `0x082e24a0`, not yet ported.
const REFRESH_DRIVE_CAPACITY_ADDRESS: usize = 0x082e_24a0;
type RefreshDriveCapacity = unsafe extern "C" fn(usize) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn refresh_drive_capacity(index: usize) -> u32 {
    let refresh: RefreshDriveCapacity = core::mem::transmute(REFRESH_DRIVE_CAPACITY_ADDRESS);
    refresh(index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_drive_index(_: *const u8) -> i32 { -1 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_semaphore(_: usize) -> usize { 0 }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_capacity_refresh(_: usize) -> u32 { u32::MAX }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_slot_lookup(_: u32) -> *mut u8 { core::ptr::null_mut() }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    drive_index: unsafe extern "C" fn(*const u8) -> i32,
    wait: unsafe extern "C" fn(usize) -> usize,
    refresh_capacity: RefreshDriveCapacity,
    lookup_slot: unsafe extern "C" fn(u32) -> *mut u8,
    signal: unsafe extern "C" fn(usize) -> usize,
}

#[cfg(not(target_os = "none"))]
const DEFAULT_HOST_OPS: HostOps = HostOps {
    drive_index: missing_drive_index,
    wait: missing_semaphore,
    refresh_capacity: missing_capacity_refresh,
    lookup_slot: missing_slot_lookup,
    signal: missing_semaphore,
};

#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = DEFAULT_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> HostOps { core::ptr::addr_of!(HOST_OPS).read_volatile() }

#[inline(always)]
unsafe fn resolve_drive_index(path: *const u8) -> i32 {
    #[cfg(target_os = "none")]
    { path_drive_index::resolve_path_drive_index(path) }
    #[cfg(not(target_os = "none"))]
    { (host_ops().drive_index)(path) }
}

#[inline(always)]
unsafe fn wait_for_drive(index: usize) {
    #[cfg(target_os = "none")]
    { ata_semaphore::ata_semaphore_wait(index); }
    #[cfg(not(target_os = "none"))]
    { (host_ops().wait)(index); }
}

#[inline(always)]
unsafe fn capacity_refresh(index: usize) -> u32 {
    #[cfg(target_os = "none")]
    { refresh_drive_capacity(index) }
    #[cfg(not(target_os = "none"))]
    { (host_ops().refresh_capacity)(index) }
}

#[inline(always)]
unsafe fn lookup_drive_slot(index: u32) -> *mut u8 {
    #[cfg(target_os = "none")]
    { drive_slot::drive_slot_lookup(index) }
    #[cfg(not(target_os = "none"))]
    { (host_ops().lookup_slot)(index) }
}

#[inline(always)]
unsafe fn signal_drive(index: usize) {
    #[cfg(target_os = "none")]
    { ata_semaphore::ata_semaphore_signal(index); }
    #[cfg(not(target_os = "none"))]
    { (host_ops().signal)(index); }
}

/// `drive_sector_counts` — original: `FUN_082e172c` @ `0x082e172c` (132
/// bytes; five verified direct `bl` call sites, all unconditional).
///
/// Resolves `path` to a drive index. A negative result returns `u32::MAX` and
/// leaves both output pointers untouched. Otherwise it locks the drive,
/// refreshes its capacity, obtains its 508-byte slot, and, when present, writes
/// the total sector count (`slot+0x1f4`) and data-area sector count
/// (`slot+0x7c - 2`), each multiplied by the `u16` sector factor at `+0x1cc`.
/// It always unlocks a successfully resolved drive and returns the capacity
/// refresh result, except a missing slot returns `u32::MAX`.
///
/// Deliberate deviation: the unported capacity refresh remains a verified
/// resident call at `0x082e24a0`; host builds replace every boundary with
/// recording seams. Slot offsets are expressed as target-width byte offsets.
///
/// # Safety
///
/// `path` must satisfy the resident path parser ABI. On success with a present
/// slot, `data_sectors` and `total_sectors` must be writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn drive_sector_counts(path: *const u8, data_sectors: *mut u32, total_sectors: *mut u32) -> u32 {
    let index = resolve_drive_index(path);
    if index < 0 {
        return u32::MAX;
    }
    let index = index as usize;
    wait_for_drive(index);
    let result = capacity_refresh(index);
    let slot = lookup_drive_slot(index as u32);
    if slot.is_null() {
        signal_drive(index);
        return u32::MAX;
    }
    let sector_factor = slot.add(0x1cc).cast::<u16>().read() as u32;
    total_sectors.write(slot.add(0x1f4).cast::<u32>().read().wrapping_mul(sector_factor));
    data_sectors.write(slot.add(0x7c).cast::<u32>().read().wrapping_sub(2).wrapping_mul(sector_factor));
    signal_drive(index);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<std::vec::Vec<&'static str>> = Mutex::new(std::vec::Vec::new());
    static mut INDEX: i32 = 0;
    static mut SLOT: *mut u8 = core::ptr::null_mut();
    static mut REFRESH_RESULT: u32 = 0;

    unsafe extern "C" fn drive_index(_: *const u8) -> i32 { EVENTS.lock().push("index"); INDEX }
    unsafe extern "C" fn wait(_: usize) -> usize { EVENTS.lock().push("wait"); 0 }
    unsafe extern "C" fn refresh(_: usize) -> u32 { EVENTS.lock().push("refresh"); REFRESH_RESULT }
    unsafe extern "C" fn lookup(_: u32) -> *mut u8 { EVENTS.lock().push("lookup"); SLOT }
    unsafe extern "C" fn signal(_: usize) -> usize { EVENTS.lock().push("signal"); 0 }

    unsafe fn install() { HOST_OPS = HostOps { drive_index, wait, refresh_capacity: refresh, lookup_slot: lookup, signal }; }
    fn reset() {
        EVENTS.lock().clear();
        unsafe { INDEX = 0; SLOT = core::ptr::null_mut(); REFRESH_RESULT = 0; install(); }
    }

    #[test]
    fn reports_scaled_counts_and_unlocks() {
        let _guard = OPS_LOCK.lock();
        let Some(slot) = try_map_u32_slab(hints::DRIVE_SECTOR_COUNTS, 0x1000) else { return };
        reset();
        unsafe {
            slot.add(0x1cc).cast::<u16>().write(8);
            slot.add(0x1f4).cast::<u32>().write(100);
            slot.add(0x7c).cast::<u32>().write(5);
            SLOT = slot;
            REFRESH_RESULT = 0x1234;
            let mut data = 0;
            let mut total = 0;
            assert_eq!(drive_sector_counts(b"A:\0".as_ptr(), &mut data, &mut total), 0x1234);
            assert_eq!((data, total), (24, 800));
        }
        assert_eq!(*EVENTS.lock(), ["index", "wait", "refresh", "lookup", "signal"]);
    }

    #[test]
    fn missing_slot_unlocks_and_overrides_refresh_result() {
        let _guard = OPS_LOCK.lock();
        reset();
        unsafe {
            REFRESH_RESULT = 7;
            assert_eq!(drive_sector_counts(core::ptr::null(), core::ptr::null_mut(), core::ptr::null_mut()), u32::MAX);
        }
        assert_eq!(*EVENTS.lock(), ["index", "wait", "refresh", "lookup", "signal"]);
    }

    #[test]
    fn invalid_drive_does_not_touch_outputs_or_call_boundaries() {
        let _guard = OPS_LOCK.lock();
        reset();
        unsafe {
            INDEX = -1;
            let mut data = 0xaaaa_aaaa;
            let mut total = 0xbbbb_bbbb;
            assert_eq!(drive_sector_counts(core::ptr::null(), &mut data, &mut total), u32::MAX);
            assert_eq!((data, total), (0xaaaa_aaaa, 0xbbbb_bbbb));
        }
        assert_eq!(*EVENTS.lock(), ["index"]);
    }
}
