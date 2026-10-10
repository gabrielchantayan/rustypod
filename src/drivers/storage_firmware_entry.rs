//! Firmware directory entry resolution — `FUN_080763e4` @ `0x080763e4`.
//!
//! True extent: **116 bytes**, ending at the next function's push at
//! `0x08076458`. Raw A32 words contain four unconditional outbound BLs and
//! zero predicated BLs; two unconditional inbound BLs, zero predicated.
//! Gets storage device 0, returns 2 if absent, invokes the locked predicate
//! (ignoring its result), finds the firmware partition, then resolves the
//! entry matching a type word and 16-bit identifier. Errors pass through.
//!
//! Deliberate deviations: host builds require explicit operation boundaries;
//! firmware uses the existing getter/predicate ports and unported partition
//! (`0x080b3fdc`) and directory (`0x08079a58`) routines directly. Scratch
//! words are uninitialized, as in retailOS, and never read on an error path.

use core::mem::MaybeUninit;

/// Host boundaries for operations whose objects use target-width pointers.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct StorageFirmwareEntryOps {
    pub get: unsafe fn(u32) -> *mut u8,
    pub prepare: unsafe fn(*mut u8) -> bool,
    pub partition: unsafe fn(*mut u8, *mut u32, *mut u32) -> i32,
    pub entry: unsafe fn(*mut u8, u32, u32, u32, *mut u32, *mut u32, *mut u32) -> i32,
}

#[cfg(not(target_os = "none"))]
unsafe fn missing_get(_: u32) -> *mut u8 { panic!("install storage firmware entry host operations") }
#[cfg(not(target_os = "none"))]
unsafe fn missing_prepare(_: *mut u8) -> bool { panic!("install storage firmware entry host operations") }
#[cfg(not(target_os = "none"))]
unsafe fn missing_partition(_: *mut u8, _: *mut u32, _: *mut u32) -> i32 { panic!("install storage firmware entry host operations") }
#[cfg(not(target_os = "none"))]
unsafe fn missing_entry(_: *mut u8, _: u32, _: u32, _: u32, _: *mut u32, _: *mut u32, _: *mut u32) -> i32 { panic!("install storage firmware entry host operations") }

/// Must be installed before calling the host export; no simulated fallback.
#[cfg(not(target_os = "none"))]
pub static mut STORAGE_FIRMWARE_ENTRY_OPS: StorageFirmwareEntryOps = StorageFirmwareEntryOps {
    get: missing_get, prepare: missing_prepare, partition: missing_partition, entry: missing_entry,
};

#[inline(always)]
unsafe fn resolve(
    get: impl FnOnce() -> *mut u8,
    prepare: impl FnOnce(*mut u8),
    partition: impl FnOnce(*mut u8, *mut u32, *mut u32) -> i32,
    entry: impl FnOnce(*mut u8, u32, *mut u32) -> i32,
) -> i32 {
    let device = get();
    if device.is_null() { return 2; }
    prepare(device);
    let mut start = MaybeUninit::<u32>::uninit();
    let mut length = MaybeUninit::<u32>::uninit();
    let status = partition(device, start.as_mut_ptr(), length.as_mut_ptr());
    if status != 0 { return status; }
    let mut flags = MaybeUninit::<u32>::uninit();
    entry(device, start.assume_init(), flags.as_mut_ptr())
}

/// Resolve the firmware entry's absolute sector and sector count.
///
/// # Safety
/// Output pointers must be writable u32 words, and active storage operations
/// must obey their recovered ABI. Partition success must initialize start.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn storage_firmware_entry(
    entry_type: u32, identifier: u32, sector: *mut u32, sector_count: *mut u32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let partition: unsafe extern "C" fn(*mut u8, *mut u32, *mut u32) -> i32 =
            core::mem::transmute(0x080b_3fdcusize);
        let entry: unsafe extern "C" fn(*mut u8, u32, u32, u32, *mut u32, *mut u32, *mut u32) -> i32 =
            core::mem::transmute(0x0807_9a58usize);
        resolve(
            || super::storage_device_get::storage_device_get(0),
            |device| { crate::app::locked_callback_predicate::locked_callback_predicate(device.cast()); },
            |device, start, length| partition(device, start, length),
            |device, start, flags| entry(device, start, entry_type, identifier, sector, sector_count, flags))
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = core::ptr::read(core::ptr::addr_of!(STORAGE_FIRMWARE_ENTRY_OPS));
        resolve(
            || (ops.get)(0), |device| { (ops.prepare)(device); },
            |device, start, length| (ops.partition)(device, start, length),
            |device, start, flags| (ops.entry)(device, start, entry_type, identifier, sector, sector_count, flags))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn absent_device_returns_two_without_storage_access() {
        let status = unsafe { resolve(
            || core::ptr::null_mut(), |_| panic!("prepare on absent device"),
            |_, _, _| panic!("partition on absent device"),
            |_, _, _| panic!("entry on absent device")) };
        assert_eq!(status, 2);
    }

    #[test]
    fn partition_error_short_circuits_without_reading_scratch() {
        for error in [-1, 7, 0x21] {
            let prepared = Cell::new(false);
            let mut device = [0u32; 8];
            let status = unsafe { resolve(
                || device.as_mut_ptr().cast(), |_| prepared.set(true),
                |_, _, _| { assert!(prepared.get()); error },
                |_, _, _| panic!("entry after partition error")) };
            assert_eq!(status, error);
        }
    }

    #[test]
    fn directory_status_is_preserved_after_successful_partition() {
        for result in [0, 7, 0x20, -1] {
            let prepared = Cell::new(false);
            let mut device = [0u32; 8];
            let status = unsafe { resolve(
                || device.as_mut_ptr().cast(), |_| prepared.set(true),
                |_, start, _| { assert!(prepared.get()); start.write(u32::MAX); 0 },
                |_, start, _| { assert_eq!(start, u32::MAX); result }) };
            assert_eq!(status, result);
        }
    }
}
