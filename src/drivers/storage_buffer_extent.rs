//! `storage_buffer_extent` — retailOS `FUN_082bd218` at load address
//! **0x082bd218**. Raw ARM runs from `push {r4-r9,lr}` through `pop
//! {r4-r9,pc}` at `0x082bd2d0`, followed by the literal-pool word at
//! `0x082bd2d4`; the independently entered next function begins at
//! `0x082bd2d8`. Its true extent is therefore **192 bytes** (Ghidra reports
//! 188 instruction bytes).
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds exactly **five**
//! inbound direct calls, all unconditional `bl`: `0x080fcc4c`, `0x0814fc10`,
//! `0x08279670`, `0x082796b0`, and `0x082bd36c`. There are no predicated
//! direct calls or direct tail branches.
//!
//! # Algorithm
//!
//! Obtain the storage-device operation table and invoke its +0x08 callback
//! with a 4-byte scratch result. Then call `FUN_082bd164` with the scan
//! context word at `0x089caaec`, a 104-byte stack result area, and the input
//! buffer address. On successful scan, select the first entry whose byte at
//! `8 + 12 * index` is 1 or 2, returning the two words at
//! `12 + 12 * index` and `16 + 12 * index`. Missing results remain
//! `0xffffffff`; optional output pointers are independently nullable. The
//! return value is always zero.
//!
//! # Deliberate deviation
//!
//! `FUN_082bd164` and the operation-table callback are unported. Firmware
//! builds call their verified target addresses. Host builds use seams, because
//! target-width operation-table words cannot hold host function pointers.

use core::ptr;

use super::storage_device_operations::storage_device_operations_get;

#[cfg(target_os = "none")]
const RETAIL_STORAGE_SCAN_CONTEXT_SLOT: usize = 0x089c_aaec;
#[cfg(target_os = "none")]
const RETAIL_STORAGE_RECORD_SCAN: usize = 0x082b_d164;

#[repr(C, align(4))]
struct StorageScanResults {
    bytes: [u8; 104],
}

#[cfg(not(target_os = "none"))]
pub static mut STORAGE_SCAN_CONTEXT: u32 = 0;

/// ABI of the unported `FUN_082bd164` storage-record scanner.
#[cfg(not(target_os = "none"))]
pub type StorageRecordScan = unsafe extern "C" fn(u32, *mut u8, u32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_storage_record_scan(_: u32, _: *mut u8, _: u32) -> i32 {
    panic!("storage record scanner is unported")
}

#[cfg(not(target_os = "none"))]
pub static mut STORAGE_RECORD_SCAN: StorageRecordScan = missing_storage_record_scan;

/// Host replacement for the target-width operation-table callback at +0x08.
#[cfg(not(target_os = "none"))]
pub type StorageOperation = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_storage_operation(_: *mut u8) {
    panic!("storage operation callback is unported")
}

#[cfg(not(target_os = "none"))]
pub static mut STORAGE_OPERATION: StorageOperation = missing_storage_operation;

#[inline(always)]
unsafe fn storage_scan_context() -> u32 {
    #[cfg(target_os = "none")]
    {
        (RETAIL_STORAGE_SCAN_CONTEXT_SLOT as *const u32).read_volatile()
    }
    #[cfg(not(target_os = "none"))]
    {
        ptr::read_volatile(ptr::addr_of!(STORAGE_SCAN_CONTEXT))
    }
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn invoke_storage_operation(scratch: *mut u8) {
    let operations = storage_device_operations_get();
    let operation: unsafe extern "C" fn(*mut u8) = core::mem::transmute(operations.add(2).read_volatile());
    operation(scratch);
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn invoke_storage_operation(scratch: *mut u8) {
    storage_device_operations_get();
    ptr::read_volatile(ptr::addr_of!(STORAGE_OPERATION))(scratch);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn scan_storage_records(context: u32, results: *mut u8, buffer: u32) -> i32 {
    let scan: unsafe extern "C" fn(u32, *mut u8, u32) -> i32 = core::mem::transmute(RETAIL_STORAGE_RECORD_SCAN);
    scan(context, results, buffer)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn scan_storage_records(context: u32, results: *mut u8, buffer: u32) -> i32 {
    ptr::read_volatile(ptr::addr_of!(STORAGE_RECORD_SCAN))(context, results, buffer)
}

/// Returns the first usable storage extent discovered for `buffer`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn storage_buffer_extent(buffer: u32, start_out: *mut u32, length_out: *mut u32) -> u32 {
    let mut scratch = 0u32;
    let mut start = u32::MAX;
    let mut length = u32::MAX;
    let mut results = StorageScanResults { bytes: [0; 104] };

    invoke_storage_operation(ptr::addr_of_mut!(scratch).cast::<u8>());
    if scan_storage_records(storage_scan_context(), results.bytes.as_mut_ptr(), buffer) == 0 {
        let count = ptr::read_unaligned(results.bytes.as_ptr().add(4).cast::<u32>());
        let mut index = 0;
        while index < count {
            let offset = 8usize + index as usize * 12;
            let kind = results.bytes[offset];
            if kind == 1 || kind == 2 {
                start = ptr::read_unaligned(results.bytes.as_ptr().add(offset + 4).cast::<u32>());
                length = ptr::read_unaligned(results.bytes.as_ptr().add(offset + 8).cast::<u32>());
                break;
            }
            index += 1;
        }
    }
    if !start_out.is_null() {
        start_out.write(start);
    }
    if !length_out.is_null() {
        length_out.write(length);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut OPERATION_CALLS: u32 = 0;
    static mut SCAN_STATUS: i32 = 0;
    static mut SCAN_BUFFER: u32 = 0;

    unsafe extern "C" fn recording_operation(scratch: *mut u8) {
        OPERATION_CALLS += 1;
        scratch.cast::<u32>().write(0xfeed_beef);
    }

    unsafe extern "C" fn recording_scan(_: u32, results: *mut u8, buffer: u32) -> i32 {
        SCAN_BUFFER = buffer;
        SCAN_STATUS
    }

    unsafe fn reset() {
        OPERATION_CALLS = 0;
        SCAN_STATUS = 0;
        SCAN_BUFFER = 0;
        STORAGE_SCAN_CONTEXT = 0x1234_5678;
        STORAGE_OPERATION = recording_operation;
        STORAGE_RECORD_SCAN = recording_scan;
    }

    #[test]
    fn selects_first_usable_record_and_passes_buffer() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset();
            unsafe extern "C" fn scan(_: u32, results: *mut u8, buffer: u32) -> i32 {
                recording_scan(0, results, buffer);
                results.add(4).cast::<u32>().write_unaligned(3);
                *results.add(8) = 0;
                *results.add(20) = 2;
                results.add(24).cast::<u32>().write_unaligned(41);
                results.add(28).cast::<u32>().write_unaligned(99);
                *results.add(32) = 1;
                results.add(36).cast::<u32>().write_unaligned(7);
                results.add(40).cast::<u32>().write_unaligned(8);
                0
            }
            STORAGE_RECORD_SCAN = scan;
            let mut start = 0;
            let mut length = 0;
            assert_eq!(storage_buffer_extent(0xaabb_ccdd, &mut start, &mut length), 0);
            assert_eq!((start, length), (41, 99));
            assert_eq!(OPERATION_CALLS, 1);
            assert_eq!(SCAN_BUFFER, 0xaabb_ccdd);
        }
    }

    #[test]
    fn scan_failure_and_null_outputs_preserve_sentinel_behavior() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            reset();
            SCAN_STATUS = -1;
            let mut start = 0;
            assert_eq!(storage_buffer_extent(0, &mut start, ptr::null_mut()), 0);
            assert_eq!(start, u32::MAX);
            assert_eq!(OPERATION_CALLS, 1);
        }
    }
}
