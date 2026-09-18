//! Extent-list storage-read wrapper.
//!
//! `storage_extent_read` — retailOS `FUN_08136920` at load address
//! **0x08136920**, 52 raw bytes (thirteen ARM words; the next independently
//! entered function begins at 0x08136954). Four inbound direct calls are plain
//! unconditional `bl` at 0x081bfa98, 0x081bfea4, 0x081bfee8, and 0x081c024c;
//! there are no predicated direct calls. Its body makes one unconditional `bl`.
//!
//! It forwards an extent-list read request to the stock extent-transfer helper
//! at 0x08136c64, inserting operation value one between `buffer` and `flags`.
//! That helper maps the requested block range over its extent list and, for this
//! operation value, reaches the storage-backend read dispatch.
//!
//! Deliberate deviation: 0x08136c64 has no verified Rust identity or port, so
//! target builds retain it as a raw-address seam; host tests replace that seam
//! with a recorder. The wrapper otherwise preserves all six input words and
//! returns the helper status unchanged.

#[cfg(target_os = "none")]
const STORAGE_EXTENT_TRANSFER_ADDRESS: usize = 0x0813_6c64;

type StorageExtentTransfer = unsafe extern "C" fn(
    *mut u8,
    u32,
    u32,
    *mut u32,
    *mut u8,
    u32,
    u32,
) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_storage_extent_transfer(
    _extent_list: *mut u8,
    _block: u32,
    _count: u32,
    _completed_blocks: *mut u32,
    _buffer: *mut u8,
    _operation: u32,
    _flags: u32,
) -> i32 {
    2
}

#[cfg(not(target_os = "none"))]
static mut HOST_STORAGE_EXTENT_TRANSFER: StorageExtentTransfer = missing_storage_extent_transfer;

#[inline(always)]
unsafe fn storage_extent_transfer(
    extent_list: *mut u8,
    block: u32,
    count: u32,
    completed_blocks: *mut u32,
    buffer: *mut u8,
    operation: u32,
    flags: u32,
) -> i32 {
    #[cfg(target_os = "none")]
    {
        let transfer: StorageExtentTransfer = core::mem::transmute(STORAGE_EXTENT_TRANSFER_ADDRESS);
        transfer(extent_list, block, count, completed_blocks, buffer, operation, flags)
    }

    #[cfg(not(target_os = "none"))]
    {
        let transfer = core::ptr::read_volatile(core::ptr::addr_of!(HOST_STORAGE_EXTENT_TRANSFER));
        transfer(extent_list, block, count, completed_blocks, buffer, operation, flags)
    }
}

/// Reads contiguous logical blocks through an extent-list-backed storage object.
///
/// # Safety
///
/// `extent_list`, `completed_blocks`, and `buffer` must meet the unchecked
/// extent-transfer helper contract. The original neither validates nor adjusts
/// any of these pointers before dispatch.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.storage_extent_read")]
#[inline(never)]
pub unsafe extern "C" fn storage_extent_read(
    extent_list: *mut u8,
    block: u32,
    count: u32,
    completed_blocks: *mut u32,
    buffer: *mut u8,
    flags: u32,
) -> i32 {
    storage_extent_transfer(
        extent_list,
        block,
        count,
        completed_blocks,
        buffer,
        1,
        flags,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: LazyLock<Mutex<std::vec::Vec<(usize, u32, u32, usize, usize, u32, u32)>>> =
        LazyLock::new(|| Mutex::new(std::vec::Vec::new()));
    static mut STATUS: i32 = 0;

    unsafe extern "C" fn record_extent_transfer(
        extent_list: *mut u8,
        block: u32,
        count: u32,
        completed_blocks: *mut u32,
        buffer: *mut u8,
        operation: u32,
        flags: u32,
    ) -> i32 {
        CALLS.lock().push((
            extent_list as usize,
            block,
            count,
            completed_blocks as usize,
            buffer as usize,
            operation,
            flags,
        ));
        STATUS
    }

    unsafe fn install_recorder(status: i32) {
        HOST_STORAGE_EXTENT_TRANSFER = record_extent_transfer;
        STATUS = status;
        CALLS.lock().clear();
    }

    unsafe fn reset_recorder() {
        HOST_STORAGE_EXTENT_TRANSFER = missing_storage_extent_transfer;
        CALLS.lock().clear();
    }

    #[test]
    fn inserts_read_operation_and_preserves_zero_request() {
        let _lock = TEST_LOCK.lock();
        unsafe { install_recorder(-0x34) };

        let status = unsafe {
            storage_extent_read(
                0x1234_5678usize as *mut u8,
                0xffff_fffe,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0xa5a5_5a5a,
            )
        };

        assert_eq!(status, -0x34);
        assert_eq!(
            *CALLS.lock(),
            std::vec![(0x1234_5678, 0xffff_fffe, 0, 0, 0, 1, 0xa5a5_5a5a)],
        );
        unsafe { reset_recorder() };
    }

    #[test]
    fn preserves_nonzero_pointer_and_request_words() {
        let _lock = TEST_LOCK.lock();
        unsafe { install_recorder(7) };

        let status = unsafe {
            storage_extent_read(
                0x8765_4321usize as *mut u8,
                0x1020_3040,
                0x5060_7080,
                0x2233_4455usize as *mut u32,
                0x6677_8899usize as *mut u8,
                0xffff_ffff,
            )
        };

        assert_eq!(status, 7);
        assert_eq!(
            *CALLS.lock(),
            std::vec![(
                0x8765_4321,
                0x1020_3040,
                0x5060_7080,
                0x2233_4455,
                0x6677_8899,
                1,
                0xffff_ffff,
            )],
        );
        unsafe { reset_recorder() };
    }
}
