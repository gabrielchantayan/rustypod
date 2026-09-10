//! Aligned storage-transfer validation and dispatch.
//!
//! `storage_transfer_aligned_blocks` — retailOS `FUN_08077444` at load address
//! **0x08077444**, 76 raw bytes (19 ARM words; the independently linked next
//! function starts at 0x08077490). A complete decode of every ARM B/BL word in
//! `osos.dec` finds 11 direct call sites, all unconditional `bl`; there are no
//! predicated calls.
//!
//! It divides the requested byte count by the geometry's block size. A nonzero
//! remainder returns 0x50 without dispatching. Otherwise it adds the geometry
//! base block to the supplied relative block, then tail-dispatches the block
//! count and buffer through stock helper 0x0807dd68. That helper loads the
//! opaque storage object at 0x089cfd04, returns 2 if it is absent, and otherwise
//! reaches virtual thunk 0x08149e10 with `(absolute_block, block_count, buffer,
//! 0)`.
//!
//! Deliberate deviations: the original calculates the high half of
//! `base_block + relative_block` but overwrites it before the tail branch, so
//! this port represents that ABI-preserved `relative_block_high` input without
//! reproducing its dead arithmetic. The unported dynamic dispatch is an
//! explicit target-address seam; host tests replace it with a recorder.

use core::ptr;

use crate::runtime::rt_div::__rt_udivmod;

/// Two-word geometry read by the original at offsets zero and four.
#[repr(C)]
pub struct StorageTransferGeometry {
    /// Bytes in one backend block.
    pub block_size: u32,
    /// Backend block number corresponding to relative block zero.
    pub base_block: u32,
}

type StorageBlockTransfer = unsafe extern "C" fn(u32, u32, *mut u8) -> i32;

#[cfg(target_os = "none")]
const STORAGE_BLOCK_TRANSFER_ADDRESS: usize = 0x0807_dd68;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_storage_block_transfer(_block: u32, _count: u32, _buffer: *mut u8) -> i32 {
    2
}

/// Host-only replacement for the opaque dispatch rooted at 0x089cfd04.
#[cfg(not(target_os = "none"))]
static mut HOST_STORAGE_BLOCK_TRANSFER: StorageBlockTransfer = missing_storage_block_transfer;

#[inline(always)]
unsafe fn storage_block_transfer(block: u32, count: u32, buffer: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    {
        let transfer: StorageBlockTransfer = core::mem::transmute(STORAGE_BLOCK_TRANSFER_ADDRESS);
        transfer(block, count, buffer)
    }

    #[cfg(not(target_os = "none"))]
    {
        let transfer = ptr::read_volatile(ptr::addr_of!(HOST_STORAGE_BLOCK_TRANSFER));
        transfer(block, count, buffer)
    }
}

/// Validates an aligned byte transfer and sends its block representation to the
/// active storage backend — retailOS `FUN_08077444` @ 0x08077444 (76 bytes;
/// 11 direct unconditional `bl` call sites).
///
/// # Safety
///
/// `geometry` must point to two readable, word-aligned words. `buffer` and the
/// global storage object's dynamic target must satisfy the dispatched backend's
/// contract. Like the original, this function does not NULL-check `geometry`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.storage_transfer_aligned_blocks")]
#[inline(never)]
pub unsafe extern "C" fn storage_transfer_aligned_blocks(
    geometry: *const StorageTransferGeometry,
    _unused: u32,
    relative_block: u32,
    _relative_block_high: u32,
    byte_count: u32,
    buffer: *mut u8,
) -> i32 {
    let block_size = ptr::read_volatile(ptr::addr_of!((*geometry).block_size));
    let mut remainder = 0;
    let block_count = __rt_udivmod(byte_count, block_size, &mut remainder);
    if remainder != 0 {
        return 0x50;
    }

    let base_block = ptr::read_volatile(ptr::addr_of!((*geometry).base_block));
    storage_block_transfer(base_block.wrapping_add(relative_block), block_count, buffer)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLS: LazyLock<Mutex<std::vec::Vec<(u32, u32, usize)>>> = LazyLock::new(|| Mutex::new(std::vec::Vec::new()));
    static mut TRANSFER_STATUS: i32 = 0;

    unsafe extern "C" fn record_storage_block_transfer(block: u32, count: u32, buffer: *mut u8) -> i32 {
        CALLS.lock().push((block, count, buffer as usize));
        TRANSFER_STATUS
    }

    unsafe fn install_recorder(status: i32) {
        HOST_STORAGE_BLOCK_TRANSFER = record_storage_block_transfer;
        TRANSFER_STATUS = status;
        CALLS.lock().clear();
    }

    unsafe fn reset_recorder() {
        HOST_STORAGE_BLOCK_TRANSFER = missing_storage_block_transfer;
        CALLS.lock().clear();
    }

    #[test]
    fn rejects_byte_count_not_divisible_by_block_size_without_dispatching() {
        let _lock = TEST_LOCK.lock();
        let geometry = StorageTransferGeometry { block_size: 512, base_block: 0x1234_5678 };
        unsafe { install_recorder(-9) };

        let status = unsafe {
            storage_transfer_aligned_blocks(&geometry, 0, 7, 0xffff_ffff, 513, 0x1234_5000usize as *mut u8)
        };

        assert_eq!(status, 0x50);
        assert!(CALLS.lock().is_empty());
        unsafe { reset_recorder() };
    }

    #[test]
    fn dispatches_zero_and_full_blocks_with_wrapping_base_and_ignored_high_word() {
        let _lock = TEST_LOCK.lock();
        let geometry = StorageTransferGeometry { block_size: 512, base_block: 0xffff_fff0 };
        unsafe { install_recorder(-0x34) };

        let zero_status = unsafe {
            storage_transfer_aligned_blocks(&geometry, 0, 0x30, 0, 0, 0x1234_5000usize as *mut u8)
        };
        let full_status = unsafe {
            storage_transfer_aligned_blocks(&geometry, 0, 0x30, 0xdead_beef, 1024, 0x5678_9000usize as *mut u8)
        };

        assert_eq!(zero_status, -0x34);
        assert_eq!(full_status, -0x34);
        assert_eq!(*CALLS.lock(), std::vec![
            (0x20, 0, 0x1234_5000),
            (0x20, 2, 0x5678_9000),
        ]);
        unsafe { reset_recorder() };
    }
}
