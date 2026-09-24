//! Chunked storage transfer through a temporary aligned buffer.
//!
//! `storage_transfer_chunked` — retailOS `FUN_080f086c` at load address
//! **0x080f086c**, 192 raw bytes (48 ARM words; the next real function starts
//! at 0x080f092c). A complete decode of every ARM B/BL word in `osos.dec`
//! finds three direct unconditional `bl` call sites and no predicated calls.
//!
//! It limits each request to the geometry's maximum block count, allocates and
//! zeroes one temporary `count * 512` byte buffer, then transfers consecutive
//! chunks while carrying the 64-bit block address. Allocation failure returns
//! 0x19; any transfer failure stops immediately after releasing the buffer.
//! Deliberate deviations: the original leaves `r1` as its final helper-call
//! residue on success; Rust exposes the verified `r0` status only.

use core::ptr;

use crate::fs::storage_transfer::{storage_transfer_aligned_blocks, StorageTransferGeometry};
use crate::heap::aligned_buffer::{aligned_buffer_init, aligned_buffer_reset};
use crate::libc::iram_veneers::iram_memzero_veneer;

/// Storage geometry followed by the maximum number of 512-byte blocks per call.
#[repr(C)]
pub struct ChunkedStorageTransferGeometry {
    pub transfer: StorageTransferGeometry,
    pub max_blocks: u32,
}

/// Transfers `block_count` consecutive blocks in geometry-limited chunks.
///
/// # Safety
///
/// `geometry` must name three readable target words. Its maximum block count
/// must be nonzero for a nonzero request. The storage backend and its temporary
/// buffer must satisfy `storage_transfer_aligned_blocks`'s contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.storage_transfer_chunked")]
#[inline(never)]
pub unsafe extern "C" fn storage_transfer_chunked(
    geometry: *const ChunkedStorageTransferGeometry,
    _unused: u32,
    mut block: u32,
    mut block_high: u32,
    mut block_count: u32,
) -> i32 {
    let mut chunk_blocks = ptr::read_volatile(ptr::addr_of!((*geometry).max_blocks));
    if block_count <= chunk_blocks {
        chunk_blocks = block_count;
    }
    let mut chunk_bytes = chunk_blocks.wrapping_shl(9);
    let mut buffer = [0u32; 2];
    aligned_buffer_init(buffer.as_mut_ptr().cast(), chunk_bytes as usize);
    let data = ptr::read_volatile(buffer.as_ptr()) as usize as *mut u8;
    if data.is_null() {
        aligned_buffer_reset(buffer.as_mut_ptr().cast());
        return 0x19;
    }
    iram_memzero_veneer(data, chunk_bytes as usize);
    while block_count != 0 {
        let status = storage_transfer_aligned_blocks(
            geometry.cast::<StorageTransferGeometry>(),
            chunk_bytes,
            block,
            block_high,
            chunk_bytes,
            data,
        );
        if status != 0 {
            aligned_buffer_reset(buffer.as_mut_ptr().cast());
            return status;
        }
        let (next_block, carry) = block.overflowing_add(chunk_blocks);
        block = next_block;
        block_high = block_high.wrapping_add(carry as u32);
        block_count = block_count.wrapping_sub(chunk_blocks);
        if block_count < chunk_blocks {
            chunk_bytes = block_count.wrapping_shl(9);
            chunk_blocks = block_count;
        }
    }
    aligned_buffer_reset(buffer.as_mut_ptr().cast());
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::veneers::tests::{alloc_log, free_log, mock_heap, set_alloc_ret};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STORAGE_TRANSFER_CHUNKED, 0x4000).map(|pointer| pointer as usize)
    });

    fn fixture() -> Option<*mut u8> { (*SLAB).map(|pointer| pointer as *mut u8) }

    #[test]
    fn allocation_failure_returns_0x19_after_requesting_maximum_chunk_size() {
        let _lock = LOCK.lock();
        let _heap = mock_heap();
        set_alloc_ret(core::ptr::null_mut());
        let geometry = ChunkedStorageTransferGeometry {
            transfer: StorageTransferGeometry { block_size: 512, base_block: 0 }, max_blocks: 4,
        };
        assert_eq!(unsafe { storage_transfer_chunked(&geometry, 0, 7, 9, 10) }, 0x19);
        assert_eq!(alloc_log(), (1, 0x820, 3));
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn backend_failure_releases_the_temporary_buffer() {
        let _lock = LOCK.lock();
        let _heap = mock_heap();
        let Some(slab) = fixture() else {
            assert!(note_missing_u32_fixture("fs/storage_transfer_chunked"));
            return;
        };
        unsafe { set_alloc_ret(slab.add(0x20)) };
        let geometry = ChunkedStorageTransferGeometry {
            transfer: StorageTransferGeometry { block_size: 512, base_block: 0 }, max_blocks: 3,
        };
        assert_eq!(unsafe { storage_transfer_chunked(&geometry, 0, u32::MAX, 1, 5) }, 2);
        assert_eq!(alloc_log(), (1, 0x620, 3));
        assert_eq!(free_log().0, 1);
    }
}
