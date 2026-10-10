//! Writes a chain of empty B-tree allocation-map nodes.
//!
//! retailOS `FUN_080819d8` @ **0x080819d8**, 208 bytes, ending at the
//! next real ARM prologue @ 0x08081aa8. Raw-word scan verifies two incoming
//! unconditional BL calls (0x0807cec8, 0x0807cf50), no predicated BL calls;
//! the body contains seven unconditional BL instructions.
//!
//! Zero one reusable node buffer, set kind=2, one record, record start=14,
//! and free-space start=node_size-6. Write successive map nodes with a
//! big-endian forward link, ending in zero; advance disk blocks by size>>9.
//! Stop on the first storage error. Even a zero count initializes the buffer.
//! Preserve the original counter's bit-16 clearing (counts above 65535 may
//! never terminate). Node numbers and disk blocks wrap at 32 bits.
//!
//! Deliberate deviations: byte-swap helpers inline; the existing unaligned
//! store uses its Rust pointer-first ABI. Only the r0 status is exposed:
//! the original saves/restores r1, not a meaningful second return value.

use crate::fs::storage_transfer::{storage_transfer_aligned_blocks, StorageTransferGeometry};
use crate::libc::iram_veneers::iram_memzero_veneer;
use crate::libc::rt_unaligned::__rt_uwrite4;
use crate::util::bswap::{bswap16, bswap32};

/// Initializes and writes empty map nodes following `previous_node`.
///
/// # Safety
/// `buffer` must be halfword-aligned and writable for `node_size` bytes;
/// `node_size` must be even and at least 14. Geometry and backend must satisfy
/// `storage_transfer_aligned_blocks`'s contract. For termination, `node_count`
/// must not exceed 65535. The original does not validate these preconditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn storage_write_btree_map_nodes(
    geometry: *const StorageTransferGeometry,
    first_block: u32,
    previous_node: u32,
    node_count: u32,
    node_size: u32,
    buffer: *mut u8,
) -> i32 {
    write_map_nodes(first_block, previous_node, node_count, node_size, buffer, |block, data| {
        storage_transfer_aligned_blocks(geometry, 0, block, 0, node_size, data)
    })
}

#[inline(always)]
unsafe fn write_map_nodes(
    mut block: u32,
    mut previous_node: u32,
    node_count: u32,
    node_size: u32,
    buffer: *mut u8,
    mut transfer: impl FnMut(u32, *mut u8) -> i32,
) -> i32 {
    iram_memzero_veneer(buffer, node_size as usize);
    buffer.add(8).write(2);
    buffer.add(10).cast::<u16>().write(bswap16(1) as u16);
    buffer.add(node_size as usize - 2).cast::<u16>().write(bswap16(14) as u16);
    buffer.add(node_size as usize - 4).cast::<u16>().write(bswap16(node_size.wrapping_sub(6)) as u16);
    let mut index = 0u32;
    while index < node_count {
        let next_index = index.wrapping_add(1);
        let link = if next_index < node_count {
            previous_node = previous_node.wrapping_add(1);
            bswap32(previous_node)
        } else { 0 };
        __rt_uwrite4(buffer, link);
        let status = transfer(block, buffer);
        if status != 0 { return status; }
        block = block.wrapping_add(node_size >> 9);
        index = next_index & !0x10000;
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn expected(size: usize, link: u32) -> std::vec::Vec<u8> {
        let mut node = std::vec![0; size];
        node[..4].copy_from_slice(&link.to_be_bytes());
        node[8] = 2;
        node[10..12].copy_from_slice(&1u16.to_be_bytes());
        node[size - 2..].copy_from_slice(&14u16.to_be_bytes());
        node[size - 4..size - 2].copy_from_slice(&((size as u32 - 6) as u16).to_be_bytes());
        node
    }

    #[test]
    fn empty_chain_initializes_node_without_reading_geometry() {
        let mut buffer = [0xffff_ffffu32; 128];
        let status = unsafe {
            storage_write_btree_map_nodes(core::ptr::null(), 7, 9, 0, 512, buffer.as_mut_ptr().cast())
        };
        assert_eq!(status, 0);
        assert_eq!(unsafe { core::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 512) }, expected(512, 0));
    }

    #[test]
    fn chain_links_and_blocks_wrap_and_final_link_is_zero() {
        for size in [512usize, 1024, 65536] {
            let mut buffer = std::vec![0xffff_ffffu32; size / 4 + 1];
            let mut calls = 0;
            let status = unsafe { write_map_nodes(u32::MAX, u32::MAX - 1, 3, size as u32,
                buffer.as_mut_ptr().cast(), |block, data| {
                    assert_eq!(block, u32::MAX.wrapping_add(calls * (size as u32 >> 9)));
                    let link = if calls == 0 { u32::MAX } else { 0 };
                    assert_eq!(core::slice::from_raw_parts(data, size), expected(size, link));
                    calls += 1;
                    0
                }) };
            assert_eq!(status, 0);
            assert_eq!(calls, 3);
            assert_eq!(buffer[size / 4], u32::MAX);
        }
    }

    #[test]
    fn error_stops_before_next_node_and_preserves_failed_node_link() {
        let mut buffer = [0xffff_ffffu32; 128];
        let mut calls = 0;
        let status = unsafe { write_map_nodes(17, 40, 4, 512, buffer.as_mut_ptr().cast(), |block, data| {
            assert_eq!(block, 17 + calls);
            assert_eq!(core::slice::from_raw_parts(data, 512), expected(512, 41 + calls));
            calls += 1;
            if calls == 2 { -7 } else { 0 }
        }) };
        assert_eq!(status, -7);
        assert_eq!(calls, 2);
    }

    #[test]
    fn single_node_has_no_forward_link_and_uses_real_transfer_validation() {
        let geometry = StorageTransferGeometry { block_size: 1024, base_block: 0 };
        let mut buffer = [0xffff_ffffu32; 128];
        let status = unsafe { storage_write_btree_map_nodes(&geometry, 7, 9, 1, 512, buffer.as_mut_ptr().cast()) };
        assert_eq!(status, 0x50);
        assert_eq!(unsafe { core::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), 512) }, expected(512, 0));
    }
}
