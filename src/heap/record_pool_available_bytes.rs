//! Record-pool available byte capacity.
//!
//! Original: `FUN_081a8514` @ **0x081a8514**, **80 bytes** through
//! 0x081a8564 (the next real function). Raw words verify two inbound plain
//! BL sites, zero predicated BL sites, and five outbound plain BL instructions.
//! Lock pool+0x28, dereference its optional client handle, query available
//! blocks, sum body sizes in the sentinel list, then add the wrapping product
//! of available blocks and (region block size - 16). Unlock before returning.
//!
//! Deliberate deviations: inline the verified list sum at 0x081a84dc rather
//! than introduce a firmware seam; its nodes use record_body_size(node, 4).
//! Use existing REGION_MUTEX_OPS and block-manager global modeling. Mutex
//! results are ignored, and all arithmetic retains ARM low-word wrapping.

use crate::heap::block_region::REGION_MUTEX_OPS;
use crate::heap::block_mgr::region_block_size;
use crate::heap::client_available_blocks::client_available_blocks;
use crate::util::record_body_size::record_body_size;
use core::ptr;

/// Available byte capacity; the pool and its list must be valid. A NULL handle
/// is forwarded as a NULL client, exactly as retailOS (not a safe empty pool).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_pool_available_bytes(pool: *mut u32) -> u32 {
    let mutex = pool.add(10).cast::<u8>();
    (ptr::read_volatile(ptr::addr_of!(REGION_MUTEX_OPS.lock)))(mutex);
    let handle = pool.read() as usize as *const u32;
    let client = if handle.is_null() { 0 } else { handle.read() };
    let blocks = client_available_blocks(client as usize as *mut u8) as u32;
    let sentinel = pool.add(1);
    let mut node = pool.add(2).read() as usize as *const u32;
    let mut bytes = 0u32;
    while node != sentinel {
        bytes = bytes.wrapping_add(record_body_size(node, 4));
        node = node.add(1).read() as usize as *const u32;
    }
    let result = region_block_size().wrapping_sub(16).wrapping_mul(blocks).wrapping_add(bytes);
    (ptr::read_volatile(ptr::addr_of!(REGION_MUTEX_OPS.unlock)))(mutex);
    result
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::block_mgr::BLOCK_MANAGER;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn empty_and_linked_capacity_preserve_signed_counts_and_low_word_arithmetic() {
        let _guard = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = try_map_u32_slab(hints::RECORD_POOL_AVAILABLE_BYTES, 0x1000) else {
            assert!(note_missing_u32_fixture("heap/record_pool_available_bytes"));
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let pool = slab.cast::<u32>();
            let handle = slab.add(0x100).cast::<u32>();
            let client = slab.add(0x200).cast::<u32>();
            let manager = slab.add(0x400);
            let first = slab.add(0x800).cast::<u32>();
            let second = slab.add(0x820).cast::<u32>();
            pool.write(handle as u32);
            handle.write(client as u32);
            client.add(1).write(manager as u32);
            // Reservation path avoids capping at manager availability.
            client.add(0x44 / 4).write(0x40000);
            let saved_manager = BLOCK_MANAGER;
            BLOCK_MANAGER = manager;
            for (block_size, produced, end) in [(512u32, 3u32, 10u32), (16, 0, 8), (0, 0, 1), (15, 0, 2), (u32::MAX, 0, 0x80000001), (512, 9, 4)] {
                manager.add(0x30).cast::<u32>().write(block_size);
                client.add(0x18 / 4).write(produced);
                client.add(0x50 / 4).write(end);
                let base = block_size.wrapping_sub(16).wrapping_mul(end.wrapping_sub(produced));
                pool.add(2).write(pool.add(1) as u32);
                assert_eq!(record_pool_available_bytes(pool), base);
                first.write(0xff00_0011);
                first.add(1).write(second as u32);
                second.write(0x80ff_ffff);
                second.add(1).write(pool.add(1) as u32);
                pool.add(2).write(first as u32);
                assert_eq!(record_pool_available_bytes(pool), base.wrapping_add(0x0100_0010));
                assert_eq!(first.read(), 0xff00_0011);
                assert_eq!(second.read(), 0x80ff_ffff);
            }
            BLOCK_MANAGER = saved_manager;
        }
    }
}
