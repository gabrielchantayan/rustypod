//! Acquire a red-black-tree node with 12-byte payload at `0x083b6d00`.
//!
//! Raw extent: 184 bytes, [0x083b6d00, 0x083b6db8); the next function
//! starts with `ldr r2,[r1,#12]`. Two plain BLs at 0x083b6d64 and
//! 0x083b6d78 target checked new (0x08266c70); no predicated BLs.
//! One incoming plain BL at 0x08212220; its caller uses the returned r0.
//!
//! Pop the +12-threaded free list before using the bump arena. On exhaustion,
//! allocate a 12-byte chunk and 28-byte nodes, initially 32, then
//! max(old+32, old+old/2+old/8) with wrapping u32 arithmetic. Clear the
//! color byte and three links, leaving padding and payload untouched.
//! Deliberate deviations: delegate the identical algorithm to the existing
//! 0x083b73f0 port rather than duplicate it. This introduces a tail branch
//! instead of a second allocation body; pointers retain target-width layout
//! and the dead allocator r1 argument is omitted by the canonical port.

use super::red_black_tree_payload_12_node_pool_acquire_083b73f0::{
    red_black_tree_payload_12_node_pool_acquire_083b73f0,
    RedBlackTreePayload12Node083b73f0, RedBlackTreePayload12NodePool083b73f0,
};

/// Acquire a node, preserving its payload and padding.
///
/// # Safety
/// All pool pointers must denote valid, aligned target-addressable storage;
/// the allocator must supply writable chunk and node buffers on exhaustion.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_12_node_pool_acquire_083b6d00(
    pool: *mut RedBlackTreePayload12NodePool083b73f0,
) -> *mut RedBlackTreePayload12Node083b73f0 {
    red_black_tree_payload_12_node_pool_acquire_083b73f0(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    static mut BASE: *mut u8 = ptr::null_mut();
    static mut CALLS: usize = 0;
    static mut SIZES: [usize; 6] = [0; 6];

    unsafe extern "C" fn allocate(
        _heap: *mut HeapDescriptorDescriptor, size: usize, _tag: usize,
    ) -> *mut u8 {
        let index = CALLS;
        assert!(index < 6);
        SIZES[index] = size;
        CALLS += 1;
        BASE.add(index * 0x2000)
    }

    #[test]
    fn free_precedes_arena_and_growth_preserves_storage() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(
            hints::RED_BLACK_TREE_PAYLOAD_12_NODE_POOL_ACQUIRE_083B6D00, 0xc000,
        ) else {
            note_missing_u32_fixture("cxx/red_black_tree_payload_12_node_pool_acquire_083b6d00");
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0xa5, 0xc000);
            BASE = slab; CALLS = 0; SIZES = [0; 6];
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = allocate;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            let mut pool = RedBlackTreePayload12NodePool083b73f0::default();
            let first = red_black_tree_payload_12_node_pool_acquire_083b6d00(&mut pool);
            assert_eq!(first.cast::<u8>(), slab.add(0x2000));
            assert_eq!(SIZES[..2], [12, 32 * 28]);
            assert_eq!(pool.end, first as u32 + 32 * 28);
            assert_eq!((*first).payload, [0xa5a5a5a5; 3]);
            assert_eq!(core::slice::from_raw_parts(first.cast::<u8>().add(1), 3), &[0xa5; 3]);
            let second = red_black_tree_payload_12_node_pool_acquire_083b6d00(&mut pool);
            assert_eq!(second as usize, first as usize + 28);
            let cursor = pool.next;
            (*first).color = 7; (*first).parent = 8; (*first).left = 9;
            (*first).right = second as u32;
            pool.free = first as u32;
            assert_eq!(red_black_tree_payload_12_node_pool_acquire_083b6d00(&mut pool), first);
            assert_eq!(pool.free, second as u32);
            assert_eq!(pool.next, cursor);
            assert_eq!((*first).color, 0);
            assert_eq!([(*first).parent, (*first).left, (*first).right], [0; 3]);
            assert_eq!((*first).payload, [0xa5a5a5a5; 3]);
            assert_eq!(CALLS, 2);
            pool.free = 0; pool.next = pool.end;
            let grown = red_black_tree_payload_12_node_pool_acquire_083b6d00(&mut pool);
            assert_eq!(grown.cast::<u8>(), slab.add(0x6000));
            assert_eq!(SIZES[2..4], [12, 64 * 28]);
            assert_eq!(*slab.add(0x4000).cast::<u32>(), slab as u32);
            pool.next = pool.end;
            let grown_again = red_black_tree_payload_12_node_pool_acquire_083b6d00(&mut pool);
            assert_eq!(grown_again.cast::<u8>(), slab.add(0xa000));
            assert_eq!(SIZES[4..6], [12, 104 * 28]);
            assert_eq!(pool.end, grown_again as u32 + 104 * 28);
            assert_eq!(*slab.add(0x8000).cast::<u32>(), slab.add(0x4000) as u32);
        }
    }
}
