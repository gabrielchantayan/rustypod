//! Event-list tree node clone — `FUN_083c1580` @ `0x083c1580`.
//!
//! True raw extent: 200 bytes, through the return at 0x083c1644, before
//! the next prologue at 0x083c1648. Five outbound plain BLs, zero predicated
//! BLs; one inbound plain BL at 0x083c1ebc, zero predicated inbound BLs.
//! Acquires a 24-byte-payload node, COW-copies its two strings, clears the
//! vector bounds, allocates max(unsigned(signed byte difference >> 4), 32)
//! 16-byte entries, constructs the range, recomputes end, and copies the flag.
//! Deliberate deviations: dead r2/r3 spills are omitted. Host string copies
//! use native-pointer locals around target-width fields. The existing range
//! seam retains the unported retail element constructor; no new seam is added.

use crate::cxx::red_black_tree_payload_24_node_pool_acquire::{
    red_black_tree_payload_24_node_pool_acquire, RedBlackTreePayload24Node,
    RedBlackTreePayload24NodePool,
};
use crate::cxx::string::cxx_string_copy_ctor;
use crate::cxx::templates::{vector_copy_construct_range_elem16_alt, VectorStorage};
use crate::heap::new_handler::operator_new_checked;

#[inline(always)]
unsafe fn entry_count(bounds: *const u32) -> u32 {
    ((bounds.add(1).read().wrapping_sub(bounds.read()) as i32) >> 4) as u32
}

/// Clones the two-string/vector/flag payload into a newly acquired node.
///
/// # Safety
/// Pool and source must be aligned, valid target-layout objects. Strings must
/// be valid COW representations and vector bounds must delimit readable whole
/// 16-byte entries. Allocations must satisfy the retail constructors' contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_list_tree_node_clone(
    pool: *mut RedBlackTreePayload24NodePool, source: *const u8,
) -> *mut RedBlackTreePayload24Node {
    let node = red_black_tree_payload_24_node_pool_acquire(pool);
    let destination = (node as usize).wrapping_add(16) as *mut u8;
    if destination.is_null() { return node; }
    for offset in [0, 4] {
        #[cfg(target_os = "none")]
        { cxx_string_copy_ctor(destination.add(offset).cast(), source.add(offset).cast()); }
        #[cfg(not(target_os = "none"))]
        {
            let string = source.add(offset).cast::<u32>().read() as usize as *mut u8;
            let mut copied = core::ptr::null_mut();
            cxx_string_copy_ctor(&mut copied, &string);
            destination.add(offset).cast::<u32>().write(copied as usize as u32);
        }
    }
    let bounds = destination.add(8).cast::<u32>();
    bounds.write(0);
    bounds.add(1).write(0);
    bounds.add(2).write(0);
    let source_bounds = source.add(8).cast::<u32>();
    let capacity = core::cmp::max(entry_count(source_bounds), 32);
    let allocation = operator_new_checked(capacity.wrapping_shl(4) as usize);
    bounds.write(allocation as usize as u32);
    vector_copy_construct_range_elem16_alt(
        source_bounds.read() as usize as *const u8,
        source_bounds.add(1).read() as usize as *const u8,
        allocation, bounds.cast::<VectorStorage>(),
    );
    let begin = bounds.read();
    bounds.add(1).write(begin.wrapping_add(entry_count(source_bounds).wrapping_shl(4)));
    bounds.add(2).write(begin.wrapping_add(capacity.wrapping_shl(4)));
    destination.add(20).write(source.add(20).read());
    node
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::veneers::tests::{alloc_log, mock_heap, set_alloc_ret};

    #[test]
    fn recycled_node_shares_both_strings_reserves_empty_vector_and_preserves_padding() {
        let _heap = mock_heap();
        unsafe {
            let Some(slab) = crate::testing::try_map_u32_slab(
                crate::testing::hints::EVENT_LIST_TREE_NODE_CLONE, 0x1000,
            ) else { assert!(crate::testing::note_missing_u32_fixture("event_list_tree_node_clone")); return; };
            let node = slab.add(0x100).cast::<RedBlackTreePayload24Node>();
            core::ptr::write_bytes(node.cast::<u8>(), 0xcc, 40);
            (*node).right = 0;
            let mut source = [0u32; 6];
            for (index, offset) in [0usize, 0x40].into_iter().enumerate() {
                let rep = slab.add(offset);
                rep.cast::<u32>().write(0);
                rep.add(4).cast::<u32>().write(0);
                rep.add(8).cast::<u32>().write(0);
                rep.add(12).write(0);
                source[index] = rep.add(12) as usize as u32;
            }
            source[5] = 0x4433_22a7;
            let mut pool = RedBlackTreePayload24NodePool {
                free: node as usize as u32, ..Default::default()
            };
            set_alloc_ret(slab.add(0x400));
            assert_eq!(event_list_tree_node_clone(&mut pool, source.as_ptr().cast()), node);
            let payload = (*node).payload.as_ptr().cast::<u32>();
            assert_eq!(payload.read(), source[0]);
            assert_eq!(payload.add(1).read(), source[1]);
            let begin = slab.add(0x400) as usize as u32;
            assert_eq!(payload.add(2).read(), begin);
            assert_eq!(payload.add(3).read(), begin);
            assert_eq!(payload.add(4).read(), begin + 512);
            assert_eq!(payload.add(5).read(), 0xcccc_cca7);
            assert_eq!(slab.cast::<u32>().read(), 1);
            assert_eq!(slab.add(0x40).cast::<u32>().read(), 1);
            assert_eq!(((*node).color, (*node).parent, (*node).left, (*node).right), (0, 0, 0, 0));
            assert_eq!(pool.free, 0);
        }
        assert_eq!(alloc_log(), (1, 512, 2));
    }

    #[test]
    fn signed_difference_unsigned_capacity_boundaries() {
        unsafe {
            for (begin, end, count) in [(0x1000, 0x11f0, 31), (0x1000, 0x1200, 32),
                (0x1000, 0x1210, 33), (0xffff_fff0, 0x10, 2), (0x1010, 0x1000, u32::MAX)] {
                let actual = entry_count([begin, end].as_ptr());
                assert_eq!(actual, count);
                assert_eq!(core::cmp::max(actual, 32), if count < 32 { 32 } else { count });
            }
        }
    }
}
