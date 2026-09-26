//! `list_node_pool_list_construct` — retailOS `FUN_083dc5f8` @
//! `0x083dc5f8` (72 bytes).
//!
//! Raw `osos.dec` establishes the exact eighteen-word A32 extent from `push
//! {r4,lr}` at 0x083dc5f8 through `pop {r4,pc}` at 0x083dc63c; 0x083dc640
//! starts the next separately linked function. The body has one unconditional
//! plain `bl`, to `list_node_pool_acquire` @ 0x083dc344, and no predicated
//! `bl` calls. Whole-image decoding finds two inbound unconditional plain
//! `bl` sites and no predicated inbound sites.
//!
//! Clears the 24-byte ADS `std::list` header, acquires its one-node sentinel,
//! stores it in the header, and self-links its next and previous words.
//! Deliberate deviations: none; pointers remain target-width words so the
//! header stays 24 bytes on hosts.

use super::list_node_pool_acquire::{list_node_pool_acquire, ListNode, ListNodePool};
use core::ptr::addr_of_mut;

/// Target-layout ADS `std::list` header for 20-byte nodes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListNodePoolList {
    pub pool: ListNodePool,
    pub sentinel: u32,
    pub count: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(ListNodePoolList, sentinel)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(ListNodePoolList, count)];
const _: [u8; 0x18] = [0; core::mem::size_of::<ListNodePoolList>()];

/// Initializes `list` with an empty self-linked sentinel node.
///
/// # Safety
///
/// `list` must point to writable target-layout storage. The configured heap
/// must provide writable target-addressable storage for the sentinel chunk.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_list_construct")]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_list_construct(
    list: *mut ListNodePoolList,
) -> *mut ListNodePoolList {
    addr_of_mut!((*list).pool.chunks).write(0);
    addr_of_mut!((*list).pool.free).write(0);
    addr_of_mut!((*list).pool.next).write(0);
    addr_of_mut!((*list).pool.end).write(0);
    addr_of_mut!((*list).sentinel).write(0);
    addr_of_mut!((*list).count).write(0);
    let sentinel = list_node_pool_acquire(addr_of_mut!((*list).pool), 1);
    let sentinel_word = sentinel as usize as u32;
    addr_of_mut!((*list).sentinel).write(sentinel_word);
    addr_of_mut!((*sentinel).next).write(sentinel_word);
    addr_of_mut!((*sentinel).prev).write(sentinel_word);
    list
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATIONS: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut ALLOCATION_CURSOR: usize = 0;

    unsafe extern "C" fn pool_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        _size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let allocation = ALLOCATIONS[ALLOCATION_CURSOR];
        ALLOCATION_CURSOR += 1;
        allocation
    }

    #[test]
    fn clears_header_and_self_links_a_fresh_sentinel() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_LIST_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture("cxx/list_node_pool_list_construct");
            return;
        };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<ListNodePoolList>();
            let chunk = slab.add(0x200);
            let sentinel = slab.add(0x300).cast::<ListNode>();
            ALLOCATIONS = [chunk, sentinel.cast()];
            ALLOCATION_CURSOR = 0;
            let _heap = crate::heap::veneers::tests::mock_heap();
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            assert_eq!(list_node_pool_list_construct(list), list);
            assert_eq!(((*list).pool.free, (*list).count), (0, 0));
            assert_eq!(((*list).pool.next, (*list).pool.end),
                (sentinel as usize as u32 + 20, sentinel as usize as u32 + 20));
            assert_eq!(((*list).sentinel, (*sentinel).next, (*sentinel).prev),
                (sentinel as usize as u32, sentinel as usize as u32, sentinel as usize as u32));
            assert_eq!(ALLOCATION_CURSOR, 2);
        }
    }
}
