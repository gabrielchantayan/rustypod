//! `word_pair_list_sentinel_initialize` — retailOS `FUN_083dd0bc` @
//! `0x083dd0bc` (32 bytes).
//!
//! Raw `osos.dec` establishes the exact eight-word A32 extent from `push
//! {r4,lr}` at 0x083dd0bc through `pop {r4,pc}` at 0x083dd0d8; 0x083dd0dc
//! starts `word_pair_list_copy_construct`. The body makes one unconditional
//! plain `bl` to the 16-byte pair-node-pool acquire helper @ 0x083dce90 and
//! no predicated `bl` calls. Whole-image decoding finds two inbound plain
//! `bl` sites and no predicated inbound sites.
//!
//! Acquires a node using `single`, publishes it as `list.sentinel`, then
//! self-links its next and previous words. The original returns the acquired
//! node in r0 despite its known callers discarding that value. Deliberate
//! deviations: target builds retain the verified retail pool-acquire seam;
//! host builds use the existing equivalent implementation shared by the
//! pair-list copy constructor.

#[cfg(not(target_os = "none"))]
use super::word_pair_list_copy_construct::acquire_node;
use super::word_pair_list_copy_construct::{WordPairList, WordPairListNode};
use core::ptr::addr_of_mut;
#[cfg(target_os = "none")]
unsafe fn acquire_node(list: *mut WordPairList, single: u32) -> *mut WordPairListNode {
    let acquire: unsafe extern "C" fn(*mut WordPairList, u32) -> *mut WordPairListNode =
        core::mem::transmute(0x083d_ce90usize);
    acquire(list, single)
}

/// Acquires and self-links the sentinel node for a pair-valued intrusive list.
///
/// # Safety
///
/// `list` must point to a writable target-layout list owner. Its node-pool
/// state must be valid, and when its free list and bump range are exhausted,
/// the configured heap must return target-addressable writable storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_pair_list_sentinel_initialize")]
#[inline(never)]
pub unsafe extern "C" fn word_pair_list_sentinel_initialize(
    list: *mut WordPairList,
    single: u32,
) -> *mut WordPairListNode {
    let sentinel = acquire_node(list, single);
    let sentinel_word = sentinel as usize as u32;
    addr_of_mut!((*list).sentinel).write(sentinel_word);
    addr_of_mut!((*sentinel).next).write(sentinel_word);
    addr_of_mut!((*sentinel).previous).write(sentinel_word);
    sentinel
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
    fn reuses_a_free_node_and_initializes_a_single_node_pool_sentinel() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::WORD_PAIR_LIST_SENTINEL_INITIALIZE, 0x1000) else {
            note_missing_u32_fixture("cxx/word_pair_list_sentinel_initialize");
            return;
        };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let reused_list = slab.cast::<WordPairList>();
            let reused_node = slab.add(0x100).cast::<WordPairListNode>();
            let next_free = slab.add(0x120).cast::<WordPairListNode>();
            (*reused_list).free = reused_node as usize as u32;
            (*reused_node).next = next_free as usize as u32;

            assert_eq!(word_pair_list_sentinel_initialize(reused_list, 0), reused_node);
            assert_eq!((*reused_list).free, next_free as usize as u32);
            assert_eq!(((*reused_list).sentinel, (*reused_node).next, (*reused_node).previous),
                (reused_node as usize as u32, reused_node as usize as u32, reused_node as usize as u32));

            let fresh_list = slab.add(0x200).cast::<WordPairList>();
            let chunk = slab.add(0x400);
            let node = slab.add(0x500).cast::<WordPairListNode>();
            ALLOCATIONS = [chunk, node.cast()];
            ALLOCATION_CURSOR = 0;
            let _heap = crate::heap::veneers::tests::mock_heap();
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            assert_eq!(word_pair_list_sentinel_initialize(fresh_list, 1), node);
            assert_eq!(((*fresh_list).next, (*fresh_list).end),
                (node as usize as u32 + 16, node as usize as u32 + 16));
            assert_eq!(((*fresh_list).sentinel, (*node).next, (*node).previous),
                (node as usize as u32, node as usize as u32, node as usize as u32));
            assert_eq!(ALLOCATION_CURSOR, 2);
        }
    }
}
