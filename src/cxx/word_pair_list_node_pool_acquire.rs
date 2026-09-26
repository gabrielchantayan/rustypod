//! `word_pair_list_node_pool_acquire` — retailOS `FUN_083dce90` @ `0x083dce90`.
//!
//! Raw `osos.dec` establishes the true 176-byte extent: 44 A32 words from
//! `push {r4-r6,lr}` through `pop {r4-r6,pc}` at `0x083dcf3c`; `0x083dcf40`
//! begins the next real function. The body has exactly two unconditional plain
//! `bl` calls, both to `operator_new_checked` @ `0x08266c70`, and no predicated
//! `bl` calls.
//!
//! The helper pops an uninitialized 16-byte `{next, previous, first, second}`
//! node from `list.free`, or bump-allocates one from a chunk. Empty pools
//! allocate a 12-byte `{previous, capacity, nodes}` chunk header and a
//! `capacity * 16` node arena. `single != 0` requests one node; otherwise the
//! first capacity is 32 and later capacities are `max(old + 32, old + old/2 +
//! old/8)`. Deliberate deviations: none; object pointers remain target-width
//! `u32` words.

use super::word_pair_list_copy_construct::{WordPairList, WordPairListNode};
use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = core::mem::size_of::<WordPairListNode>();

#[repr(C)]
struct WordPairListNodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x0c] = [0; core::mem::size_of::<WordPairListNodePoolChunk>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut WordPairListNode {
    word as usize as *mut WordPairListNode
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut WordPairListNodePoolChunk {
    word as usize as *mut WordPairListNodePoolChunk
}

/// Acquires an uninitialized pair node from `list`.
///
/// # Safety
///
/// `list` must be writable, and all nonzero target pointer words in its pool
/// state must designate valid target-layout nodes or chunks. The checked
/// allocator's returned storage is immediately written, as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.word_pair_list_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn word_pair_list_node_pool_acquire(
    list: *mut WordPairList,
    single: u32,
) -> *mut WordPairListNode {
    if (*list).free != 0 {
        let node = node_from_word((*list).free);
        (*list).free = (*node).next;
        return node;
    }

    if (*list).next == (*list).end {
        let capacity = if single != 0 {
            1
        } else if (*list).chunks == 0 {
            INITIAL_CAPACITY
        } else {
            let previous_capacity = (*chunk_from_word((*list).chunks)).capacity;
            core::cmp::max(
                previous_capacity.wrapping_add(INITIAL_CAPACITY),
                previous_capacity
                    .wrapping_add(previous_capacity >> 1)
                    .wrapping_add(previous_capacity >> 3),
            )
        };
        let chunk = operator_new_checked(core::mem::size_of::<WordPairListNodePoolChunk>())
            as *mut WordPairListNodePoolChunk;
        let nodes = operator_new_checked(capacity as usize * NODE_SIZE);

        (*chunk).nodes = pointer_word(nodes);
        (*chunk).previous = (*list).chunks;
        (*chunk).capacity = capacity;
        (*list).chunks = pointer_word(chunk.cast());
        (*list).next = pointer_word(nodes);
        (*list).end = pointer_word(nodes.add(capacity as usize * NODE_SIZE));
    }

    let node = node_from_word((*list).next);
    (*list).next = pointer_word(node.cast::<u8>().add(NODE_SIZE));
    node
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    static mut ALLOCATIONS: [*mut u8; 6] = [ptr::null_mut(); 6];
    static mut ALLOCATION_SIZES: [usize; 6] = [0; 6];
    static mut ALLOCATION_CURSOR: usize = 0;

    unsafe extern "C" fn pool_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let index = ALLOCATION_CURSOR;
        ALLOCATION_CURSOR += 1;
        ptr::addr_of_mut!(ALLOCATION_SIZES).cast::<usize>().add(index).write(size);
        ptr::addr_of!(ALLOCATIONS).cast::<*mut u8>().add(index).read()
    }

    #[test]
    fn acquires_free_single_initial_and_grown_pair_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::WORD_PAIR_LIST_NODE_POOL_ACQUIRE, 0x8000) else {
            note_missing_u32_fixture("cxx/word_pair_list_node_pool_acquire");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x8000);
            ptr::addr_of_mut!(ALLOCATIONS).write([
                slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000),
                slab.add(0x4000), slab.add(0x5000),
            ]);
            ALLOCATION_CURSOR = 0;
            ptr::addr_of_mut!(ALLOCATION_SIZES).write([0; 6]);
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let mut list = WordPairList::default();
            let single = word_pair_list_node_pool_acquire(&mut list, 1);
            assert_eq!(single.cast::<u8>(), slab.add(0x1000));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!(ALLOCATION_SIZES, [0x0c, NODE_SIZE, 0, 0, 0, 0]);
            assert_eq!((*single).first, 0xa5a5_a5a5);
            assert_eq!((*single).second, 0xa5a5_a5a5);
            assert_eq!(list.next, pointer_word(slab.add(0x1000 + NODE_SIZE)));
            assert_eq!(list.end, pointer_word(slab.add(0x1000 + NODE_SIZE)));

            let free_next = slab.add(0x1040).cast::<WordPairListNode>();
            (*single).next = pointer_word(free_next.cast());
            (*single).second = 7;
            list.free = pointer_word(single.cast());
            assert_eq!(word_pair_list_node_pool_acquire(&mut list, 0), single);
            assert_eq!(list.free, pointer_word(free_next.cast()));
            assert_eq!((*single).second, 7);
            assert_eq!(ALLOCATION_CURSOR, 2);

            let mut list = WordPairList::default();
            assert_eq!(word_pair_list_node_pool_acquire(&mut list, 0).cast::<u8>(), slab.add(0x3000));
            assert_eq!(ALLOCATION_SIZES[2], 0x0c);
            assert_eq!(ALLOCATION_SIZES[3], 32 * NODE_SIZE);
            list.next = list.end;
            assert_eq!(word_pair_list_node_pool_acquire(&mut list, 0).cast::<u8>(), slab.add(0x5000));
            assert_eq!(ALLOCATION_SIZES[4], 0x0c);
            assert_eq!(ALLOCATION_SIZES[5], 64 * NODE_SIZE);
            let grown = slab.add(0x4000).cast::<WordPairListNodePoolChunk>();
            assert_eq!((*grown).previous, pointer_word(slab.add(0x2000)));
            assert_eq!((*grown).capacity, 64);
        }
    }
}
