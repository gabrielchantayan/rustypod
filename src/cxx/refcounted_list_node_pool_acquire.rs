//! Refcounted-list node-pool acquire — original: `FUN_083dc120` at load
//! address `0x083dc120`.
//!
//! Raw `osos.dec` establishes the true 184-byte extent: 46 ARM words from
//! `push {r4-r8,lr}` at `0x083dc120` through `pop {r4-r8,pc}` at
//! `0x083dc1d4`; `0x083dc1d8` begins the next real function. The body has
//! exactly two unconditional plain `bl` calls, both to `operator_new_checked`
//! @ `0x08266c70`, and no predicated `bl` calls.
//!
//! This acquires an uninitialized 12-byte `{next, previous, value}` node from
//! a free list or a bump chunk. A `single` request allocates one node; ordinary
//! chunks start at 32 nodes then grow by `max(capacity + 32, capacity +
//! capacity/2 + capacity/8)`. Deliberate deviations: the original's dead
//! second allocator argument is omitted; pointers remain target-width `u32`
//! words so host pointer width cannot alter the layout.

use crate::cxx::word_list_node_pool_acquire::{WordListNode, WordListNodePool};
use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x0c;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RefcountedListNodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RefcountedListNodePoolChunk, capacity)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RefcountedListNodePoolChunk, nodes)];
const _: [u8; 0x0c] = [0; core::mem::size_of::<RefcountedListNodePoolChunk>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 {
    pointer as usize as u32
}

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut WordListNode {
    word as usize as *mut WordListNode
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut RefcountedListNodePoolChunk {
    word as usize as *mut RefcountedListNodePoolChunk
}

/// Acquires an uninitialized node from `pool`; `single != 0` forces a
/// one-node chunk, matching the refcounted-list sentinel constructor.
///
/// # Safety
///
/// `pool` and all target pointer words it contains must designate writable,
/// correctly aligned pool objects. The checked allocator is dereferenced
/// immediately, as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.refcounted_list_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn refcounted_list_node_pool_acquire(
    pool: *mut WordListNodePool,
    single: u32,
) -> *mut WordListNode {
    if (*pool).free != 0 {
        let free = node_from_word((*pool).free);
        (*pool).free = (*free).next;
        return free;
    }

    if (*pool).next == (*pool).end {
        let capacity = if single != 0 {
            1
        } else if (*pool).chunks == 0 {
            INITIAL_CAPACITY
        } else {
            let previous_capacity = (*chunk_from_word((*pool).chunks)).capacity;
            core::cmp::max(
                previous_capacity + INITIAL_CAPACITY,
                previous_capacity + (previous_capacity >> 1) + (previous_capacity >> 3),
            )
        };
        let chunk = operator_new_checked(core::mem::size_of::<RefcountedListNodePoolChunk>())
            as *mut RefcountedListNodePoolChunk;
        let nodes = operator_new_checked(capacity as usize * NODE_SIZE);

        (*chunk).nodes = pointer_word(nodes);
        (*chunk).previous = (*pool).chunks;
        (*chunk).capacity = capacity;
        (*pool).chunks = pointer_word(chunk.cast());
        (*pool).next = pointer_word(nodes);
        (*pool).end = pointer_word(nodes.add(capacity as usize * NODE_SIZE));
    }

    let node = node_from_word((*pool).next);
    (*pool).next = pointer_word(node.cast::<u8>().add(NODE_SIZE));
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

    static mut ALLOCATIONS: [*mut u8; 8] = [ptr::null_mut(); 8];
    static mut ALLOCATION_SIZES: [usize; 8] = [0; 8];
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

    unsafe fn allocation_size(index: usize) -> usize {
        ptr::addr_of!(ALLOCATION_SIZES).cast::<usize>().add(index).read()
    }

    #[test]
    fn acquires_single_free_fresh_and_grown_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::REFCOUNTED_LIST_NODE_POOL_ACQUIRE, 0x8000) else {
            note_missing_u32_fixture("cxx/refcounted_list_node_pool_acquire");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x8000);
            ptr::addr_of_mut!(ALLOCATIONS).write([slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000), slab.add(0x4000), slab.add(0x5000), slab.add(0x6000), slab.add(0x7000)]);
            ALLOCATION_CURSOR = 0;
            ptr::addr_of_mut!(ALLOCATION_SIZES).write([0; 8]);
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let mut pool = WordListNodePool::default();
            let sentinel = refcounted_list_node_pool_acquire(&mut pool, 1);
            assert_eq!(sentinel as *mut u8, slab.add(0x1000));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!(allocation_size(0), 0x0c);
            assert_eq!(allocation_size(1), NODE_SIZE);
            assert_eq!(pool.chunks, pointer_word(slab));
            assert_eq!(pool.next, pointer_word(slab.add(0x1000 + NODE_SIZE)));
            assert_eq!(pool.end, pointer_word(slab.add(0x1000 + NODE_SIZE)));
            let chunk1 = slab.cast::<RefcountedListNodePoolChunk>();
            assert_eq!((*chunk1).previous, 0);
            assert_eq!((*chunk1).capacity, 1);
            assert_eq!((*chunk1).nodes, pointer_word(slab.add(0x1000)));
            assert_eq!((*sentinel).next, 0xa5a5_a5a5);
            assert_eq!((*sentinel).previous, 0xa5a5_a5a5);
            assert_eq!((*sentinel).value, 0xa5a5_a5a5);

            let second_free = slab.add(0x1040).cast::<WordListNode>();
            (*sentinel).next = pointer_word(second_free.cast());
            (*sentinel).previous = 7;
            (*sentinel).value = 3;
            pool.free = pointer_word(sentinel.cast());
            assert_eq!(refcounted_list_node_pool_acquire(&mut pool, 0), sentinel);
            assert_eq!(pool.free, pointer_word(second_free.cast()));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!((*sentinel).previous, 7);
            assert_eq!((*sentinel).value, 3);

            let mut pool = WordListNodePool::default();
            let first = refcounted_list_node_pool_acquire(&mut pool, 0);
            assert_eq!(first as *mut u8, slab.add(0x3000));
            assert_eq!(ALLOCATION_CURSOR, 4);
            assert_eq!(allocation_size(2), 0x0c);
            assert_eq!(allocation_size(3), INITIAL_CAPACITY as usize * NODE_SIZE);
            let chunk32 = slab.add(0x2000).cast::<RefcountedListNodePoolChunk>();
            assert_eq!((*chunk32).capacity, INITIAL_CAPACITY);
            assert_eq!(pool.next, pointer_word(slab.add(0x3000 + NODE_SIZE)));

            pool.next = pool.end;
            let grown = refcounted_list_node_pool_acquire(&mut pool, 0);
            assert_eq!(grown as *mut u8, slab.add(0x5000));
            assert_eq!(ALLOCATION_CURSOR, 6);
            assert_eq!(allocation_size(5), 64 * NODE_SIZE);
            let chunk64 = slab.add(0x4000).cast::<RefcountedListNodePoolChunk>();
            assert_eq!((*chunk64).previous, pointer_word(chunk32.cast()));
            assert_eq!((*chunk64).capacity, 64);

            pool.next = pool.end;
            let geometric = refcounted_list_node_pool_acquire(&mut pool, 0);
            assert_eq!(geometric as *mut u8, slab.add(0x7000));
            assert_eq!(ALLOCATION_CURSOR, 8);
            assert_eq!(allocation_size(7), 104 * NODE_SIZE);
            assert_eq!((*slab.add(0x6000).cast::<RefcountedListNodePoolChunk>()).capacity, 104);
        }
    }
}
