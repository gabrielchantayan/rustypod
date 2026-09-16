//! Doubly-linked-list node-pool acquire — original: `FUN_083dc344` at load
//! address `0x083dc344`.
//!
//! Raw `osos.dec` establishes the exact 184-byte extent: 46 ARM words from
//! `push {r4-r6,lr}` at `0x083dc344` through `pop {r4-r6,pc}` at
//! `0x083dc3f8`; the separately linked list-erase sibling begins at
//! `0x083dc3fc`. Decoding every aligned ARM B/BL-immediate word in
//! `osos.dec` finds exactly four inbound direct calls, all unconditional
//! `bl` at `0x0811f0ec`, `0x0811f394`, `0x083dc578`, and `0x083dc624`;
//! there are no predicated direct calls. The body itself performs two
//! unconditional `bl` calls, both to `operator_new_checked` @ `0x08266c70`.
//!
//! The pool serves the ADS `std::list` node: 20 bytes of
//! `{next, prev, payload[3]}`. It first removes a node from its free list
//! (the free link lives in the node's `next` word). Otherwise it advances
//! through its current 20-byte node chunk, allocating a new 12-byte chunk
//! header and backing chunk when exhausted. When `single` is nonzero the new
//! chunk holds exactly one node (the list constructor's sentinel acquire);
//! otherwise the first chunk has 32 nodes and later chunks grow by
//! `max(capacity + 32, capacity + capacity/2 + capacity/8)`. The returned
//! node is handed back uninitialized: no link or payload word is cleared.
//!
//! Deliberate deviations: none. Pointers in the firmware objects remain `u32`
//! target words so their 32-bit layout is preserved on the host. As in
//! retailOS, a failed checked allocation is immediately dereferenced rather
//! than handled.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x14;

/// A 20-byte doubly-linked-list node with a 12-byte caller payload.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListNode {
    pub next: u32,
    pub prev: u32,
    pub payload: [u32; 3],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(ListNode, prev)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ListNode, payload)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<ListNode>()];

/// Heap header prepended to each pool chunk.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ListNodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(ListNodePoolChunk, capacity)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ListNodePoolChunk, nodes)];
const _: [u8; 0x0c] = [0; core::mem::size_of::<ListNodePoolChunk>()];

/// The target-width node-pool state consumed by [`list_node_pool_acquire`].
/// It occupies the first 16 bytes of the 24-byte list header (the sentinel
/// head and node count words follow and are not touched here).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListNodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(ListNodePool, free)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ListNodePool, next)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(ListNodePool, end)];
const _: [u8; 0x10] = [0; core::mem::size_of::<ListNodePool>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 {
    pointer as usize as u32
}

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut ListNode {
    word as usize as *mut ListNode
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut ListNodePoolChunk {
    word as usize as *mut ListNodePoolChunk
}

/// Acquires one node from `pool`. `single != 0` forces a one-node chunk,
/// matching the list constructor's sentinel allocation.
///
/// Original: `FUN_083dc344` at load address `0x083dc344` (184 bytes; four
/// unconditional inbound `bl` sites).
///
/// # Safety
///
/// `pool` must point to a writable [`ListNodePool`]. Existing pool words
/// must describe valid aligned chunks and nodes. The checked allocator is
/// assumed to return writable storage, matching the retail routine's
/// immediate dereference of both allocation results.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_acquire(
    pool: *mut ListNodePool,
    single: u32,
) -> *mut ListNode {
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
            let previous = chunk_from_word((*pool).chunks);
            let previous_capacity = (*previous).capacity;
            let geometric_capacity =
                previous_capacity + (previous_capacity >> 1) + (previous_capacity >> 3);
            core::cmp::max(previous_capacity + INITIAL_CAPACITY, geometric_capacity)
        };
        let chunk = operator_new_checked(core::mem::size_of::<ListNodePoolChunk>())
            as *mut ListNodePoolChunk;
        let nodes = operator_new_checked(capacity as usize * NODE_SIZE);

        (*chunk).nodes = pointer_word(nodes);
        (*chunk).previous = (*pool).chunks;
        (*chunk).capacity = capacity;
        (*pool).chunks = pointer_word(chunk.cast());
        (*pool).end = pointer_word(nodes.add(capacity as usize * NODE_SIZE));
        (*pool).next = pointer_word(nodes);
    }

    let next = node_from_word((*pool).next);
    (*pool).next = pointer_word(next.cast::<u8>().add(NODE_SIZE));
    next
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
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
        ptr::addr_of_mut!(ALLOCATION_SIZES)
            .cast::<usize>()
            .add(index)
            .write(size);
        ptr::addr_of!(ALLOCATIONS)
            .cast::<*mut u8>()
            .add(index)
            .read()
    }

    unsafe fn allocation_size(index: usize) -> usize {
        ptr::addr_of!(ALLOCATION_SIZES)
            .cast::<usize>()
            .add(index)
            .read()
    }

    #[test]
    fn acquires_single_free_fresh_and_grown_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_ACQUIRE, 0x8000) else {
            note_missing_u32_fixture("cxx/list_node_pool_acquire");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x8000);
            ptr::addr_of_mut!(ALLOCATIONS).write([
                slab,
                slab.add(0x1000),
                slab.add(0x2000),
                slab.add(0x3000),
                slab.add(0x4000),
                slab.add(0x5000),
                slab.add(0x6000),
                slab.add(0x7000),
            ]);
            ALLOCATION_CURSOR = 0;
            ptr::addr_of_mut!(ALLOCATION_SIZES).write([0; 8]);

            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            // single != 0: exactly one node per chunk (sentinel acquire).
            let mut pool = ListNodePool::default();
            let sentinel = list_node_pool_acquire(&mut pool, 1);
            assert_eq!(sentinel as *mut u8, slab.add(0x1000));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!(allocation_size(0), 0x0c);
            assert_eq!(allocation_size(1), NODE_SIZE);
            assert_eq!(pool.chunks, pointer_word(slab));
            assert_eq!(pool.next, pointer_word(slab.add(0x1000 + NODE_SIZE)));
            assert_eq!(pool.end, pointer_word(slab.add(0x1000 + NODE_SIZE)));
            let first_chunk = slab as *mut ListNodePoolChunk;
            assert_eq!((*first_chunk).previous, 0);
            assert_eq!((*first_chunk).capacity, 1);
            assert_eq!((*first_chunk).nodes, pointer_word(slab.add(0x1000)));
            // The node is returned uninitialized.
            assert_eq!((*sentinel).next, 0xa5a5_a5a5);
            assert_eq!((*sentinel).prev, 0xa5a5_a5a5);
            assert_eq!((*sentinel).payload, [0xa5a5_a5a5; 3]);

            // Free-list pop: free link in the node's next word, no clearing.
            let second_free = slab.add(0x1040) as *mut ListNode;
            (*sentinel).next = pointer_word(second_free.cast());
            (*sentinel).prev = 7;
            (*sentinel).payload = [1, 2, 3];
            pool.free = pointer_word(sentinel.cast());
            assert_eq!(list_node_pool_acquire(&mut pool, 0), sentinel);
            assert_eq!(pool.free, pointer_word(second_free.cast()));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!((*sentinel).prev, 7);
            assert_eq!((*sentinel).payload, [1, 2, 3]);

            // Fresh pool with single == 0: 32-node first chunk.
            let mut pool = ListNodePool::default();
            let first = list_node_pool_acquire(&mut pool, 0);
            assert_eq!(first as *mut u8, slab.add(0x3000));
            assert_eq!(ALLOCATION_CURSOR, 4);
            assert_eq!(allocation_size(2), 0x0c);
            assert_eq!(allocation_size(3), INITIAL_CAPACITY as usize * NODE_SIZE);
            assert_eq!(pool.chunks, pointer_word(slab.add(0x2000)));
            assert_eq!(pool.next, pointer_word(slab.add(0x3000 + NODE_SIZE)));
            assert_eq!(
                pool.end,
                pointer_word(slab.add(0x3000 + INITIAL_CAPACITY as usize * NODE_SIZE))
            );
            let chunk32 = slab.add(0x2000) as *mut ListNodePoolChunk;
            assert_eq!((*chunk32).previous, 0);
            assert_eq!((*chunk32).capacity, INITIAL_CAPACITY);
            assert_eq!((*chunk32).nodes, pointer_word(slab.add(0x3000)));

            // Bump within the chunk: no allocation, cursor advances by 20.
            let bumped = list_node_pool_acquire(&mut pool, 0);
            assert_eq!(bumped as *mut u8, slab.add(0x3000 + NODE_SIZE));
            assert_eq!(ALLOCATION_CURSOR, 4);
            assert_eq!(pool.next, pointer_word(slab.add(0x3000 + 2 * NODE_SIZE)));

            // Growth: max(32 + 32, 32 + 16 + 4) = 64 nodes.
            pool.next = pool.end;
            let grown = list_node_pool_acquire(&mut pool, 0);
            assert_eq!(grown as *mut u8, slab.add(0x5000));
            assert_eq!(ALLOCATION_CURSOR, 6);
            assert_eq!(allocation_size(4), 0x0c);
            assert_eq!(allocation_size(5), 64 * NODE_SIZE);
            let chunk64 = slab.add(0x4000) as *mut ListNodePoolChunk;
            assert_eq!((*chunk64).previous, pointer_word(chunk32.cast()));
            assert_eq!((*chunk64).capacity, 64);
            assert_eq!((*chunk64).nodes, pointer_word(slab.add(0x5000)));
            assert_eq!(pool.next, pointer_word(slab.add(0x5000 + NODE_SIZE)));
            assert_eq!(pool.end, pointer_word(slab.add(0x5000 + 64 * NODE_SIZE)));

            // Geometric growth wins: max(64 + 32, 64 + 32 + 8) = 104 nodes.
            pool.next = pool.end;
            let geometric = list_node_pool_acquire(&mut pool, 0);
            assert_eq!(geometric as *mut u8, slab.add(0x7000));
            assert_eq!(ALLOCATION_CURSOR, 8);
            assert_eq!(allocation_size(6), 0x0c);
            assert_eq!(allocation_size(7), 104 * NODE_SIZE);
            let chunk104 = slab.add(0x6000) as *mut ListNodePoolChunk;
            assert_eq!((*chunk104).previous, pointer_word(chunk64.cast()));
            assert_eq!((*chunk104).capacity, 104);
            assert_eq!((*chunk104).nodes, pointer_word(slab.add(0x7000)));
            assert_eq!(pool.next, pointer_word(slab.add(0x7000 + NODE_SIZE)));
            assert_eq!(pool.end, pointer_word(slab.add(0x7000 + 104 * NODE_SIZE)));
        }
    }
}
