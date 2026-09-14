//! Red-black-tree 24-byte-payload node-pool acquire — original:
//! `FUN_083c14c8` at load address `0x083c14c8`.
//!
//! Raw `osos.dec` establishes the exact 184-byte extent: 46 ARM words from
//! `push {r4-r8,lr}` at `0x083c14c8` through `pop {r4-r8,pc}` at
//! `0x083c157c`; the separately linked next function starts at `0x083c1580`.
//! Decoding every aligned ARM B/BL-immediate word in `osos.dec` finds exactly
//! five inbound direct calls, all unconditional `bl` at `0x08134e48`,
//! `0x081cdb58`, `0x083c1588`, `0x083c1f6c`, and `0x083db308`; there are no
//! predicated direct calls or plain `b` tail calls.
//!
//! The pool first removes a node from its free list. Otherwise it advances
//! through its current 40-byte node chunk, allocating a new 12-byte chunk
//! header and backing chunk when exhausted. The first chunk has 32 nodes;
//! later chunks grow by `max(capacity + 32, capacity + capacity/2 +
//! capacity/8)`. The returned node's color byte and three red-black-tree link
//! words are cleared, preserving its 24-byte client payload at +0x10.
//!
//! Deliberate deviations: none. Pointers in firmware objects remain `u32`
//! target words so their 32-bit layout is preserved on the host. As in retailOS,
//! a failed checked allocation is immediately dereferenced rather than handled.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x28;

/// A 40-byte red-black-tree node with a caller-owned 24-byte payload.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RedBlackTreePayload24Node {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub payload: [u8; 24],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreePayload24Node, parent)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreePayload24Node, left)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreePayload24Node, right)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreePayload24Node, payload)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<RedBlackTreePayload24Node>()];

/// Heap header prepended to each pool chunk.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RedBlackTreePayload24NodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreePayload24NodePoolChunk, capacity)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreePayload24NodePoolChunk, nodes)];
const _: [u8; 0x0c] = [0; core::mem::size_of::<RedBlackTreePayload24NodePoolChunk>()];

/// The target-width node-pool state consumed by
/// [`red_black_tree_payload_24_node_pool_acquire`].
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload24NodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreePayload24NodePool, free)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreePayload24NodePool, next)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreePayload24NodePool, end)];
const _: [u8; 0x10] = [0; core::mem::size_of::<RedBlackTreePayload24NodePool>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 {
    pointer as usize as u32
}

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreePayload24Node {
    word as usize as *mut RedBlackTreePayload24Node
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut RedBlackTreePayload24NodePoolChunk {
    word as usize as *mut RedBlackTreePayload24NodePoolChunk
}

/// Acquires and initializes one 24-byte-payload node from `pool`.
///
/// Original: `FUN_083c14c8` at load address `0x083c14c8` (184 bytes; five
/// unconditional inbound `bl` sites).
///
/// # Safety
///
/// `pool` must point to a writable [`RedBlackTreePayload24NodePool`]. Existing
/// pool words must describe valid aligned chunks and nodes. The checked
/// allocator is assumed to return writable storage, matching the retail
/// routine's immediate dereference of both allocation results.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_payload_24_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_24_node_pool_acquire(
    pool: *mut RedBlackTreePayload24NodePool,
) -> *mut RedBlackTreePayload24Node {
    let node = if (*pool).free != 0 {
        let free = node_from_word((*pool).free);
        (*pool).free = (*free).right;
        free
    } else {
        let next = node_from_word((*pool).next);
        if next as u32 == (*pool).end {
            let capacity = if (*pool).chunks == 0 {
                INITIAL_CAPACITY
            } else {
                let previous = chunk_from_word((*pool).chunks);
                let previous_capacity = (*previous).capacity;
                let geometric_capacity = previous_capacity
                    + (previous_capacity >> 1)
                    + (previous_capacity >> 3);
                core::cmp::max(previous_capacity + INITIAL_CAPACITY, geometric_capacity)
            };
            let chunk = operator_new_checked(core::mem::size_of::<RedBlackTreePayload24NodePoolChunk>())
                as *mut RedBlackTreePayload24NodePoolChunk;
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
    };

    (*node).parent = 0;
    (*node).left = 0;
    (*node).right = 0;
    (*node).color = 0;
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
    fn acquires_from_new_free_and_grown_chunks() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_24_NODE_POOL_ACQUIRE, 0x7000) else {
            note_missing_u32_fixture("cxx/red_black_tree_payload_24_node_pool_acquire");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x7000);
            ptr::addr_of_mut!(ALLOCATIONS).write([
                slab,
                slab.add(0x1000),
                slab.add(0x2000),
                slab.add(0x3000),
                slab.add(0x4000),
                slab.add(0x5000),
            ]);
            ALLOCATION_CURSOR = 0;
            ptr::addr_of_mut!(ALLOCATION_SIZES).write([0; 6]);

            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let mut pool = RedBlackTreePayload24NodePool::default();
            let first = red_black_tree_payload_24_node_pool_acquire(&mut pool);
            assert_eq!(first as *mut u8, slab.add(0x1000));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!(allocation_size(0), 0x0c);
            assert_eq!(allocation_size(1), INITIAL_CAPACITY as usize * NODE_SIZE);
            assert_eq!(pool.chunks, pointer_word(slab));
            assert_eq!(pool.next, pointer_word(slab.add(0x1000 + NODE_SIZE)));
            assert_eq!(pool.end, pointer_word(slab.add(0x1000 + INITIAL_CAPACITY as usize * NODE_SIZE)));
            let first_chunk = slab as *mut RedBlackTreePayload24NodePoolChunk;
            assert_eq!((*first_chunk).previous, 0);
            assert_eq!((*first_chunk).capacity, INITIAL_CAPACITY);
            assert_eq!((*first_chunk).nodes, pointer_word(slab.add(0x1000)));
            assert_eq!((*first).color, 0);
            assert_eq!((*first).parent, 0);
            assert_eq!((*first).left, 0);
            assert_eq!((*first).right, 0);
            assert_eq!((*first).payload, [0xa5; 24]);

            let second_free = slab.add(0x1080) as *mut RedBlackTreePayload24Node;
            (*first).color = 1;
            (*first).parent = 2;
            (*first).left = 3;
            (*first).right = pointer_word(second_free.cast());
            (*first).payload = [4; 24];
            pool.free = pointer_word(first.cast());
            assert_eq!(red_black_tree_payload_24_node_pool_acquire(&mut pool), first);
            assert_eq!(pool.free, pointer_word(second_free.cast()));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!((*first).color, 0);
            assert_eq!((*first).parent, 0);
            assert_eq!((*first).left, 0);
            assert_eq!((*first).right, 0);
            assert_eq!((*first).payload, [4; 24]);

            pool.free = 0;
            pool.next = pool.end;
            let grown = red_black_tree_payload_24_node_pool_acquire(&mut pool);
            assert_eq!(grown as *mut u8, slab.add(0x3000));
            assert_eq!(ALLOCATION_CURSOR, 4);
            assert_eq!(allocation_size(2), 0x0c);
            assert_eq!(allocation_size(3), 64 * NODE_SIZE);
            let second_chunk = slab.add(0x2000) as *mut RedBlackTreePayload24NodePoolChunk;
            assert_eq!((*second_chunk).previous, pointer_word(first_chunk.cast()));
            assert_eq!((*second_chunk).capacity, 64);
            assert_eq!((*second_chunk).nodes, pointer_word(slab.add(0x3000)));
            assert_eq!(pool.chunks, pointer_word(second_chunk.cast()));
            assert_eq!(pool.next, pointer_word(slab.add(0x3000 + NODE_SIZE)));
            assert_eq!(pool.end, pointer_word(slab.add(0x3000 + 64 * NODE_SIZE)));
            assert_eq!((*grown).color, 0);
            assert_eq!((*grown).parent, 0);
            assert_eq!((*grown).left, 0);
            assert_eq!((*grown).right, 0);
            assert_eq!((*grown).payload, [0xa5; 24]);

            pool.next = pool.end;
            let geometric = red_black_tree_payload_24_node_pool_acquire(&mut pool);
            assert_eq!(geometric as *mut u8, slab.add(0x5000));
            assert_eq!(ALLOCATION_CURSOR, 6);
            assert_eq!(allocation_size(4), 0x0c);
            assert_eq!(allocation_size(5), 104 * NODE_SIZE);
            let third_chunk = slab.add(0x4000) as *mut RedBlackTreePayload24NodePoolChunk;
            assert_eq!((*third_chunk).previous, pointer_word(second_chunk.cast()));
            assert_eq!((*third_chunk).capacity, 104);
            assert_eq!((*third_chunk).nodes, pointer_word(slab.add(0x5000)));
            assert_eq!(pool.chunks, pointer_word(third_chunk.cast()));
            assert_eq!(pool.next, pointer_word(slab.add(0x5000 + NODE_SIZE)));
            assert_eq!(pool.end, pointer_word(slab.add(0x5000 + 104 * NODE_SIZE)));
        }
    }
}
