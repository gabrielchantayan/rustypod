//! Red-black-tree 28-byte-payload node-pool acquire — retailOS `FUN_083cad14`
//! at load address `0x083cad14`.
//!
//! Raw `osos.dec` establishes the exact 188-byte extent: 47 ARM words from
//! `push {r4-r8,lr}` at `0x083cad14` through `pop {r4-r8,pc}` at
//! `0x083cadcc`; `0x083cadd0` begins the next real function. The body has two
//! unconditional plain `bl` calls, at `0x083cad78` and `0x083cad8c`, both to
//! `operator_new_checked` @ `0x08266c70`, and no predicated `bl` calls. Raw
//! whole-image branch decoding finds two inbound unconditional plain `bl`
//! calls, at `0x08213a18` and `0x083cb5d0`, and no predicated inbound calls.
//!
//! The pool removes a node from its free list or advances through its current
//! 44-byte node chunk. Exhaustion allocates a 12-byte chunk header and backing
//! chunk: the first contains 32 nodes, and later chunks grow by
//! `max(capacity + 32, capacity + capacity/2 + capacity/8)`. The returned
//! node's color byte and three red-black-tree link words are cleared, preserving
//! its 28-byte client payload. Deliberate deviations: none; target pointers
//! remain `u32` words to preserve the firmware layout on 64-bit hosts.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x2c;

/// A 44-byte red-black-tree node with a caller-owned 28-byte payload.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload28Node {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub payload: [u32; 7],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreePayload28Node, parent)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreePayload28Node, left)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreePayload28Node, right)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreePayload28Node, payload)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<RedBlackTreePayload28Node>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RedBlackTreePayload28NodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x0c] = [0; core::mem::size_of::<RedBlackTreePayload28NodePoolChunk>()];

/// Target-width node-pool state consumed by the pool acquire routine.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload28NodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

const _: [u8; 0x10] = [0; core::mem::size_of::<RedBlackTreePayload28NodePool>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreePayload28Node {
    word as usize as *mut RedBlackTreePayload28Node
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut RedBlackTreePayload28NodePoolChunk {
    word as usize as *mut RedBlackTreePayload28NodePoolChunk
}

/// Acquires and initializes one node from `pool`.
///
/// # Safety
///
/// `pool` must be writable; its nonzero words must name valid, aligned chunks
/// and nodes. The checked allocator's results are immediately dereferenced,
/// matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_payload_28_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_28_node_pool_acquire(
    pool: *mut RedBlackTreePayload28NodePool,
) -> *mut RedBlackTreePayload28Node {
    let node = if (*pool).free != 0 {
        let free = node_from_word((*pool).free);
        (*pool).free = (*free).right;
        free
    } else {
        if node_from_word((*pool).next) as u32 == (*pool).end {
            let capacity = if (*pool).chunks == 0 {
                INITIAL_CAPACITY
            } else {
                let previous_capacity = (*chunk_from_word((*pool).chunks)).capacity;
                core::cmp::max(
                    previous_capacity.wrapping_add(INITIAL_CAPACITY),
                    previous_capacity
                        .wrapping_add(previous_capacity >> 1)
                        .wrapping_add(previous_capacity >> 3),
                )
            };
            let chunk = operator_new_checked(core::mem::size_of::<RedBlackTreePayload28NodePoolChunk>())
                as *mut RedBlackTreePayload28NodePoolChunk;
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
        ptr::addr_of_mut!(ALLOCATION_SIZES).cast::<usize>().add(index).write(size);
        ptr::addr_of!(ALLOCATIONS).cast::<*mut u8>().add(index).read()
    }

    #[test]
    fn acquires_initial_free_and_grown_payload_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_28_NODE_POOL_ACQUIRE, 0x7000) else {
            note_missing_u32_fixture("cxx/red_black_tree_payload_28_node_pool_acquire");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x7000);
            ptr::addr_of_mut!(ALLOCATIONS).write([
                slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000),
                slab.add(0x4000), slab.add(0x5000),
            ]);
            ALLOCATION_CURSOR = 0;
            ptr::addr_of_mut!(ALLOCATION_SIZES).write([0; 6]);
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let mut pool = RedBlackTreePayload28NodePool::default();
            let first = red_black_tree_payload_28_node_pool_acquire(&mut pool);
            assert_eq!(first.cast::<u8>(), slab.add(0x1000));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!(ALLOCATION_SIZES, [0x0c, 32 * NODE_SIZE, 0, 0, 0, 0]);
            assert_eq!(pool.next, pointer_word(slab.add(0x1000 + NODE_SIZE)));
            assert_eq!(pool.end, pointer_word(slab.add(0x1000 + 32 * NODE_SIZE)));
            assert_eq!((*first).payload[6], 0xa5a5_a5a5);

            let next_free = slab.add(0x1080).cast::<RedBlackTreePayload28Node>();
            (*first).color = 1;
            (*first).parent = 2;
            (*first).left = 3;
            (*first).right = pointer_word(next_free.cast());
            (*first).payload[0] = 4;
            pool.free = pointer_word(first.cast());
            assert_eq!(red_black_tree_payload_28_node_pool_acquire(&mut pool), first);
            assert_eq!(pool.free, pointer_word(next_free.cast()));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!((*first).color, 0);
            assert_eq!([(*first).parent, (*first).left, (*first).right], [0; 3]);
            assert_eq!((*first).payload[0], 4);

            pool.free = 0;
            pool.next = pool.end;
            let grown = red_black_tree_payload_28_node_pool_acquire(&mut pool);
            assert_eq!(grown.cast::<u8>(), slab.add(0x3000));
            assert_eq!(ALLOCATION_SIZES[2..4], [0x0c, 64 * NODE_SIZE]);
            let second_chunk = slab.add(0x2000).cast::<RedBlackTreePayload28NodePoolChunk>();
            assert_eq!((*second_chunk).capacity, 64);

            pool.next = pool.end;
            let geometric = red_black_tree_payload_28_node_pool_acquire(&mut pool);
            assert_eq!(geometric.cast::<u8>(), slab.add(0x5000));
            assert_eq!(ALLOCATION_SIZES[4..6], [0x0c, 104 * NODE_SIZE]);
        }
    }
}
