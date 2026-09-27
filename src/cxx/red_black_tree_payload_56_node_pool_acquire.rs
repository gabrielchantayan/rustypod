//! Red-black-tree 56-byte-payload node-pool acquire — retailOS
//! `FUN_083ccc0c` at load address `0x083ccc0c`.
//!
//! Raw `osos.dec` establishes the exact 184-byte extent: 46 ARM words from
//! `push {r4-r8,lr}` at `0x083ccc0c` through `pop {r4-r8,pc}` at
//! `0x083cccc0`; `0x083cccc4` starts the next real function. The body has
//! exactly two unconditional plain `bl` calls, both to `operator_new_checked`
//! at `0x08266c70`, and no predicated `bl` calls. It removes a free node or
//! advances a 72-byte node chunk, allocating an initial 32-node chunk and then
//! growing by `max(capacity + 32, capacity + capacity/2 + capacity/8)`. It
//! clears the returned node's color and three tree-link words while preserving
//! its 56-byte client payload.
//!
//! Deliberate deviations: none. Pointer fields remain target-width `u32` words
//! so the firmware layout remains exact on 64-bit host fixtures.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x48;

/// A 72-byte red-black-tree node with a caller-owned 56-byte payload.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RedBlackTreePayload56Node {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub payload: [u8; 56],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreePayload56Node, parent)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreePayload56Node, left)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreePayload56Node, right)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreePayload56Node, payload)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<RedBlackTreePayload56Node>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RedBlackTreePayload56NodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload56NodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 {
    pointer as usize as u32
}

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreePayload56Node {
    word as usize as *mut RedBlackTreePayload56Node
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut RedBlackTreePayload56NodePoolChunk {
    word as usize as *mut RedBlackTreePayload56NodePoolChunk
}

/// Acquires and initializes one 56-byte-payload node from `pool`.
///
/// # Safety
///
/// `pool` must be writable. Its target-width words must describe valid chunks
/// and nodes; the checked allocator must return writable storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_payload_56_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_56_node_pool_acquire(
    pool: *mut RedBlackTreePayload56NodePool,
) -> *mut RedBlackTreePayload56Node {
    let node = if (*pool).free != 0 {
        let free = node_from_word((*pool).free);
        (*pool).free = (*free).right;
        free
    } else {
        if (*pool).next == (*pool).end {
            let capacity = if (*pool).chunks == 0 {
                INITIAL_CAPACITY
            } else {
                let previous_capacity = (*chunk_from_word((*pool).chunks)).capacity;
                let geometric_capacity = previous_capacity
                    .wrapping_add(previous_capacity >> 1)
                    .wrapping_add(previous_capacity >> 3);
                core::cmp::max(previous_capacity.wrapping_add(INITIAL_CAPACITY), geometric_capacity)
            };
            let chunk = operator_new_checked(core::mem::size_of::<RedBlackTreePayload56NodePoolChunk>())
                as *mut RedBlackTreePayload56NodePoolChunk;
            let nodes = operator_new_checked((capacity as usize).wrapping_mul(NODE_SIZE));

            (*chunk).nodes = pointer_word(nodes);
            (*chunk).previous = (*pool).chunks;
            (*chunk).capacity = capacity;
            (*pool).chunks = pointer_word(chunk.cast());
            (*pool).end = pointer_word(nodes.add((capacity as usize).wrapping_mul(NODE_SIZE)));
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
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    static mut ALLOCATIONS: [*mut u8; 4] = [ptr::null_mut(); 4];
    static mut SIZES: [usize; 4] = [0; 4];
    static mut CURSOR: usize = 0;

    unsafe extern "C" fn pool_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let index = CURSOR;
        CURSOR += 1;
        SIZES[index] = size;
        ALLOCATIONS[index]
    }

    #[test]
    fn acquires_free_and_grown_payload_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_56_NODE_POOL_ACQUIRE, 0x8000) else {
            note_missing_u32_fixture("cxx/red_black_tree_payload_56_node_pool_acquire");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x8000);
            ALLOCATIONS = [slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000)];
            SIZES = [0; 4];
            CURSOR = 0;
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let mut pool = RedBlackTreePayload56NodePool::default();
            let node = red_black_tree_payload_56_node_pool_acquire(&mut pool);
            assert_eq!(node.cast::<u8>(), slab.add(0x1000));
            assert_eq!(SIZES[..2], [0x0c, 32 * NODE_SIZE]);
            assert_eq!((*node).payload, [0xa5; 56]);
            assert_eq!(((*node).color, (*node).parent, (*node).left, (*node).right), (0, 0, 0, 0));

            let next_free = slab.add(0x1800).cast::<RedBlackTreePayload56Node>();
            (*node).right = pointer_word(next_free.cast());
            (*node).payload[0] = 0x3c;
            pool.free = pointer_word(node.cast());
            assert_eq!(red_black_tree_payload_56_node_pool_acquire(&mut pool), node);
            assert_eq!(pool.free, pointer_word(next_free.cast()));
            assert_eq!((*node).payload[0], 0x3c);

            pool.next = pool.end;
            pool.free = 0;
            let grown = red_black_tree_payload_56_node_pool_acquire(&mut pool);
            assert_eq!(grown.cast::<u8>(), slab.add(0x3000));
            assert_eq!(SIZES[2..4], [0x0c, 64 * NODE_SIZE]);
            let chunk = slab.add(0x2000).cast::<RedBlackTreePayload56NodePoolChunk>();
            assert_eq!((*chunk).previous, pointer_word(slab.cast()));
            assert_eq!((*chunk).capacity, 64);
        }
    }
}
