//! Red-black-tree word-node pool acquire — original: `FUN_083bf424` at load
//! address `0x083bf424`.
//!
//! Raw `osos.dec` establishes the exact 184-byte extent: 46 ARM words from
//! `push {r4-r8,lr}` at `0x083bf424` through `pop {r4-r8,pc}` at
//! `0x083bf4d8`; the next real function starts at `0x083bf4dc`. The body has
//! two unconditional `bl` instructions, both to checked operator new @
//! `0x08266c70`, and no predicated `bl` instructions. The three inbound calls
//! are unconditional BL at `0x0819f988`, `0x083bf4e4`, and `0x083c0070`.
//!
//! The pool pops the free-list link at node+0x0c, or bumps through a 0x14-byte
//! red-black-tree node arena. Exhaustion allocates a 12-byte chunk header and
//! `capacity * 0x14` arena; capacity starts at 32 and grows by
//! `max(previous + 32, previous + previous/2 + previous/8)`. The node's color
//! and three tree links are cleared, preserving its caller-owned word payload.
//!
//! Deliberate deviations: target pointers are retained as `u32` words so host
//! pointer width cannot change firmware offsets. The dead `r1 = 0` argument to
//! checked new is omitted; its Rust declaration takes only the size.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x14;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RedBlackTreeWordNode {
    pub color: u8,
    pub _pad: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub payload: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreeWordNode, parent)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreeWordNode, left)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreeWordNode, right)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreeWordNode, payload)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<RedBlackTreeWordNode>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PoolChunk { previous: u32, capacity: u32, nodes: u32 }
const _: [u8; 0x0c] = [0; core::mem::size_of::<PoolChunk>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreeWordNodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}
const _: [u8; 0x10] = [0; core::mem::size_of::<RedBlackTreeWordNodePool>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }
#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreeWordNode {
    word as usize as *mut RedBlackTreeWordNode
}
#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut PoolChunk { word as usize as *mut PoolChunk }

/// Acquires and initializes one word-payload node from `pool`.
///
/// # Safety
/// `pool` and all nonzero target words in it must identify writable pool
/// state. The checked allocator must return writable storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_word_node_pool_acquire(
    pool: *mut RedBlackTreeWordNodePool,
) -> *mut RedBlackTreeWordNode {
    let node = if (*pool).free != 0 {
        let free = node_from_word((*pool).free);
        (*pool).free = (*free).right;
        free
    } else {
        if (*pool).next == (*pool).end {
            let capacity = if (*pool).chunks == 0 {
                INITIAL_CAPACITY
            } else {
                let old = (*chunk_from_word((*pool).chunks)).capacity;
                core::cmp::max(old.wrapping_add(INITIAL_CAPACITY), old.wrapping_add(old >> 1).wrapping_add(old >> 3))
            };
            let chunk = operator_new_checked(core::mem::size_of::<PoolChunk>()) as *mut PoolChunk;
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
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    static mut ALLOCATIONS: [*mut u8; 4] = [ptr::null_mut(); 4];
    static mut SIZES: [usize; 4] = [0; 4];
    static mut CURSOR: usize = 0;
    unsafe extern "C" fn alloc(_: *mut HeapDescriptorDescriptor, size: usize, _: usize) -> *mut u8 {
        let index = CURSOR; CURSOR += 1; SIZES[index] = size; ALLOCATIONS[index]
    }
    #[test]
    fn acquires_fresh_free_and_grown_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_WORD_NODE_POOL_ACQUIRE, 0x5000) else { note_missing_u32_fixture("cxx/red_black_tree_word_node_pool_acquire"); return; };
        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x5000);
            ALLOCATIONS = [slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000)]; SIZES = [0; 4]; CURSOR = 0;
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS)); ops.alloc = alloc; ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            let mut pool = RedBlackTreeWordNodePool::default();
            let first = red_black_tree_word_node_pool_acquire(&mut pool);
            assert_eq!(first as *mut u8, slab.add(0x1000)); assert_eq!(SIZES[..2], [0x0c, 0x20 * NODE_SIZE]);
            assert_eq!((*first).payload, 0xa5a5_a5a5); assert_eq!((*first).color, 0);
            let second = slab.add(0x1040) as *mut RedBlackTreeWordNode;
            (*first).right = pointer_word(second.cast()); (*first).payload = 7; (*first).color = 1; pool.free = pointer_word(first.cast());
            assert_eq!(red_black_tree_word_node_pool_acquire(&mut pool), first);
            assert_eq!(pool.free, pointer_word(second.cast())); assert_eq!((*first).payload, 7); assert_eq!((*first).right, 0); assert_eq!((*first).color, 0);
            pool.free = 0; pool.next = pool.end;
            let grown = red_black_tree_word_node_pool_acquire(&mut pool);
            assert_eq!(grown as *mut u8, slab.add(0x3000)); assert_eq!(SIZES[2..4], [0x0c, 0x40 * NODE_SIZE]);
        }
    }
}
