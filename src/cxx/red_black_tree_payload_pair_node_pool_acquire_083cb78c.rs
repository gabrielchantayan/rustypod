//! Red-black-tree pair-payload node-pool acquire — original: `FUN_083cb78c`
//! at load address `0x083cb78c`.
//!
//! Raw `osos.dec` establishes the true 184-byte extent: 46 A32 words from
//! `push {r4-r8,lr}` at `0x083cb78c` through `pop {r4-r8,pc}` at
//! `0x083cb840`; the next real function begins at `0x083cb844`. The body has
//! two unconditional plain `bl` calls, both to `operator_new_checked` @
//! `0x08266c70`, and no predicated `bl` calls.
//!
//! The pool removes a free node whose link occupies node+0x0c, or bumps through
//! its 0x18-byte node arena. On exhaustion it allocates a 12-byte chunk header
//! and `capacity * 0x18` arena; capacity starts at 32 and grows by
//! `max(previous + 32, previous + previous/2 + previous/8)`. It clears the
//! color byte and three tree links, leaving the caller-owned two-word payload.
//!
//! Deliberate deviations: target pointers are retained as `u32` words, keeping
//! firmware offsets valid on 64-bit hosts; the retail dead `r1 = 0` argument to
//! checked new is omitted from its Rust signature.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x18;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RedBlackTreePayloadPairNode083cb78c {
    pub color: u8,
    pub _pad: [u8; 3],
    pub parent: u32,
    pub left: u32,
    /// Free-list link while pooled.
    pub right: u32,
    /// Caller-owned pair, deliberately uninitialized by acquisition.
    pub payload: [u32; 2],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreePayloadPairNode083cb78c, parent)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreePayloadPairNode083cb78c, left)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreePayloadPairNode083cb78c, right)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreePayloadPairNode083cb78c, payload)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<RedBlackTreePayloadPairNode083cb78c>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PoolChunk { previous: u32, capacity: u32, nodes: u32 }
const _: [u8; 0x0c] = [0; core::mem::size_of::<PoolChunk>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayloadPairNodePool083cb78c {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}
const _: [u8; 0x10] = [0; core::mem::size_of::<RedBlackTreePayloadPairNodePool083cb78c>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }
#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreePayloadPairNode083cb78c {
    word as usize as *mut RedBlackTreePayloadPairNode083cb78c
}
#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut PoolChunk { word as usize as *mut PoolChunk }

/// Acquires and initializes one pair-payload node from `pool`.
///
/// # Safety
/// `pool` and all nonzero target words in it must identify writable pool state.
/// The checked allocator must return writable storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_payload_pair_node_pool_acquire_083cb78c")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_pair_node_pool_acquire_083cb78c(
    pool: *mut RedBlackTreePayloadPairNodePool083cb78c,
) -> *mut RedBlackTreePayloadPairNode083cb78c {
    let node = if (*pool).free != 0 {
        let free = node_from_word((*pool).free);
        (*pool).free = (*free).right;
        free
    } else {
        if (*pool).next == (*pool).end {
            let capacity = if (*pool).chunks == 0 {
                INITIAL_CAPACITY
            } else {
                let previous = chunk_from_word((*pool).chunks);
                let old = (*previous).capacity;
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
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_PAIR_NODE_POOL_ACQUIRE_083CB78C, 0x5000) else { note_missing_u32_fixture("cxx/red_black_tree_payload_pair_node_pool_acquire_083cb78c"); return; };
        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x5000);
            ALLOCATIONS = [slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000)]; SIZES = [0; 4]; CURSOR = 0;
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS)); ops.alloc = alloc; ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            let mut pool = RedBlackTreePayloadPairNodePool083cb78c::default();
            let first = red_black_tree_payload_pair_node_pool_acquire_083cb78c(&mut pool);
            assert_eq!(first as *mut u8, slab.add(0x1000)); assert_eq!(SIZES[..2], [0x0c, 0x20 * NODE_SIZE]);
            assert_eq!((*first).payload, [0xa5a5_a5a5; 2]); assert_eq!((*first).color, 0);
            let second = slab.add(0x1040) as *mut RedBlackTreePayloadPairNode083cb78c;
            (*first).right = pointer_word(second.cast()); (*first).payload = [7, 9]; (*first).color = 1; pool.free = pointer_word(first.cast());
            assert_eq!(red_black_tree_payload_pair_node_pool_acquire_083cb78c(&mut pool), first);
            assert_eq!(pool.free, pointer_word(second.cast())); assert_eq!((*first).payload, [7, 9]); assert_eq!((*first).right, 0); assert_eq!((*first).color, 0);
            pool.free = 0; pool.next = pool.end;
            let grown = red_black_tree_payload_pair_node_pool_acquire_083cb78c(&mut pool);
            assert_eq!(grown as *mut u8, slab.add(0x3000)); assert_eq!(SIZES[2..4], [0x0c, 0x40 * NODE_SIZE]);
        }
    }
}
