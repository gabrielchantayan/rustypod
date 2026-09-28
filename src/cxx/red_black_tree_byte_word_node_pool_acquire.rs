//! Red-black-tree byte-and-word-payload node-pool acquire — retailOS
//! `FUN_083b9508` at `0x083b9508`.
//!
//! Raw `osos.dec` establishes the true 184-byte extent: 46 A32 words from
//! `push {r4-r8,lr}` at `0x083b9508` through `pop {r4-r8,pc}` at
//! `0x083b95bc`; `0x083b95c0` begins the next real function. The body has two
//! unconditional plain `bl` calls, at `0x083b956c` and `0x083b9580`, both to
//! `operator_new_checked` @ `0x08266c70`, and no predicated `bl` calls.
//!
//! The pool removes a free node through node+0x0c or advances through its
//! current 24-byte node arena. Exhaustion allocates a 12-byte chunk header and
//! `capacity * 24` backing store; capacity starts at 32 and grows by
//! `max(previous + 32, previous + previous/2 + previous/8)`. It clears the
//! color byte and three red-black-tree link words, preserving the caller-owned
//! byte-and-word payload at +0x10. Deliberate deviations: target pointers
//! remain `u32` words to preserve the ARM object layout on 64-bit hosts; the
//! retail dead `r1 = 0` allocator argument is omitted from the Rust signature.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x18;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreeByteWordNode {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub payload_byte: u8,
    _payload_padding: [u8; 3],
    pub payload_word: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreeByteWordNodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

#[repr(C)]
struct PoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x18] = [0; core::mem::size_of::<RedBlackTreeByteWordNode>()];
const _: [u8; 0x10] = [0; core::mem::size_of::<RedBlackTreeByteWordNodePool>()];
const _: [u8; 0x0c] = [0; core::mem::size_of::<PoolChunk>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreeByteWordNode {
    word as usize as *mut RedBlackTreeByteWordNode
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut PoolChunk { word as usize as *mut PoolChunk }

/// Acquires and initializes one byte-and-word-payload node from `pool`.
///
/// # Safety
///
/// `pool` and its nonzero target words must identify writable pool state. The
/// checked allocator must return writable storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_byte_word_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_byte_word_node_pool_acquire(
    pool: *mut RedBlackTreeByteWordNodePool,
) -> *mut RedBlackTreeByteWordNode {
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
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_BYTE_WORD_NODE_POOL_ACQUIRE, 0x5000) else { note_missing_u32_fixture("cxx/red_black_tree_byte_word_node_pool_acquire"); return; };
        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x5000);
            ALLOCATIONS = [slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000)]; SIZES = [0; 4]; CURSOR = 0;
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS)); ops.alloc = alloc; ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            let mut pool = RedBlackTreeByteWordNodePool::default();
            let first = red_black_tree_byte_word_node_pool_acquire(&mut pool);
            assert_eq!(first as *mut u8, slab.add(0x1000)); assert_eq!(SIZES[..2], [0x0c, 0x20 * NODE_SIZE]);
            assert_eq!((*first).payload_byte, 0xa5); assert_eq!((*first).payload_word, 0xa5a5_a5a5); assert_eq!((*first).color, 0); assert_eq!((*first).parent, 0); assert_eq!((*first).left, 0); assert_eq!((*first).right, 0);
            let second = slab.add(0x1040) as *mut RedBlackTreeByteWordNode;
            (*first).right = pointer_word(second.cast()); (*first).payload_byte = 7; (*first).payload_word = 0xfeed_beef; (*first).color = 1; (*first).parent = 2; (*first).left = 3; pool.free = pointer_word(first.cast());
            assert_eq!(red_black_tree_byte_word_node_pool_acquire(&mut pool), first);
            assert_eq!(pool.free, pointer_word(second.cast())); assert_eq!((*first).payload_byte, 7); assert_eq!((*first).payload_word, 0xfeed_beef); assert_eq!((*first).right, 0); assert_eq!((*first).color, 0); assert_eq!((*first).parent, 0); assert_eq!((*first).left, 0);
            pool.free = 0; pool.next = pool.end;
            let grown = red_black_tree_byte_word_node_pool_acquire(&mut pool);
            assert_eq!(grown as *mut u8, slab.add(0x3000)); assert_eq!(SIZES[2..4], [0x0c, 0x40 * NODE_SIZE]);
        }
    }
}
