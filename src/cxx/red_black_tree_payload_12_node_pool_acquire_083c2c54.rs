//! Red-black-tree 12-byte-payload node-pool acquire — retailOS `FUN_083c2c54`
//! at load address `0x083c2c54`.
//!
//! Raw `osos.dec` establishes the exact 184-byte extent: 46 A32 words from
//! `push {r4-r8,lr}` at `0x083c2c54` through `pop {r4-r8,pc}` at
//! `0x083c2d08`; `0x083c2d0c` begins the next real function. The body has two
//! unconditional plain `bl` calls, at `0x083c2cb8` and `0x083c2ccc`, both to
//! `operator_new_checked` @ `0x08266c70`, and no predicated `bl` calls.
//!
//! The pool pops a node from the +0xc-threaded free list or advances its
//! current 28-byte node arena. Exhaustion allocates a 12-byte chunk header and
//! an arena of 32 nodes, later growing by
//! `max(capacity + 32, capacity + capacity/2 + capacity/8)`. It clears the
//! returned node's color and red-black-tree links, preserving the 12-byte
//! caller payload. Deliberate deviations: the dead `r1 = 0` allocator argument
//! is omitted; target pointers remain `u32` words so host layout stays exact.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x1c;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload12Node083c2c54 {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    /// Left uninitialised for the caller.
    pub payload: [u32; 3],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(RedBlackTreePayload12Node083c2c54, parent)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(RedBlackTreePayload12Node083c2c54, left)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(RedBlackTreePayload12Node083c2c54, right)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreePayload12Node083c2c54, payload)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<RedBlackTreePayload12Node083c2c54>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreePayload12NodePool083c2c54 {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreePayload12Node083c2c54 {
    word as usize as *mut RedBlackTreePayload12Node083c2c54
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut PoolChunk { word as usize as *mut PoolChunk }

/// Acquires and initializes one node from `pool`.
///
/// # Safety
/// `pool` and all nonzero target-width pointers it contains must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_payload_12_node_pool_acquire_083c2c54(
    pool: *mut RedBlackTreePayload12NodePool083c2c54,
) -> *mut RedBlackTreePayload12Node083c2c54 {
    let node = if (*pool).free != 0 {
        let free = node_from_word((*pool).free);
        (*pool).free = (*free).right;
        free
    } else {
        if node_from_word((*pool).next) as u32 == (*pool).end {
            let capacity = if (*pool).chunks == 0 {
                INITIAL_CAPACITY
            } else {
                let previous = (*chunk_from_word((*pool).chunks)).capacity;
                core::cmp::max(
                    previous.wrapping_add(INITIAL_CAPACITY),
                    previous.wrapping_add(previous >> 1).wrapping_add(previous >> 3),
                )
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

    unsafe extern "C" fn pool_alloc(
        _heap: *mut HeapDescriptorDescriptor, size: usize, _tag: usize,
    ) -> *mut u8 {
        let index = CURSOR;
        CURSOR += 1;
        SIZES[index] = size;
        ALLOCATIONS[index]
    }

    #[test]
    fn grows_reuses_and_reinitializes_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_PAYLOAD_12_NODE_POOL_ACQUIRE_083C2C54, 0x7000) else {
            note_missing_u32_fixture("cxx/red_black_tree_payload_12_node_pool_acquire_083c2c54");
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x7000);
            ALLOCATIONS = [slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000)];
            SIZES = [0; 4]; CURSOR = 0;
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            let mut pool = RedBlackTreePayload12NodePool083c2c54::default();
            let first = red_black_tree_payload_12_node_pool_acquire_083c2c54(&mut pool);
            assert_eq!(first.cast::<u8>(), slab.add(0x1000));
            assert_eq!(SIZES[..2], [0x0c, 32 * NODE_SIZE]);
            assert_eq!((*first).payload, [0xa5a5_a5a5; 3]);
            (*first).color = 1; (*first).parent = 2; (*first).left = 3;
            let next_free = slab.add(0x1080).cast::<RedBlackTreePayload12Node083c2c54>();
            (*first).right = pointer_word(next_free.cast()); pool.free = pointer_word(first.cast());
            assert_eq!(red_black_tree_payload_12_node_pool_acquire_083c2c54(&mut pool), first);
            assert_eq!([(*first).parent, (*first).left, (*first).right], [0; 3]);
            pool.free = 0; pool.next = pool.end;
            let grown = red_black_tree_payload_12_node_pool_acquire_083c2c54(&mut pool);
            assert_eq!(grown.cast::<u8>(), slab.add(0x3000));
            assert_eq!(SIZES[2..4], [0x0c, 64 * NODE_SIZE]);
        }
    }
}
