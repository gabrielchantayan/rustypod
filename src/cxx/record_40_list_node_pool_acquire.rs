//! `record_40_list_node_pool_acquire` — retailOS `FUN_083dc7e4` @
//! `0x083dc7e4`.
//!
//! Raw `osos.dec` establishes the true 184-byte extent: 46 ARM words from
//! `push {r4-r6,lr}` through `pop {r4-r6,pc}` at `0x083dc898`; `0x083dc89c`
//! starts the next real function. The body holds exactly two unconditional
//! plain `bl` calls, both to `operator_new_checked` @ `0x08266c70`; there are
//! no predicated `bl` calls. It acquires an uninitialized 48-byte list node
//! `{next, previous, payload[10]}` from a target-width pool. A nonzero
//! `single` allocates one node for a sentinel; otherwise chunks start at 32
//! nodes and grow by `max(capacity + 32, capacity + capacity/2 + capacity/8)`.
//!
//! Deliberate deviations: none. Pointer fields remain `u32` target words, so
//! the target layout stays exact on 64-bit host fixtures.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x30;

/// A 48-byte list node with the 40-byte record copied into it by the caller.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Record40ListNode {
    pub next: u32,
    pub previous: u32,
    pub payload: [u32; 10],
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(Record40ListNode, previous)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(Record40ListNode, payload)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<Record40ListNode>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Record40ListNodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Record40ListNodePool {
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
unsafe fn node_from_word(word: u32) -> *mut Record40ListNode {
    word as usize as *mut Record40ListNode
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut Record40ListNodePoolChunk {
    word as usize as *mut Record40ListNodePoolChunk
}

/// Acquires an uninitialized node. `single != 0` forces a one-node chunk.
///
/// # Safety
///
/// `pool` and its target-width node/chunk words must be writable and valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record_40_list_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn record_40_list_node_pool_acquire(
    pool: *mut Record40ListNodePool,
    single: u32,
) -> *mut Record40ListNode {
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
            let geometric_capacity = previous_capacity
                .wrapping_add(previous_capacity >> 1)
                .wrapping_add(previous_capacity >> 3);
            core::cmp::max(previous_capacity.wrapping_add(INITIAL_CAPACITY), geometric_capacity)
        };
        let chunk = operator_new_checked(core::mem::size_of::<Record40ListNodePoolChunk>())
            as *mut Record40ListNodePoolChunk;
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
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    static mut ALLOCATIONS: [*mut u8; 6] = [ptr::null_mut(); 6];
    static mut SIZES: [usize; 6] = [0; 6];
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
    fn acquires_single_free_and_grown_record_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RECORD_40_LIST_NODE_POOL_ACQUIRE, 0x8000) else {
            note_missing_u32_fixture("cxx/record_40_list_node_pool_acquire");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x8000);
            ALLOCATIONS = [slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000), slab.add(0x4000), slab.add(0x5000)];
            SIZES = [0; 6];
            CURSOR = 0;
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let mut pool = Record40ListNodePool::default();
            let sentinel = record_40_list_node_pool_acquire(&mut pool, 1);
            assert_eq!(sentinel.cast::<u8>(), slab.add(0x1000));
            assert_eq!(SIZES[..2], [0x0c, NODE_SIZE]);
            assert_eq!((*sentinel).payload, [0xa5a5_a5a5; 10]);

            let next_free = slab.add(0x1100).cast::<Record40ListNode>();
            (*sentinel).next = pointer_word(next_free.cast());
            (*sentinel).previous = 7;
            pool.free = pointer_word(sentinel.cast());
            assert_eq!(record_40_list_node_pool_acquire(&mut pool, 0), sentinel);
            assert_eq!(pool.free, pointer_word(next_free.cast()));
            assert_eq!((*sentinel).previous, 7);

            let mut pool = Record40ListNodePool::default();
            assert_eq!(record_40_list_node_pool_acquire(&mut pool, 0).cast::<u8>(), slab.add(0x3000));
            assert_eq!(SIZES[2..4], [0x0c, 32 * NODE_SIZE]);
            pool.next = pool.end;
            assert_eq!(record_40_list_node_pool_acquire(&mut pool, 0).cast::<u8>(), slab.add(0x5000));
            assert_eq!(SIZES[4..6], [0x0c, 64 * NODE_SIZE]);
            let chunk = slab.add(0x4000).cast::<Record40ListNodePoolChunk>();
            assert_eq!((*chunk).previous, pointer_word(slab.add(0x2000)));
            assert_eq!((*chunk).capacity, 64);
        }
    }
}
