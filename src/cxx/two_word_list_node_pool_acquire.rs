//! `two_word_list_node_pool_acquire` — retailOS `FUN_083dcb1c` @ `0x083dcb1c`.
//!
//! Raw `osos.dec` establishes the true 176-byte extent: 44 A32 words from
//! `push {r4-r6,lr}` through `pop {r4-r6,pc}` at `0x083dcbc8`; `0x083dcbcc`
//! begins the next real function. The body has exactly two unconditional plain
//! `bl` calls, both to `operator_new_checked` @ `0x08266c70`, and no predicated
//! `bl` calls. It acquires an uninitialized 16-byte doubly-linked node with two
//! payload words: pop `free`, otherwise bump from a chunk; exhausted pools
//! allocate a 12-byte header and `capacity * 16` backing storage. `single != 0`
//! selects one node; otherwise capacity starts at 32 and grows by
//! `max(old + 32, old + old/2 + old/8)`. Deliberate deviations: none; target
//! pointers remain `u32` words on host and target.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x10;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TwoWordListNode {
    pub next: u32,
    pub previous: u32,
    pub first: u32,
    pub second: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(TwoWordListNode, previous)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(TwoWordListNode, first)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<TwoWordListNode>()];

#[repr(C)]
struct TwoWordListNodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x0c] = [0; core::mem::size_of::<TwoWordListNodePoolChunk>()];

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TwoWordListNodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

const _: [u8; 0x10] = [0; core::mem::size_of::<TwoWordListNodePool>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut TwoWordListNode {
    word as usize as *mut TwoWordListNode
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut TwoWordListNodePoolChunk {
    word as usize as *mut TwoWordListNodePoolChunk
}

/// Acquires an uninitialized two-word list node from `pool`.
///
/// # Safety
///
/// `pool` and all nonzero target pointer words it contains must designate
/// writable target-layout objects. The checked allocator's storage is written
/// immediately, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.two_word_list_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn two_word_list_node_pool_acquire(
    pool: *mut TwoWordListNodePool,
    single: u32,
) -> *mut TwoWordListNode {
    if (*pool).free != 0 {
        let node = node_from_word((*pool).free);
        (*pool).free = (*node).next;
        return node;
    }

    if (*pool).next == (*pool).end {
        let capacity = if single != 0 {
            1
        } else if (*pool).chunks == 0 {
            INITIAL_CAPACITY
        } else {
            let previous = (*chunk_from_word((*pool).chunks)).capacity;
            core::cmp::max(
                previous.wrapping_add(INITIAL_CAPACITY),
                previous.wrapping_add(previous >> 1).wrapping_add(previous >> 3),
            )
        };
        let chunk = operator_new_checked(core::mem::size_of::<TwoWordListNodePoolChunk>())
            as *mut TwoWordListNodePoolChunk;
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
        ptr::addr_of_mut!(SIZES).cast::<usize>().add(index).write(size);
        ptr::addr_of!(ALLOCATIONS).cast::<*mut u8>().add(index).read()
    }

    #[test]
    fn acquires_free_single_initial_and_grown_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::TWO_WORD_LIST_NODE_POOL_ACQUIRE, 0x8000) else {
            note_missing_u32_fixture("cxx/two_word_list_node_pool_acquire");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x8000);
            ptr::addr_of_mut!(ALLOCATIONS).write([
                slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000),
                slab.add(0x4000), slab.add(0x5000),
            ]);
            CURSOR = 0;
            ptr::addr_of_mut!(SIZES).write([0; 6]);
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let mut pool = TwoWordListNodePool::default();
            let single = two_word_list_node_pool_acquire(&mut pool, 1);
            assert_eq!(single.cast::<u8>(), slab.add(0x1000));
            assert_eq!(SIZES, [0x0c, NODE_SIZE, 0, 0, 0, 0]);
            assert_eq!((*single).first, 0xa5a5_a5a5);
            let free_next = slab.add(0x1040).cast::<TwoWordListNode>();
            (*single).next = pointer_word(free_next.cast());
            (*single).second = 7;
            pool.free = pointer_word(single.cast());
            assert_eq!(two_word_list_node_pool_acquire(&mut pool, 0), single);
            assert_eq!(pool.free, pointer_word(free_next.cast()));
            assert_eq!((*single).second, 7);

            let mut pool = TwoWordListNodePool::default();
            assert_eq!(two_word_list_node_pool_acquire(&mut pool, 0).cast::<u8>(), slab.add(0x3000));
            assert_eq!(SIZES[2], 0x0c);
            assert_eq!(SIZES[3], 32 * NODE_SIZE);
            pool.next = pool.end;
            assert_eq!(two_word_list_node_pool_acquire(&mut pool, 0).cast::<u8>(), slab.add(0x5000));
            assert_eq!(SIZES[4], 0x0c);
            assert_eq!(SIZES[5], 64 * NODE_SIZE);
            let chunk = slab.add(0x4000).cast::<TwoWordListNodePoolChunk>();
            assert_eq!((*chunk).previous, pointer_word(slab.add(0x2000)));
            assert_eq!((*chunk).capacity, 64);
        }
    }
}
