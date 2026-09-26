//! `app_block_manager_node_pool_acquire` — retailOS `FUN_083dcc80` @ `0x083dcc80`.
//!
//! Raw `osos.dec` establishes the true 184-byte extent: 46 A32 words from
//! `push {r4-r6,lr}` through `pop {r4-r6,pc}` at `0x083dcd34`; `0x083dcd38`
//! begins the next real function. The body has exactly two unconditional plain
//! `bl` calls, both to `operator_new_checked` @ `0x08266c70`, and no predicated
//! `bl` calls. It has two inbound unconditional plain `bl` calls at
//! `0x081a7dec` and `0x081a7f40`.
//!
//! The helper pops an uninitialized 56-byte application-block-manager node from
//! `pool.free`, or bump-allocates one from a chunk. Empty pools allocate a
//! 12-byte `{previous, capacity, nodes}` chunk header and a `capacity * 56`
//! node arena. `single != 0` requests one node; otherwise the first capacity is
//! 32 and later capacities are `max(old + 32, old + old/2 + old/8)`. Deliberate
//! deviations: none; target pointer fields remain `u32` words.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = core::mem::size_of::<AppBlockManagerNode>();

/// Target-layout pool state at application-block-manager +0x18.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AppBlockManagerNodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

/// Opaque 56-byte intrusive-list node owned by the application block manager.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct AppBlockManagerNode {
    pub next: u32,
    pub previous: u32,
    pub words: [u32; 12],
}

#[repr(C)]
struct AppBlockManagerNodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x10] = [0; core::mem::size_of::<AppBlockManagerNodePool>()];
const _: [u8; 0x38] = [0; core::mem::size_of::<AppBlockManagerNode>()];
const _: [u8; 0x0c] = [0; core::mem::size_of::<AppBlockManagerNodePoolChunk>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut AppBlockManagerNode {
    word as usize as *mut AppBlockManagerNode
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut AppBlockManagerNodePoolChunk {
    word as usize as *mut AppBlockManagerNodePoolChunk
}

/// Acquires an uninitialized application-block-manager node from `pool`.
///
/// # Safety
///
/// `pool` must be writable, and all nonzero target pointer words in its state
/// must designate valid target-layout nodes or chunks. The checked allocator's
/// returned storage is immediately written, as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.app_block_manager_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn app_block_manager_node_pool_acquire(
    pool: *mut AppBlockManagerNodePool,
    single: u32,
) -> *mut AppBlockManagerNode {
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
            let previous_capacity = (*chunk_from_word((*pool).chunks)).capacity;
            core::cmp::max(
                previous_capacity.wrapping_add(INITIAL_CAPACITY),
                previous_capacity
                    .wrapping_add(previous_capacity >> 1)
                    .wrapping_add(previous_capacity >> 3),
            )
        };
        let chunk = operator_new_checked(core::mem::size_of::<AppBlockManagerNodePoolChunk>())
            as *mut AppBlockManagerNodePoolChunk;
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
    fn acquires_free_single_initial_and_grown_application_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::APP_BLOCK_MANAGER_NODE_POOL_ACQUIRE, 0x8000) else {
            note_missing_u32_fixture("cxx/app_block_manager_node_pool_acquire");
            return;
        };

        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x8000);
            ptr::addr_of_mut!(ALLOCATIONS).write([
                slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000),
                slab.add(0x4000), slab.add(0x5000),
            ]);
            ALLOCATION_CURSOR = 0;
            ptr::addr_of_mut!(ALLOCATION_SIZES).write([0; 6]);
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let mut pool = AppBlockManagerNodePool::default();
            let single = app_block_manager_node_pool_acquire(&mut pool, 1);
            assert_eq!(single.cast::<u8>(), slab.add(0x1000));
            assert_eq!(ALLOCATION_CURSOR, 2);
            assert_eq!(ALLOCATION_SIZES, [0x0c, NODE_SIZE, 0, 0, 0, 0]);
            assert_eq!((*single).words[0], 0xa5a5_a5a5);
            assert_eq!(pool.next, pointer_word(slab.add(0x1000 + NODE_SIZE)));
            assert_eq!(pool.end, pointer_word(slab.add(0x1000 + NODE_SIZE)));

            let free_next = slab.add(0x1080).cast::<AppBlockManagerNode>();
            (*single).next = pointer_word(free_next.cast());
            (*single).words[3] = 7;
            pool.free = pointer_word(single.cast());
            assert_eq!(app_block_manager_node_pool_acquire(&mut pool, 0), single);
            assert_eq!(pool.free, pointer_word(free_next.cast()));
            assert_eq!((*single).words[3], 7);
            assert_eq!(ALLOCATION_CURSOR, 2);

            let mut pool = AppBlockManagerNodePool::default();
            assert_eq!(app_block_manager_node_pool_acquire(&mut pool, 0).cast::<u8>(), slab.add(0x3000));
            assert_eq!(ALLOCATION_SIZES[2], 0x0c);
            assert_eq!(ALLOCATION_SIZES[3], 32 * NODE_SIZE);
            pool.next = pool.end;
            assert_eq!(app_block_manager_node_pool_acquire(&mut pool, 0).cast::<u8>(), slab.add(0x5000));
            assert_eq!(ALLOCATION_SIZES[4], 0x0c);
            assert_eq!(ALLOCATION_SIZES[5], 64 * NODE_SIZE);
            let grown = slab.add(0x4000).cast::<AppBlockManagerNodePoolChunk>();
            assert_eq!((*grown).previous, pointer_word(slab.add(0x2000)));
            assert_eq!((*grown).capacity, 64);
        }
    }
}
