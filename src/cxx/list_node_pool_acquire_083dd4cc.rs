//! List node-pool acquire — original: `FUN_083dd4cc` at load address
//! `0x083dd4cc`.
//!
//! Raw `osos.dec` establishes the true 184-byte extent: 46 A32 words from
//! `push {r4-r8,lr}` at `0x083dd4cc` through `pop {r4-r8,pc}` at
//! `0x083dd580`; `0x083dd584` begins `list_node_pool_list_clear`. The body
//! contains two unconditional `bl` calls, both to `operator_new_checked` @
//! `0x08266c70`, and no predicated `bl` calls. It has two inbound plain `bl`
//! calls, from `list_node_pool_list_append_value` and `list_node_pool_list_init`.
//!
//! Pops a 12-byte `{next, previous, value}` node from `free`, or bump-allocates
//! one from a chunk. Empty pools allocate a 12-byte chunk header and backing
//! storage: one node for `single`, otherwise 32 initially and then
//! `max(capacity + 32, capacity + capacity/2 + capacity/8)`. Deliberate
//! deviations: none; target pointers remain `u32` words on every build.

use super::list_node_pool_list_init::{ListNode, ListNodePoolList};
use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x0c;

#[repr(C)]
struct ListNodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(ListNodePoolChunk, capacity)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(ListNodePoolChunk, nodes)];
const _: [u8; 0x0c] = [0; core::mem::size_of::<ListNodePoolChunk>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 {
    pointer as usize as u32
}

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut ListNode {
    word as usize as *mut ListNode
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut ListNodePoolChunk {
    word as usize as *mut ListNodePoolChunk
}

/// Acquires an uninitialized node from the embedded pool; `single != 0`
/// forces a one-node chunk for the list sentinel.
///
/// # Safety
///
/// `list` and its target pointer words must identify writable, aligned pool
/// storage. Checked allocations are dereferenced immediately, as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.list_node_pool_acquire_083dd4cc")]
#[inline(never)]
pub unsafe extern "C" fn list_node_pool_acquire_083dd4cc(
    list: *mut ListNodePoolList,
    single: u32,
) -> *mut ListNode {
    if (*list).free != 0 {
        let free = node_from_word((*list).free);
        (*list).free = (*free).next;
        return free;
    }

    if (*list).next == (*list).end {
        let capacity = if single != 0 {
            1
        } else if (*list).chunks == 0 {
            INITIAL_CAPACITY
        } else {
            let previous_capacity = (*chunk_from_word((*list).chunks)).capacity;
            core::cmp::max(
                previous_capacity + INITIAL_CAPACITY,
                previous_capacity + (previous_capacity >> 1) + (previous_capacity >> 3),
            )
        };
        let chunk = operator_new_checked(core::mem::size_of::<ListNodePoolChunk>())
            as *mut ListNodePoolChunk;
        let nodes = operator_new_checked(capacity as usize * NODE_SIZE);

        (*chunk).nodes = pointer_word(nodes);
        (*chunk).previous = (*list).chunks;
        (*chunk).capacity = capacity;
        (*list).chunks = pointer_word(chunk.cast());
        (*list).next = pointer_word(nodes);
        (*list).end = pointer_word(nodes.add(capacity as usize * NODE_SIZE));
    }

    let node = node_from_word((*list).next);
    (*list).next = pointer_word(node.cast::<u8>().add(NODE_SIZE));
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

    static mut ALLOCATIONS: [*mut u8; 8] = [ptr::null_mut(); 8];
    static mut SIZES: [usize; 8] = [0; 8];
    static mut CURSOR: usize = 0;

    unsafe extern "C" fn pool_alloc(_heap: *mut HeapDescriptorDescriptor, size: usize, _tag: usize) -> *mut u8 {
        let index = CURSOR;
        CURSOR += 1;
        ptr::addr_of_mut!(SIZES).cast::<usize>().add(index).write(size);
        ptr::addr_of!(ALLOCATIONS).cast::<*mut u8>().add(index).read()
    }

    #[test]
    fn acquires_free_single_initial_and_grown_nodes() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::LIST_NODE_POOL_ACQUIRE_083DD4CC, 0x8000) else {
            note_missing_u32_fixture("cxx/list_node_pool_acquire_083dd4cc");
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x8000);
            ptr::addr_of_mut!(ALLOCATIONS).write([slab, slab.add(0x1000), slab.add(0x2000), slab.add(0x3000), slab.add(0x4000), slab.add(0x5000), slab.add(0x6000), slab.add(0x7000)]);
            CURSOR = 0;
            ptr::addr_of_mut!(SIZES).write([0; 8]);
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let mut list = ListNodePoolList::default();
            let sentinel = list_node_pool_acquire_083dd4cc(&mut list, 1);
            assert_eq!(sentinel.cast::<u8>(), slab.add(0x1000));
            assert_eq!((SIZES[0], SIZES[1], list.next, list.end), (12, 12, pointer_word(slab.add(0x100c)), pointer_word(slab.add(0x100c))));
            assert_eq!((*slab.cast::<ListNodePoolChunk>()).capacity, 1);
            assert_eq!((*sentinel).value, 0xa5a5_a5a5);

            let next_free = slab.add(0x1040).cast::<ListNode>();
            (*sentinel).next = pointer_word(next_free.cast());
            (*sentinel).previous = 7;
            list.free = pointer_word(sentinel.cast());
            assert_eq!(list_node_pool_acquire_083dd4cc(&mut list, 0), sentinel);
            assert_eq!((list.free, (*sentinel).previous, CURSOR), (pointer_word(next_free.cast()), 7, 2));

            let mut list = ListNodePoolList::default();
            assert_eq!(list_node_pool_acquire_083dd4cc(&mut list, 0).cast::<u8>(), slab.add(0x3000));
            assert_eq!(SIZES[3], 32 * NODE_SIZE);
            list.next = list.end;
            assert_eq!(list_node_pool_acquire_083dd4cc(&mut list, 0).cast::<u8>(), slab.add(0x5000));
            assert_eq!(SIZES[5], 64 * NODE_SIZE);
            list.next = list.end;
            assert_eq!(list_node_pool_acquire_083dd4cc(&mut list, 0).cast::<u8>(), slab.add(0x7000));
            assert_eq!(SIZES[7], 104 * NODE_SIZE);
        }
    }
}
