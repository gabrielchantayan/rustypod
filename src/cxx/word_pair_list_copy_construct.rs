//! `word_pair_list_copy_construct` — original: `FUN_083dd0dc` @ `0x083dd0dc`.
//!
//! Raw `osos.dec` establishes the true 144-byte extent: 36 A32 words from
//! `push {r0-r8,lr}` through `pop {r4-r8,pc}` at `0x083dd168`; `0x083dd16c`
//! begins the next function. The body has two unconditional plain `bl` calls,
//! to the 16-byte node-pool acquire helper @ `0x083dd0bc` and pair-node append
//! helper @ `0x083dd048`, and no predicated `bl` calls.
//!
//! It initializes a target-width intrusive list with a fresh sentinel, then
//! copies each `{first, second}` value pair from the source ring in order.
//! Deliberate deviation: the two unported helpers are inlined so the exported
//! port remains self-contained; their pool and ring operations are preserved.

use crate::heap::new_handler::operator_new_checked;

const NODE_SIZE: usize = 0x10;
const INITIAL_CAPACITY: u32 = 32;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WordPairListNode {
    pub next: u32,
    pub previous: u32,
    pub first: u32,
    pub second: u32,
}

const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<WordPairListNode>()];

#[repr(C)]
struct NodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WordPairList {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
    pub sentinel: u32,
    pub state: u32,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(WordPairList, sentinel)];
const _: [u8; 0x18] = [0; core::mem::size_of::<WordPairList>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut WordPairListNode {
    word as usize as *mut WordPairListNode
}

pub(crate) unsafe fn acquire_node(list: *mut WordPairList, single: u32) -> *mut WordPairListNode {
    if (*list).free != 0 {
        let node = node_from_word((*list).free);
        (*list).free = (*node).next;
        return node;
    }
    if (*list).next == (*list).end {
        let capacity = if single != 0 { 1 } else if (*list).chunks == 0 {
            INITIAL_CAPACITY
        } else {
            let chunk = (*list).chunks as usize as *mut NodePoolChunk;
            let previous = (*chunk).capacity;
            core::cmp::max(previous.wrapping_add(INITIAL_CAPACITY), previous.wrapping_add(previous >> 1).wrapping_add(previous >> 3))
        };
        let chunk = operator_new_checked(core::mem::size_of::<NodePoolChunk>()) as *mut NodePoolChunk;
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

/// Constructs `destination` as a value-pair copy of `source`.
///
/// # Safety
///
/// Both list owners and every node reached through `source` must be valid
/// target-layout objects. `destination` must be writable and its allocator
/// must return writable target-addressable storage when its free list is empty.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_pair_list_copy_construct(
    destination: *mut WordPairList,
    source: *const WordPairList,
) -> *mut WordPairList {
    (*destination).chunks = 0;
    (*destination).free = 0;
    (*destination).next = 0;
    (*destination).end = 0;
    (*destination).sentinel = 0;
    (*destination).state = 0;

    let sentinel = acquire_node(destination, 1);
    let sentinel_word = pointer_word(sentinel.cast());
    (*destination).sentinel = sentinel_word;
    (*sentinel).next = sentinel_word;
    (*sentinel).previous = sentinel_word;

    let source_sentinel = (*source).sentinel;
    let mut source_node = (*node_from_word(source_sentinel)).next;
    while source_node != source_sentinel {
        let source_value = node_from_word(source_node);
        let node = acquire_node(destination, 0);
        (*node).first = (*source_value).first;
        (*node).second = (*source_value).second;
        (*node).next = sentinel_word;
        let previous = (*sentinel).previous;
        (*node).previous = previous;
        (*node_from_word(previous)).next = pointer_word(node.cast());
        (*sentinel).previous = pointer_word(node.cast());
        (*destination).state = (*destination).state.wrapping_add(1);
        source_node = (*source_value).next;
    }
    destination
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use core::ptr;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    static mut ALLOCATIONS: [*mut u8; 6] = [ptr::null_mut(); 6];
    static mut ALLOCATION_CURSOR: usize = 0;

    unsafe extern "C" fn pool_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        _size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let result = ALLOCATIONS[ALLOCATION_CURSOR];
        ALLOCATION_CURSOR += 1;
        result
    }

    #[test]
    fn copies_empty_and_multi_node_rings_in_order() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::WORD_PAIR_LIST_COPY_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture("cxx/word_pair_list_copy_construct");
            return;
        };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let source = slab.cast::<WordPairList>();
            let source_sentinel = slab.add(0x100).cast::<WordPairListNode>();
            let source_first = slab.add(0x120).cast::<WordPairListNode>();
            let source_second = slab.add(0x140).cast::<WordPairListNode>();
            (*source).sentinel = pointer_word(source_sentinel.cast());
            (*source_sentinel).next = pointer_word(source_first.cast());
            (*source_sentinel).previous = pointer_word(source_second.cast());
            (*source_first).next = pointer_word(source_second.cast());
            (*source_first).previous = pointer_word(source_sentinel.cast());
            (*source_first).first = 1;
            (*source_first).second = 2;
            (*source_second).next = pointer_word(source_sentinel.cast());
            (*source_second).previous = pointer_word(source_first.cast());
            (*source_second).first = 3;
            (*source_second).second = 4;

            ptr::addr_of_mut!(ALLOCATIONS).write([
                slab.add(0x800), slab.add(0x900), slab.add(0xa00), slab.add(0xb00),
                slab.add(0xc00), slab.add(0xd00),
            ]);
            ALLOCATION_CURSOR = 0;
            let _heap = crate::heap::veneers::tests::mock_heap();
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            let destination = slab.add(0x200).cast::<WordPairList>();
            let destination_sentinel = slab.add(0x900).cast::<WordPairListNode>();
            let destination_first = slab.add(0xb00).cast::<WordPairListNode>();
            let destination_second = slab.add(0xb10).cast::<WordPairListNode>();

            assert_eq!(word_pair_list_copy_construct(destination, source), destination);
            assert_eq!((*destination).sentinel, pointer_word(destination_sentinel.cast()));
            assert_eq!((*destination).state, 2);
            assert_eq!((*destination_sentinel).next, pointer_word(destination_first.cast()));
            assert_eq!((*destination_sentinel).previous, pointer_word(destination_second.cast()));
            assert_eq!(((*destination_first).first, (*destination_first).second), (1, 2));
            assert_eq!(((*destination_second).first, (*destination_second).second), (3, 4));
            assert_eq!((*source_sentinel).next, pointer_word(source_first.cast()));

            let empty = slab.add(0x400).cast::<WordPairList>();
            let empty_sentinel = slab.add(0x500).cast::<WordPairListNode>();
            (*empty).sentinel = pointer_word(empty_sentinel.cast());
            (*empty_sentinel).next = pointer_word(empty_sentinel.cast());
            (*empty_sentinel).previous = pointer_word(empty_sentinel.cast());
            let empty_destination = slab.add(0x600).cast::<WordPairList>();
            let empty_destination_sentinel = slab.add(0xd00).cast::<WordPairListNode>();
            word_pair_list_copy_construct(empty_destination, empty);
            assert_eq!((*empty_destination).state, 0);
            assert_eq!((*empty_destination_sentinel).next, pointer_word(empty_destination_sentinel.cast()));
            assert_eq!((*empty_destination_sentinel).previous, pointer_word(empty_destination_sentinel.cast()));
            assert_eq!(ALLOCATION_CURSOR, 6);
        }
    }
}
