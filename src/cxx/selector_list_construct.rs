//! `selector_list_construct` — retailOS `FUN_083dbd0c` @ `0x083dbd0c`.
//!
//! Raw `osos.dec` establishes the exact 88-byte, twenty-two-word A32 extent
//! from `push {r4,r5,r6,lr}` at `0x083dbd0c` through `pop {r4,r5,r6,pc}` at
//! `0x083dbd60`; `0x083dbd64` begins the next real function. The body has one
//! unconditional plain `bl`, to the 24-byte-node pool acquire helper at
//! `0x083cd680`, and no predicated `bl` calls. The two inbound plain `bl` sites
//! are both in `FUN_081e1594`; no predicated inbound call sites were found.
//!
//! Clears a selector-tagged 26-byte list header, obtains its 24-byte sentinel,
//! and makes the sentinel's links self-referential. Deliberate deviation: the
//! unported `0x083cd680` helper is reproduced privately here rather than exposed
//! as a separate Rust seam; its verified allocation and initialization effects
//! are preserved.

use crate::heap::new_handler::operator_new_checked;
use core::ptr::addr_of_mut;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 24;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SelectorListPoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SelectorListNode {
    unused: u32,
    next: u32,
    previous: u32,
    owner: u32,
    payload: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SelectorListPool {
    chunks: u32,
    free: u32,
    next: u32,
    end: u32,
}

/// Target-layout selector list. The selector is deliberately byte-addressed at
/// offset 25, as it is in the retail constructor.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SelectorList {
    pool: SelectorListPool,
    sentinel: u32,
    count: u32,
    initialized: u8,
    pub selector: u8,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(SelectorListPool, free)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(SelectorListPool, next)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(SelectorListPool, end)];
const _: [u8; 0x10] = [0; core::mem::size_of::<SelectorListPool>()];
const _: [u8; 0x04] = [0; core::mem::offset_of!(SelectorListNode, next)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(SelectorListNode, previous)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(SelectorListNode, owner)];
const _: [u8; NODE_SIZE] = [0; core::mem::size_of::<SelectorListNode>()];
const _: [u8; 0x10] = [0; core::mem::offset_of!(SelectorList, sentinel)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(SelectorList, count)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(SelectorList, initialized)];
const _: [u8; 0x19] = [0; core::mem::offset_of!(SelectorList, selector)];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(never)]
unsafe fn selector_list_node_pool_acquire(pool: *mut SelectorListPool) -> *mut SelectorListNode {
    if (*pool).free != 0 {
        let node = (*pool).free as usize as *mut SelectorListNode;
        (*pool).free = (*node).owner;
        return node;
    }

    if (*pool).next == (*pool).end {
        let capacity = if (*pool).chunks == 0 {
            INITIAL_CAPACITY
        } else {
            let chunk = (*pool).chunks as usize as *mut SelectorListPoolChunk;
            let old_capacity = (*chunk).capacity;
            core::cmp::max(
                old_capacity.wrapping_add(INITIAL_CAPACITY),
                old_capacity.wrapping_add(old_capacity >> 1).wrapping_add(old_capacity >> 3),
            )
        };
        let chunk = operator_new_checked(core::mem::size_of::<SelectorListPoolChunk>())
            as *mut SelectorListPoolChunk;
        let nodes = operator_new_checked(capacity as usize * NODE_SIZE);
        (*chunk).nodes = pointer_word(nodes);
        (*chunk).previous = (*pool).chunks;
        (*chunk).capacity = capacity;
        (*pool).chunks = pointer_word(chunk.cast());
        (*pool).next = pointer_word(nodes);
        (*pool).end = pointer_word(nodes.add(capacity as usize * NODE_SIZE));
    }

    let node = (*pool).next as usize as *mut SelectorListNode;
    (*pool).next = pointer_word(node.cast::<u8>().add(NODE_SIZE));
    addr_of_mut!((*node).unused).write(0);
    addr_of_mut!((*node).next).write(0);
    addr_of_mut!((*node).previous).write(0);
    addr_of_mut!((*node).owner).write(0);
    node
}

/// Initializes `list` with a selector byte and an empty self-linked sentinel.
///
/// # Safety
///
/// `list` must identify writable target-layout storage. The configured heap
/// must return writable target-addressable storage for the sentinel chunk.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.selector_list_construct")]
#[inline(never)]
pub unsafe extern "C" fn selector_list_construct(
    list: *mut SelectorList,
    selector: *const u8,
) -> *mut SelectorList {
    addr_of_mut!((*list).pool.chunks).write(0);
    addr_of_mut!((*list).sentinel).write(0);
    addr_of_mut!((*list).count).write(0);
    addr_of_mut!((*list).initialized).write(0);
    addr_of_mut!((*list).selector).write(selector.read());
    addr_of_mut!((*list).pool.end).write(0);
    addr_of_mut!((*list).pool.next).write(0);
    addr_of_mut!((*list).pool.free).write(0);
    let sentinel = selector_list_node_pool_acquire(addr_of_mut!((*list).pool));
    let sentinel_word = pointer_word(sentinel.cast());
    addr_of_mut!((*list).sentinel).write(sentinel_word);
    addr_of_mut!((*sentinel).next).write(0);
    addr_of_mut!((*sentinel).previous).write(sentinel_word);
    addr_of_mut!((*sentinel).owner).write(sentinel_word);
    list
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATIONS: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut ALLOCATION_CURSOR: usize = 0;

    unsafe extern "C" fn pool_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        _size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let allocation = ALLOCATIONS[ALLOCATION_CURSOR];
        ALLOCATION_CURSOR += 1;
        allocation
    }

    #[test]
    fn clears_header_copies_selector_and_self_links_sentinel() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SELECTOR_LIST_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture("cxx/selector_list_construct");
            return;
        };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let list = slab.cast::<SelectorList>();
            let chunk = slab.add(0x200);
            let sentinel = slab.add(0x300).cast::<SelectorListNode>();
            ALLOCATIONS = [chunk, sentinel.cast()];
            ALLOCATION_CURSOR = 0;
            let _heap = crate::heap::veneers::tests::mock_heap();
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            let selector = 0x5au8;
            assert_eq!(selector_list_construct(list, &selector), list);
            assert_eq!(((*list).pool.next, (*list).pool.end),
                (sentinel as usize as u32 + NODE_SIZE as u32, sentinel as usize as u32 + (INITIAL_CAPACITY as usize * NODE_SIZE) as u32));
            assert_eq!(((*list).sentinel, (*sentinel).unused, (*sentinel).next, (*sentinel).previous, (*sentinel).owner),
                (sentinel as usize as u32, 0, 0, sentinel as usize as u32, sentinel as usize as u32));
            assert_eq!(ALLOCATION_CURSOR, 2);
        }
    }
}
