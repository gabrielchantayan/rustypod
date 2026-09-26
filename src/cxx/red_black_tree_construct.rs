//! Red-black-tree constructor — retailOS `FUN_083dc014` at load address
//! `0x083dc014` (88 bytes).
//!
//! Raw `osos.dec` establishes the exact 22-word A32 extent from `push
//! {r4-r6,lr}` at `0x083dc014` through `pop {r4-r6,pc}` at `0x083dc068`;
//! `0x083dc06c` starts the next separately linked function. Whole-image
//! decoding finds two inbound direct calls, both unconditional plain `bl`;
//! the body has one unconditional plain `bl`, to
//! `red_black_tree_node_pool_acquire` at `0x083cc1d0`, and no predicated
//! `bl` calls.
//!
//! Clears the tree's node pool, root, count, and state byte, copies its
//! one-byte comparator state, then acquires and self-links an empty sentinel
//! node through its left and right links. Deliberate deviations: none;
//! pointers remain target-width words so the target layout is preserved on
//! hosts.

use super::red_black_tree_node_pool_acquire::{
    red_black_tree_node_pool_acquire, RedBlackTreeNodePool,
};
use core::ptr::addr_of_mut;

/// Target-layout red-black tree header with its comparator's one-byte state.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTree {
    pub pool: RedBlackTreeNodePool,
    pub sentinel: u32,
    pub count: u32,
    pub state: u8,
    pub comparator_state: u8,
}

const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTree, sentinel)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(RedBlackTree, count)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(RedBlackTree, state)];
const _: [u8; 0x19] = [0; core::mem::offset_of!(RedBlackTree, comparator_state)];

/// Initializes an empty tree and its self-linked sentinel.
///
/// # Safety
///
/// `tree` and `comparator_state` must be valid for their respective writes and
/// reads. The configured heap must provide writable target-addressable storage
/// for the sentinel node pool.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_construct")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_construct(
    tree: *mut RedBlackTree,
    comparator_state: *const u8,
) -> *mut RedBlackTree {
    addr_of_mut!((*tree).pool.chunks).write(0);
    addr_of_mut!((*tree).sentinel).write(0);
    addr_of_mut!((*tree).count).write(0);
    addr_of_mut!((*tree).state).write(0);
    addr_of_mut!((*tree).comparator_state).write(comparator_state.read());
    addr_of_mut!((*tree).pool.end).write(0);
    addr_of_mut!((*tree).pool.next).write(0);
    addr_of_mut!((*tree).pool.free).write(0);
    let sentinel = red_black_tree_node_pool_acquire(addr_of_mut!((*tree).pool));
    let sentinel_word = sentinel as usize as u32;
    addr_of_mut!((*tree).sentinel).write(sentinel_word);
    addr_of_mut!((*sentinel).parent).write(0);
    addr_of_mut!((*sentinel).left).write(sentinel_word);
    addr_of_mut!((*sentinel).right).write(sentinel_word);
    tree
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::red_black_tree_node_pool_acquire::RedBlackTreePooledNode;
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
    fn clears_header_copies_state_and_self_links_sentinel() {
        let _lock = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_CONSTRUCT, 0x1000) else {
            note_missing_u32_fixture("cxx/red_black_tree_construct");
            return;
        };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let tree = slab.cast::<RedBlackTree>();
            let chunk = slab.add(0x200);
            let sentinel = slab.add(0x300).cast::<RedBlackTreePooledNode>();
            let comparator_state = slab.add(0x500);
            comparator_state.write(0x5a);
            ALLOCATIONS = [chunk, sentinel.cast()];
            ALLOCATION_CURSOR = 0;
            let _heap = crate::heap::veneers::tests::mock_heap();
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = pool_alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);

            assert_eq!(red_black_tree_construct(tree, comparator_state), tree);
            let sentinel_word = sentinel as usize as u32;
            assert_eq!(((*tree).pool.free, (*tree).count, (*tree).state), (0, 0, 0));
            assert_eq!((*tree).comparator_state, 0x5a);
            assert_eq!(((*tree).sentinel, (*sentinel).left, (*sentinel).right),
                (sentinel_word, sentinel_word, sentinel_word));
            assert_eq!((*sentinel).parent, 0);
            assert_eq!(ALLOCATION_CURSOR, 2);
        }
    }
}
