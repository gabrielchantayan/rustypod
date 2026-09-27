//! Red-black-tree node-pool acquire — retailOS `FUN_083ba9b8` @ `0x083ba9b8`.
//!
//! Raw `osos.dec` establishes the exact 184-byte extent: 46 A32 words from
//! `push {r4-r8,lr}` at `0x083ba9b8` through `pop {r4-r8,pc}` at `0x083baa6c`;
//! `0x083baa70` begins the next real function. The body has two unconditional
//! plain `bl` calls, at `0x083baa1c` and `0x083baa30`, both to
//! `operator_new_checked` @ `0x08266c70`, and no predicated `bl` calls.
//!
//! Pops a recycled 20-byte red-black-tree node through its right-link word, or
//! allocates a 12-byte chunk header and a `capacity * 20` arena. Capacity starts
//! at 32 and grows by `max(previous + 32, previous + previous/2 + previous/8)`.
//! It clears the color byte and three tree-link words while preserving the
//! payload word at +0x10. Deliberate deviations: none; target pointers remain
//! `u32` words to preserve the 32-bit firmware layout on hosts.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x14;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreeNode083ba9b8 {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub payload: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RedBlackTreeNodePool083ba9b8 {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

#[repr(C)]
struct NodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x14] = [0; core::mem::size_of::<RedBlackTreeNode083ba9b8>()];
const _: [u8; 0x10] = [0; core::mem::size_of::<RedBlackTreeNodePool083ba9b8>()];
const _: [u8; 0x0c] = [0; core::mem::size_of::<NodePoolChunk>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut RedBlackTreeNode083ba9b8 {
    word as usize as *mut RedBlackTreeNode083ba9b8
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut NodePoolChunk {
    word as usize as *mut NodePoolChunk
}

/// Acquires and initializes one node from `pool`.
///
/// # Safety
///
/// `pool` and every nonzero target pointer word it contains must designate
/// writable target-layout objects. Checked-allocation failure is immediately
/// dereferenced, matching retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_node_pool_acquire_083ba9b8")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_node_pool_acquire_083ba9b8(
    pool: *mut RedBlackTreeNodePool083ba9b8,
) -> *mut RedBlackTreeNode083ba9b8 {
    let node = if (*pool).free != 0 {
        let free = node_from_word((*pool).free);
        (*pool).free = (*free).right;
        free
    } else {
        if (*pool).next == (*pool).end {
            let capacity = if (*pool).chunks == 0 {
                INITIAL_CAPACITY
            } else {
                let previous_capacity = (*chunk_from_word((*pool).chunks)).capacity;
                core::cmp::max(
                    previous_capacity.wrapping_add(INITIAL_CAPACITY),
                    previous_capacity.wrapping_add(previous_capacity >> 1).wrapping_add(previous_capacity >> 3),
                )
            };
            let chunk = operator_new_checked(core::mem::size_of::<NodePoolChunk>()) as *mut NodePoolChunk;
            let nodes = operator_new_checked(capacity as usize * NODE_SIZE);
            (*chunk).nodes = pointer_word(nodes);
            (*chunk).previous = (*pool).chunks;
            (*chunk).capacity = capacity;
            (*pool).chunks = pointer_word(chunk.cast());
            (*pool).next = pointer_word(nodes);
            (*pool).end = pointer_word(nodes.add(capacity as usize * NODE_SIZE));
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
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn advances_an_arena_and_recycles_a_node_without_touching_payload() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_NODE_POOL_ACQUIRE_083BA9B8, 0x1000) else { return; };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let pool = slab.cast::<RedBlackTreeNodePool083ba9b8>();
            pool.write(RedBlackTreeNodePool083ba9b8::default());
            let first = slab.add(0x100).cast::<RedBlackTreeNode083ba9b8>();
            let recycled = slab.add(0x200).cast::<RedBlackTreeNode083ba9b8>();
            (*pool).next = pointer_word(first.cast());
            (*pool).end = pointer_word(first.cast::<u8>().add(NODE_SIZE * 2));

            assert_eq!(red_black_tree_node_pool_acquire_083ba9b8(pool), first);
            assert_eq!((*pool).next, pointer_word(first.cast::<u8>().add(NODE_SIZE)));
            assert_eq!((*first).color, 0);
            assert_eq!((*first).parent, 0);
            assert_eq!((*first).left, 0);
            assert_eq!((*first).right, 0);
            assert_eq!((*first).payload, 0xa5a5_a5a5);

            (*recycled).color = 1;
            (*recycled).parent = 0x1111_1111;
            (*recycled).left = 0x2222_2222;
            (*recycled).right = pointer_word(first.cast());
            (*recycled).payload = 0xfeed_beef;
            (*pool).free = pointer_word(recycled.cast());
            assert_eq!(red_black_tree_node_pool_acquire_083ba9b8(pool), recycled);
            assert_eq!((*pool).free, pointer_word(first.cast()));
            assert_eq!((*recycled).color, 0);
            assert_eq!((*recycled).parent, 0);
            assert_eq!((*recycled).left, 0);
            assert_eq!((*recycled).right, 0);
            assert_eq!((*recycled).payload, 0xfeed_beef);
        }
    }
}
