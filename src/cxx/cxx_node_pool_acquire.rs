//! C++ red-black-tree node-pool acquire — retailOS `FUN_083be9e8` @ `0x083be9e8`.
//!
//! Raw `osos.dec` establishes the exact 184-byte extent: 46 A32 words from
//! `push {r4-r8,lr}` at `0x083be9e8` through `pop {r4-r8,pc}` at `0x083bea9c`;
//! `0x083beaa0` begins the next real function. The body has exactly two
//! unconditional plain `bl` calls, at `0x083bea4c` and `0x083bea60`, both to
//! `operator_new_checked` @ `0x08266c70`; it has no predicated `bl` calls.
//! Whole-image raw A32 decoding finds two inbound unconditional plain `bl`
//! sites, at `0x083bf264` and `0x083dbe90`, and no predicated inbound calls.
//!
//! The pool pops a recycled 20-byte red-black-tree node through its right link,
//! or allocates a 12-byte chunk header and a `capacity * 20` node arena.
//! Capacity starts at 32 and grows by `max(previous + 32, previous +
//! previous/2 + previous/8)`. Each returned node has its color and tree links
//! cleared while preserving its payload word at +0x10. Deliberate deviations:
//! none; target pointers remain `u32` words.

use crate::heap::new_handler::operator_new_checked;

const INITIAL_CAPACITY: u32 = 32;
const NODE_SIZE: usize = 0x14;

/// Target-layout 20-byte red-black-tree node.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CxxNodePoolNode {
    pub color: u8,
    _padding: [u8; 3],
    pub parent: u32,
    pub left: u32,
    pub right: u32,
    pub payload: u32,
}

/// The four target-width pool fields at the start of the owning container.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CxxNodePool {
    pub chunks: u32,
    pub free: u32,
    pub next: u32,
    pub end: u32,
}

#[repr(C)]
struct CxxNodePoolChunk {
    previous: u32,
    capacity: u32,
    nodes: u32,
}

const _: [u8; 0x14] = [0; core::mem::size_of::<CxxNodePoolNode>()];
const _: [u8; 0x10] = [0; core::mem::size_of::<CxxNodePool>()];
const _: [u8; 0x0c] = [0; core::mem::size_of::<CxxNodePoolChunk>()];

#[inline(always)]
fn pointer_word(pointer: *mut u8) -> u32 { pointer as usize as u32 }

#[inline(always)]
unsafe fn node_from_word(word: u32) -> *mut CxxNodePoolNode {
    word as usize as *mut CxxNodePoolNode
}

#[inline(always)]
unsafe fn chunk_from_word(word: u32) -> *mut CxxNodePoolChunk {
    word as usize as *mut CxxNodePoolChunk
}

/// Acquires and initializes one red-black-tree node from `pool`.
///
/// # Safety
///
/// `pool` and every nonzero target pointer word it contains must designate
/// writable target-layout objects. As in retailOS, allocation failure is not
/// handled before the returned storage is written.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cxx_node_pool_acquire")]
#[inline(never)]
pub unsafe extern "C" fn cxx_node_pool_acquire(
    pool: *mut CxxNodePool,
) -> *mut CxxNodePoolNode {
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
                    previous_capacity
                        .wrapping_add(previous_capacity >> 1)
                        .wrapping_add(previous_capacity >> 3),
                )
            };
            let chunk = operator_new_checked(core::mem::size_of::<CxxNodePoolChunk>())
                as *mut CxxNodePoolChunk;
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
    fn pops_a_recycled_node_and_resets_only_tree_fields() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::CXX_NODE_POOL_ACQUIRE, 0x1000) else { return; };
        unsafe {
            slab.write_bytes(0xa5, 0x1000);
            let pool = slab.cast::<CxxNodePool>();
            let node = slab.add(0x100).cast::<CxxNodePoolNode>();
            let next_free = slab.add(0x200).cast::<CxxNodePoolNode>();
            (*pool).free = pointer_word(node.cast());
            (*node).color = 1;
            (*node).parent = 0x1111_1111;
            (*node).left = 0x2222_2222;
            (*node).right = pointer_word(next_free.cast());
            (*node).payload = 0xfeed_beef;

            assert_eq!(cxx_node_pool_acquire(pool), node);
            assert_eq!((*pool).free, pointer_word(next_free.cast()));
            assert_eq!((*node).color, 0);
            assert_eq!((*node).parent, 0);
            assert_eq!((*node).left, 0);
            assert_eq!((*node).right, 0);
            assert_eq!((*node).payload, 0xfeed_beef);
        }
    }
}
