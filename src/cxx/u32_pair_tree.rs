//! Pool allocator for a libstdc++ red-black tree whose payload is two u32 words.
//!
//! `u32_pair_tree_allocate_node` — original: `FUN_083cd680` @ 0x083cd680
//! (184 bytes, 46 A32 words through `pop {r4-r8,pc}` at 0x083cd734; the
//! independently entered next function begins at 0x083cd738). Raw whole-image
//! decoding finds two inbound plain unconditional `bl` sites (0x083cdff4 and
//! 0x083dbd48), no predicated `bl` sites, and two unconditional internal calls
//! to `operator_new_checked` @ 0x08266c70.
//!
//! The pool's first four target words are `{chunks, free, bump, end}`. It pops
//! a free node through its right-link word, otherwise bump-allocates a 0x18-byte
//! node. An exhausted pool adds a 0xc-byte chunk and `capacity * 0x18` arena;
//! capacity is 0x20 initially, then `max(previous + 0x20, previous * 13 / 8)`.
//! The returned node is red and has null parent/child links; its two-word
//! payload remains uninitialised for the insertion caller.
//!
//! Deliberate deviations: the checked-new callee's dead second zero argument is
//! omitted; `size_of` preserves target sizes while keeping host pointer fields
//! disjoint; and the return type corrects Ghidra's `void`, as both direct
//! callers consume the returned node in r0.

#[repr(C)]
pub struct U32PairTreeNode {
    pub color: u8,
    pub _pad: [u8; 3],
    pub parent: *mut U32PairTreeNode,
    pub left: *mut U32PairTreeNode,
    /// Also holds the next-free link while recycled.
    pub right: *mut U32PairTreeNode,
    /// Written by the insertion caller, not this allocator.
    pub payload: [u32; 2],
}

#[repr(C)]
pub struct U32PairTreePoolChunk {
    pub prev: *mut U32PairTreePoolChunk,
    pub capacity: u32,
    pub arena: *mut u8,
}

#[repr(C)]
pub struct U32PairTreeNodePool {
    pub chunk_head: *mut U32PairTreePoolChunk,
    pub free_list: *mut U32PairTreeNode,
    pub bump: *mut u8,
    pub bump_end: *mut u8,
}

#[repr(C)]
pub struct U32PairTree {
    pub pool: U32PairTreeNodePool,
    pub header: *mut U32PairTreeNode,
    pub node_count: u32,
}

#[cfg(target_pointer_width = "32")]
mod layout_checks {
    use super::*;
    const _: [u8; 0x4] = [0; core::mem::offset_of!(U32PairTreeNode, parent)];
    const _: [u8; 0x8] = [0; core::mem::offset_of!(U32PairTreeNode, left)];
    const _: [u8; 0xc] = [0; core::mem::offset_of!(U32PairTreeNode, right)];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(U32PairTreeNode, payload)];
    const _: [u8; 0x18] = [0; core::mem::size_of::<U32PairTreeNode>()];
    const _: [u8; 0x10] = [0; core::mem::size_of::<U32PairTreeNodePool>()];
    const _: [u8; 0xc] = [0; core::mem::size_of::<U32PairTreePoolChunk>()];
}

/// Keeps the two device allocation boundaries visible to LLVM.
#[inline(never)]
fn pool_operator_new(size: usize) -> *mut u8 {
    unsafe { crate::heap::veneers::operator_new_checked(size) }
}

/// Allocates an uninitialised-payload red-black-tree node from `tree`'s pool.
///
/// # Safety
/// `tree` must point to a live container with a valid leading pool state. The
/// returned payload must be written before it is read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn u32_pair_tree_allocate_node(
    tree: *mut U32PairTree,
) -> *mut U32PairTreeNode {
    const NODE_SIZE: usize = core::mem::size_of::<U32PairTreeNode>();
    let pool = core::ptr::addr_of_mut!((*tree).pool);
    let node;
    if !(*pool).free_list.is_null() {
        node = (*pool).free_list;
        (*pool).free_list = (*node).right;
    } else {
        let mut bump = (*pool).bump;
        if bump == (*pool).bump_end {
            let capacity = if (*pool).chunk_head.is_null() {
                0x20
            } else {
                let previous = (*(*pool).chunk_head).capacity;
                previous.wrapping_add(0x20).max(
                    previous.wrapping_add(previous >> 1).wrapping_add(previous >> 3),
                )
            };
            let chunk = pool_operator_new(core::mem::size_of::<U32PairTreePoolChunk>())
                .cast::<U32PairTreePoolChunk>();
            let arena = pool_operator_new((capacity as usize).wrapping_mul(NODE_SIZE));
            (*chunk).arena = arena;
            (*chunk).prev = (*pool).chunk_head;
            (*chunk).capacity = capacity;
            (*pool).chunk_head = chunk;
            bump = arena;
            (*pool).bump_end = arena.add((capacity as usize).wrapping_mul(NODE_SIZE));
        }
        node = bump.cast::<U32PairTreeNode>();
        (*pool).bump = bump.add(NODE_SIZE);
    }
    (*node).parent = core::ptr::null_mut();
    (*node).left = core::ptr::null_mut();
    (*node).right = core::ptr::null_mut();
    (*node).color = 0;
    node
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::MutexGuard;

    #[repr(C, align(8))]
    struct Arena([u8; 8192]);
    static mut ARENA: Arena = Arena([0; 8192]);
    static mut USED: usize = 0;
    static mut SIZES: [usize; 4] = [0; 4];
    static mut SIZE_COUNT: usize = 0;

    unsafe extern "C" fn allocate(_: *mut HeapDescriptorDescriptor, size: usize, _: usize) -> *mut u8 {
        let at = (USED + 7) & !7;
        USED = at + ((size + 7) & !7);
        SIZES[SIZE_COUNT] = size;
        SIZE_COUNT += 1;
        core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(at)
    }
    unsafe extern "C" fn create(desc: *mut HeapDescriptor, _: *mut u8, _: usize) -> *mut HeapDescriptorDescriptor {
        desc.cast()
    }
    fn heap() -> MutexGuard<'static, ()> {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            USED = 0; SIZE_COUNT = 0;
            (*core::ptr::addr_of_mut!(HEAP_OPS)).alloc = allocate;
            (*core::ptr::addr_of_mut!(HEAP_OPS)).create = create;
        }
        guard
    }
    fn tree() -> U32PairTree {
        U32PairTree { pool: U32PairTreeNodePool { chunk_head: core::ptr::null_mut(), free_list: core::ptr::null_mut(), bump: core::ptr::null_mut(), bump_end: core::ptr::null_mut() }, header: core::ptr::null_mut(), node_count: 0 }
    }

    #[test]
    fn fresh_pool_carves_chunk_and_arena() {
        let _heap = heap();
        unsafe {
            let mut value = tree();
            let node = u32_pair_tree_allocate_node(core::ptr::addr_of_mut!(value));
            assert_eq!(SIZE_COUNT, 2);
            assert_eq!(SIZES[0], core::mem::size_of::<U32PairTreePoolChunk>());
            assert_eq!(SIZES[1], 0x20 * core::mem::size_of::<U32PairTreeNode>());
            assert_eq!(node, (*value.pool.chunk_head).arena.cast());
            assert_eq!((*node).color, 0);
            assert!((*node).parent.is_null() && (*node).left.is_null() && (*node).right.is_null());
        }
    }

    #[test]
    fn exhaustion_grows_by_floor_then_reuses_free_nodes() {
        let _heap = heap();
        unsafe {
            let mut value = tree();
            for _ in 0..0x20 { u32_pair_tree_allocate_node(core::ptr::addr_of_mut!(value)); }
            let node = u32_pair_tree_allocate_node(core::ptr::addr_of_mut!(value));
            assert_eq!((*value.pool.chunk_head).capacity, 0x40);
            assert_eq!(SIZE_COUNT, 4);
            (*node).payload = [0xdead_beef, 0xa5a5_5a5a];
            (*node).right = core::ptr::null_mut();
            value.pool.free_list = node;
            let recycled = u32_pair_tree_allocate_node(core::ptr::addr_of_mut!(value));
            assert_eq!(recycled, node);
            assert_eq!((*recycled).payload, [0xdead_beef, 0xa5a5_5a5a]);
            assert_eq!(SIZE_COUNT, 4, "free-list pop has no heap traffic");
        }
    }
}
