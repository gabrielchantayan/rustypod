//! `opaque_tree_node_pool_acquire` — original: `FUN_083bb500` @ 0x083bb500.
//!
//! Raw osos.dec establishes the exact 184-byte A32 extent
//! 0x083bb500..0x083bb5b8 (46 words); `ldr r2,[r1,#12]` at 0x083bb5b8 begins
//! the next real function. The body has two unconditional plain `bl` calls,
//! both to `operator_new_checked` @ 0x08266c70, and no predicated `bl` calls.
//! It allocates 20-byte red-black-tree nodes: first reusing the +0x0c-threaded
//! free list, then bump allocation, or a 12-byte chunk header and a grown
//! arena. New nodes are red with all three links cleared; their 32-bit payload
//! word is deliberately preserved. Deliberate deviations: Ghidra says `void`,
//! but callers consume r0, so Rust returns the node; host pointer fields widen
//! under `repr(C)`, while target layout assertions retain the firmware offsets.

#[repr(C)]
pub struct OpaqueTreeNode {
    pub color: u8,
    pub _pad: [u8; 3],
    pub parent: *mut OpaqueTreeNode,
    pub left: *mut OpaqueTreeNode,
    /// Also the next-free link while recycled.
    pub right: *mut OpaqueTreeNode,
    /// Written by the caller, never by this allocator.
    pub payload: u32,
}

#[repr(C)]
pub struct OpaqueTreePoolChunk {
    pub prev: *mut OpaqueTreePoolChunk,
    pub capacity: u32,
    pub arena: *mut u8,
}

/// The first four target-width words of the owning tree/list object.
#[repr(C)]
pub struct OpaqueTreeNodePool {
    pub chunk_head: *mut OpaqueTreePoolChunk,
    pub free_list: *mut OpaqueTreeNode,
    pub bump: *mut u8,
    pub bump_end: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::size_of::<OpaqueTreeNode>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xc] = [0; core::mem::size_of::<OpaqueTreePoolChunk>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::size_of::<OpaqueTreeNodePool>()];

/// Keeps each of the original allocator calls as a real boundary.
#[inline(never)]
fn pool_operator_new(size: usize) -> *mut u8 {
    unsafe { crate::heap::veneers::operator_new_checked(size) }
}

/// Acquires a red-black-tree node from `pool`.
///
/// # Safety
/// `pool` must address the first 16 bytes of a live target-layout pool. The
/// returned payload word is uninitialised or stale and must be written before
/// it is read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_tree_node_pool_acquire(
    pool: *mut OpaqueTreeNodePool,
) -> *mut OpaqueTreeNode {
    let node;
    let free = (*pool).free_list;
    if !free.is_null() {
        node = free;
        (*pool).free_list = (*free).right;
    } else {
        let mut bump = (*pool).bump;
        if bump == (*pool).bump_end {
            let capacity = if (*pool).chunk_head.is_null() {
                0x20
            } else {
                let previous = (*(*pool).chunk_head).capacity;
                let grown = previous.wrapping_add(previous >> 1).wrapping_add(previous >> 3);
                previous.wrapping_add(0x20).max(grown)
            };
            let chunk = pool_operator_new(core::mem::size_of::<OpaqueTreePoolChunk>())
                .cast::<OpaqueTreePoolChunk>();
            let node_size = core::mem::size_of::<OpaqueTreeNode>();
            let arena = pool_operator_new((capacity as usize).wrapping_mul(node_size));
            (*chunk).arena = arena;
            (*chunk).prev = (*pool).chunk_head;
            (*chunk).capacity = capacity;
            (*pool).chunk_head = chunk;
            bump = arena;
            (*pool).bump_end = arena.add((capacity as usize).wrapping_mul(node_size));
        }
        node = bump.cast::<OpaqueTreeNode>();
        (*pool).bump = bump.add(core::mem::size_of::<OpaqueTreeNode>());
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
    struct Arena([u8; 0x4000]);
    static mut ARENA: Arena = Arena([0; 0x4000]);
    static mut USED: usize = 0;
    static mut ALLOC_SIZES: [usize; 4] = [0; 4];
    static mut ALLOC_COUNT: usize = 0;

    unsafe extern "C" fn alloc(_heap: *mut HeapDescriptorDescriptor, size: usize, _tag: usize) -> *mut u8 {
        let at = USED;
        USED = (USED + size + 7) & !7;
        ALLOC_SIZES[ALLOC_COUNT] = size;
        ALLOC_COUNT += 1;
        core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(at)
    }
    unsafe extern "C" fn create(desc: *mut HeapDescriptor, _start: *mut u8, _size: usize) -> *mut HeapDescriptorDescriptor {
        desc.cast()
    }
    fn mock_heap() -> MutexGuard<'static, ()> {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            USED = 0;
            ALLOC_COUNT = 0;
            (*core::ptr::addr_of_mut!(HEAP_OPS)).alloc = alloc;
            (*core::ptr::addr_of_mut!(HEAP_OPS)).create = create;
        }
        guard
    }
    fn empty_pool() -> OpaqueTreeNodePool {
        OpaqueTreeNodePool { chunk_head: core::ptr::null_mut(), free_list: core::ptr::null_mut(), bump: core::ptr::null_mut(), bump_end: core::ptr::null_mut() }
    }

    #[test]
    fn recycled_node_is_reinitialised_without_allocation() {
        unsafe {
            let mut node = OpaqueTreeNode { color: 0xff, _pad: [0; 3], parent: core::ptr::dangling_mut(), left: core::ptr::dangling_mut(), right: core::ptr::null_mut(), payload: 0xdead_beef };
            let mut pool = empty_pool();
            pool.free_list = core::ptr::addr_of_mut!(node);
            let got = opaque_tree_node_pool_acquire(core::ptr::addr_of_mut!(pool));
            assert_eq!(got, core::ptr::addr_of_mut!(node));
            assert_eq!((*got).color, 0);
            assert!((*got).parent.is_null() && (*got).left.is_null() && (*got).right.is_null());
            assert_eq!((*got).payload, 0xdead_beef);
        }
    }

    #[test]
    fn fresh_and_exhausted_pool_grow_with_firmware_capacities() {
        let _heap = mock_heap();
        unsafe {
            let mut pool = empty_pool();
            let first = opaque_tree_node_pool_acquire(core::ptr::addr_of_mut!(pool));
            let chunk = pool.chunk_head;
            let node_size = core::mem::size_of::<OpaqueTreeNode>();
            assert_eq!((*chunk).capacity, 0x20);
            assert_eq!(first, (*chunk).arena.cast());
            for _ in 1..0x20 { opaque_tree_node_pool_acquire(core::ptr::addr_of_mut!(pool)); }
            opaque_tree_node_pool_acquire(core::ptr::addr_of_mut!(pool));
            assert_eq!((*pool.chunk_head).capacity, 0x40);
            assert_eq!(&ALLOC_SIZES[..ALLOC_COUNT], &[core::mem::size_of::<OpaqueTreePoolChunk>(), 0x20 * node_size, core::mem::size_of::<OpaqueTreePoolChunk>(), 0x40 * node_size]);
        }
    }
}
