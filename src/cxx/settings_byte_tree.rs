//! Pool allocator for the settings store's byte-key/byte-value red-black tree.
//!
//! [`settings_byte_tree_allocate_node`] — original: `FUN_083b8a24` @
//! `0x083b8a24` (184 bytes; two unconditional plain `bl` call sites).

/// A settings byte-map node: the red-black-tree base followed by its two-byte
/// key/value pair. The spare payload bytes are intentionally untouched.
#[repr(C)]
pub struct SettingsByteTreeNode {
    pub color: u8,
    _pad: [u8; 3],
    pub parent: *mut SettingsByteTreeNode,
    pub left: *mut SettingsByteTreeNode,
    pub right: *mut SettingsByteTreeNode,
    pub key: u8,
    pub value: u8,
    _payload_pad: [u8; 2],
}

/// The first four target words of the embedded libstdc++ pool.
#[repr(C)]
pub struct SettingsByteTreeNodePool {
    pub chunk_head: *mut SettingsByteTreePoolChunk,
    pub free_list: *mut SettingsByteTreeNode,
    pub bump: *mut u8,
    pub bump_end: *mut u8,
}

#[repr(C)]
pub struct SettingsByteTreePoolChunk {
    pub previous: *mut SettingsByteTreePoolChunk,
    pub capacity: u32,
    pub arena: *mut u8,
}

#[inline(never)]
fn pool_operator_new(size: usize) -> *mut u8 {
    unsafe { crate::heap::veneers::operator_new_checked(size) }
}

/// `settings_byte_tree_allocate_node` — original: `FUN_083b8a24` @
/// `0x083b8a24` (184 bytes, `0x083b8a24..0x083b8adc`; the next real function
/// starts at `0x083b8adc`). Raw A32 decoding verifies two outbound plain,
/// unconditional `bl` calls, both to `operator_new_checked` at `0x08266c70`,
/// and no predicated `bl` calls.
///
/// Pops a recycled 20-byte byte-key/byte-value red-black-tree node through its
/// right link, or bump-allocates one from the current arena. An exhausted pool
/// links a 12-byte chunk header and allocates an arena of `capacity * 20`, with
/// initial capacity 32 and subsequent capacity
/// `max(previous + 32, previous + previous/2 + previous/8)`. The returned node
/// is red with parent, left, and right links cleared; its key/value payload is
/// deliberately preserved.
///
/// Deliberate deviations: the dead `r1 = 0` allocator argument is omitted;
/// `size_of` preserves the 20-byte/12-byte target layout while keeping widened
/// host pointers disjoint; and the inline-never allocator front-end retains the
/// two allocation boundaries. Ghidra reports `void`, but both callers consume
/// the node left in `r0`, so this port returns it.
///
/// # Safety
/// `pool` must address a live, target-layout pool state. As in retailOS,
/// allocation failure is not checked before the returned storage is written.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn settings_byte_tree_allocate_node(
    pool: *mut SettingsByteTreeNodePool,
) -> *mut SettingsByteTreeNode {
    let node: *mut SettingsByteTreeNode;
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
            let chunk = pool_operator_new(core::mem::size_of::<SettingsByteTreePoolChunk>())
                .cast::<SettingsByteTreePoolChunk>();
            let arena = pool_operator_new(
                (capacity as usize).wrapping_mul(core::mem::size_of::<SettingsByteTreeNode>()),
            );
            (*chunk).previous = (*pool).chunk_head;
            (*chunk).capacity = capacity;
            (*chunk).arena = arena;
            (*pool).chunk_head = chunk;
            bump = arena;
            (*pool).bump_end = arena.add(
                (capacity as usize).wrapping_mul(core::mem::size_of::<SettingsByteTreeNode>()),
            );
        }
        node = bump.cast::<SettingsByteTreeNode>();
        (*pool).bump = bump.add(core::mem::size_of::<SettingsByteTreeNode>());
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
    use std::vec::Vec;

    const ARENA_SIZE: usize = 0x4000;
    #[repr(C, align(8))]
    struct Arena([u8; ARENA_SIZE]);
    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut USED: usize = 0;
    static mut SIZES: Vec<usize> = Vec::new();

    unsafe extern "C" fn allocate(_heap: *mut HeapDescriptorDescriptor, size: usize, _tag: usize) -> *mut u8 {
        let start = USED;
        USED += (size + 7) & !7;
        (*core::ptr::addr_of_mut!(SIZES)).push(size);
        core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(start)
    }
    unsafe extern "C" fn create(desc: *mut HeapDescriptor, _start: *mut u8, _size: usize) -> *mut HeapDescriptorDescriptor { desc.cast() }
    fn heap() -> MutexGuard<'static, ()> {
        let lock = crate::heap::veneers::tests::mock_heap();
        unsafe { USED = 0; (*core::ptr::addr_of_mut!(SIZES)).clear(); HEAP_OPS.alloc = allocate; HEAP_OPS.create = create; }
        lock
    }
    fn empty_pool() -> SettingsByteTreeNodePool {
        SettingsByteTreeNodePool { chunk_head: core::ptr::null_mut(), free_list: core::ptr::null_mut(), bump: core::ptr::null_mut(), bump_end: core::ptr::null_mut() }
    }

    #[test]
    fn fresh_pool_grows_then_bump_allocates() {
        let _heap = heap();
        unsafe {
            let mut pool = empty_pool();
            let first = settings_byte_tree_allocate_node(&mut pool);
            let second = settings_byte_tree_allocate_node(&mut pool);
            assert_eq!(first.cast::<u8>().add(core::mem::size_of::<SettingsByteTreeNode>()), second.cast());
            assert_eq!((*pool.chunk_head).capacity, 0x20);
            assert_eq!((*pool.chunk_head).previous, core::ptr::null_mut());
            assert_eq!((*core::ptr::addr_of!(SIZES)).as_slice(), &[core::mem::size_of::<SettingsByteTreePoolChunk>(), 0x20 * core::mem::size_of::<SettingsByteTreeNode>()]);
        }
    }

    #[test]
    fn recycled_node_is_reinitialized_without_touching_payload() {
        let _heap = heap();
        unsafe {
            let mut node = SettingsByteTreeNode { color: 0xff, _pad: [0; 3], parent: core::ptr::dangling_mut(), left: core::ptr::dangling_mut(), right: core::ptr::null_mut(), key: 0x52, value: 0xa4, _payload_pad: [0xde, 0xad] };
            let mut pool = empty_pool();
            pool.free_list = &mut node;
            let returned = settings_byte_tree_allocate_node(&mut pool);
            assert!(returned == &mut node);
            assert!(pool.free_list.is_null());
            assert_eq!(((*returned).color, (*returned).key, (*returned).value, (*returned)._payload_pad), (0, 0x52, 0xa4, [0xde, 0xad]));
            assert!((*returned).parent.is_null() && (*returned).left.is_null() && (*returned).right.is_null());
            assert!((*core::ptr::addr_of!(SIZES)).is_empty());
        }
    }
}
