//! Word-payload red-black-tree copy constructor — `FUN_083c0034` @
//! `0x083c0034`, 168 bytes (`0x083c0034..0x083c00dc`). The next independently
//! called function begins at `0x083c00dc`. Raw A32 decoding finds one inbound
//! plain BL at `0x0819ed28`, four outbound plain BLs, and zero predicated BLs.
//!
//! Initializes a fresh node pool, copies the source count and comparison byte,
//! stores the requested ownership byte, allocates a red sentinel, and clones
//! the source root. Empty trees point both extrema at the sentinel; nonempty
//! trees cache their leftmost and rightmost descendants. Returns destination.
//! Deliberate deviations: target pointers remain u32 words on hosts; none in
//! behavior. The two trailing object padding bytes are left untouched.

use super::red_black_tree_word_node_pool_acquire::{
    red_black_tree_word_node_pool_acquire, RedBlackTreeWordNode, RedBlackTreeWordNodePool,
};
use super::red_black_tree_word_subtree_clone::red_black_tree_word_subtree_clone;
use super::red_black_tree_leftmost_descendant_083b6a10::red_black_tree_leftmost_descendant_083b6a10;
use super::red_black_tree_rightmost_descendant_083b69fc::red_black_tree_rightmost_descendant_083b69fc;

#[repr(C)]
pub struct RedBlackTreeWord {
    pub pool: RedBlackTreeWordNodePool,
    pub header: u32,
    pub count: u32,
    pub ownership: u8,
    pub comparison: u8,
    pub _pad: [u8; 2],
}
const _: [u8; 0x10] = [0; core::mem::offset_of!(RedBlackTreeWord, header)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(RedBlackTreeWord, count)];
const _: [u8; 0x18] = [0; core::mem::offset_of!(RedBlackTreeWord, ownership)];
const _: [u8; 0x19] = [0; core::mem::offset_of!(RedBlackTreeWord, comparison)];
const _: [u8; 0x1c] = [0; core::mem::size_of::<RedBlackTreeWord>()];

/// # Safety
/// Destination must be writable and distinct from the readable source tree.
/// Source links must be valid target-width nodes; the allocator must supply
/// writable target-addressable storage for the sentinel and cloned nodes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_word_copy_construct(
    destination: *mut RedBlackTreeWord,
    source: *const RedBlackTreeWord,
    ownership: u8,
) -> *mut RedBlackTreeWord {
    (*destination).pool.chunks = 0;
    (*destination).header = 0;
    (*destination).count = (*source).count;
    (*destination).ownership = ownership;
    (*destination).comparison = (*source).comparison;
    (*destination).pool.end = 0;
    (*destination).pool.next = 0;
    (*destination).pool.free = 0;
    let pool = core::ptr::addr_of_mut!((*destination).pool);
    let header = red_black_tree_word_node_pool_acquire(pool);
    let header_word = header as usize as u32;
    (*destination).header = header_word;
    (*header).color = 0;
    let source_header = (*source).header as usize as *const RedBlackTreeWordNode;
    let root = red_black_tree_word_subtree_clone(
        pool, (*source_header).parent as usize as *mut RedBlackTreeWordNode, header,
    );
    let root_word = root as usize as u32;
    (*header).parent = root_word;
    if root.is_null() {
        (*header).left = header_word;
        (*header).right = header_word;
    } else {
        (*header).left = red_black_tree_leftmost_descendant_083b6a10(root_word);
        (*header).right = red_black_tree_rightmost_descendant_083b69fc(root_word);
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::HEAP_OPS;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;

    static mut ARENA: *mut u8 = ptr::null_mut();
    static mut CURSOR: usize = 0;
    unsafe extern "C" fn alloc(_: *mut HeapDescriptorDescriptor, _: usize, _: usize) -> *mut u8 {
        let result = ARENA.add(CURSOR * 0x1000);
        CURSOR += 1;
        result
    }
    unsafe fn word(node: *mut RedBlackTreeWordNode) -> u32 { node as usize as u32 }

    #[test]
    fn copies_empty_singleton_and_branched_tree_independently() {
        let _heap = crate::heap::veneers::tests::mock_heap();
        let Some(slab) = try_map_u32_slab(hints::RED_BLACK_TREE_WORD_COPY_CONSTRUCT, 0x9000) else {
            assert!(note_missing_u32_fixture("cxx/red_black_tree_word_copy_construct"));
            return;
        };
        unsafe {
            ptr::write_bytes(slab, 0xa5, 0x9000);
            ARENA = slab.add(0x2000); CURSOR = 0;
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = alloc;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), ops);
            let header = slab.cast::<RedBlackTreeWordNode>();
            let root = slab.add(0x40).cast::<RedBlackTreeWordNode>();
            let left = slab.add(0x80).cast::<RedBlackTreeWordNode>();
            let right = slab.add(0xc0).cast::<RedBlackTreeWordNode>();
            for (node, payload, color) in [(root, 20, 1), (left, 10, 0), (right, 30, 1)] {
                ptr::write(node, RedBlackTreeWordNode { color, _pad: [0; 3], parent: word(header), left: 0, right: 0, payload });
            }
            ptr::write(header, RedBlackTreeWordNode { color: 0, _pad: [0; 3], parent: 0, left: word(header), right: word(header), payload: 0 });
            let mut source = RedBlackTreeWord { pool: RedBlackTreeWordNodePool::default(), header: word(header), count: 0, ownership: 0x17, comparison: 0x93, _pad: [0; 2] };
            for count in [0, 1, 3] {
                source.count = count;
                (*header).parent = if count == 0 { 0 } else { word(root) };
                (*root).left = if count == 3 { word(left) } else { 0 };
                (*root).right = if count == 3 { word(right) } else { 0 };
                let destination = slab.add(0x100 + count as usize * 0x40).cast::<RedBlackTreeWord>();
                assert_eq!(red_black_tree_word_copy_construct(destination, &source, 0xfe), destination);
                assert_eq!(((*destination).count, (*destination).ownership, (*destination).comparison, (*destination)._pad), (count, 0xfe, 0x93, [0xa5; 2]));
                let copy_header = (*destination).header as usize as *mut RedBlackTreeWordNode;
                assert_ne!(copy_header, header);
                assert_eq!((*copy_header).color, 0);
                if count == 0 {
                    assert_eq!(((*copy_header).parent, (*copy_header).left, (*copy_header).right), (0, word(copy_header), word(copy_header)));
                } else {
                    let copy_root = (*copy_header).parent as usize as *mut RedBlackTreeWordNode;
                    assert_ne!(copy_root, root);
                    assert_eq!(((*copy_root).parent, (*copy_root).payload, (*copy_root).color), (word(copy_header), 20, 1));
                    if count == 1 {
                        assert_eq!(((*copy_header).left, (*copy_header).right), (word(copy_root), word(copy_root)));
                        assert_eq!(((*copy_root).left, (*copy_root).right), (0, 0));
                    } else {
                        for (link, payload, color) in [((*copy_root).left, 10, 0), ((*copy_root).right, 30, 1)] {
                            let node = link as usize as *mut RedBlackTreeWordNode;
                            assert_eq!(((*node).parent, (*node).payload, (*node).color, (*node).left, (*node).right), (word(copy_root), payload, color, 0, 0));
                        }
                        assert_eq!(((*copy_header).left, (*copy_header).right), ((*copy_root).left, (*copy_root).right));
                    }
                    (*copy_root).payload = 999;
                    assert_eq!((*root).payload, 20);
                }
            }
            assert_eq!(source.ownership, 0x17);
        }
    }
}
