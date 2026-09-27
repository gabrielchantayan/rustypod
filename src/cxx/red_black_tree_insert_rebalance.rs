//! Generic C++ red-black-tree insertion and rebalancing — retailOS
//! `FUN_083c12f8` at load address `0x083c12f8`.
//!
//! Raw `osos.dec` establishes the true 464-byte extent: 116 ARM words from
//! `push {r2-r9,sl,lr}` through `pop {r2-r9,sl,pc}` at `0x083c14c4`; the next
//! separately linked function begins with `push {r4-r8,lr}` at `0x083c14c8`.
//! The body has four unconditional `bl` instructions (node-pool acquire,
//! unsigned comparison, right rotation, left rotation) and two predicated
//! `bleq` instructions (left and right rotations). It allocates a 20-byte node,
//! stores the supplied u32 key at +0x10, links it beneath the requested parent,
//! and restores red-black color and rotation invariants. Deliberate deviations:
//! the unported node-pool acquire remains a verified target-address seam; host
//! tests replace only that allocator.

use super::red_black_tree_increment::RedBlackTreeNode;
use super::red_black_tree_rotate_left::red_black_tree_rotate_left;
use super::red_black_tree_rotate_right::{red_black_tree_rotate_right, RedBlackTree};
use super::templates::less_unsigned_alias_74dc;
use core::ptr::{addr_of_mut, read_volatile};

type NodePoolAcquire = unsafe extern "C" fn(*mut u8) -> *mut RedBlackTreeNode;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn node_pool_acquire(tree: *mut u8) -> *mut RedBlackTreeNode {
    let acquire: NodePoolAcquire = core::mem::transmute(0x083c_0ba8usize);
    acquire(tree)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_node_pool_acquire(_: *mut u8) -> *mut RedBlackTreeNode {
    panic!("install red-black-tree insertion node-pool seam")
}

#[cfg(not(target_os = "none"))]
pub static mut RED_BLACK_TREE_INSERT_NODE_POOL_ACQUIRE: NodePoolAcquire = missing_node_pool_acquire;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn node_pool_acquire(tree: *mut u8) -> *mut RedBlackTreeNode {
    read_volatile(addr_of_mut!(RED_BLACK_TREE_INSERT_NODE_POOL_ACQUIRE))(tree)
}

#[inline(always)]
unsafe fn node_from_word(address: u32) -> *mut RedBlackTreeNode {
    address as usize as *mut RedBlackTreeNode
}

#[inline(always)]
fn node_word(node: *mut RedBlackTreeNode) -> u32 {
    node as usize as u32
}

/// Allocates, links, and rebalances one u32-keyed red-black-tree node.
///
/// # Safety
///
/// `tree` must contain the target's node pool at +0, header word at +0x10, and
/// count at +0x14. `parent` is the header or a valid node; `key` is readable.
/// The allocator and every traversed target-width link must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.red_black_tree_insert_rebalance")]
#[inline(never)]
pub unsafe extern "C" fn red_black_tree_insert_rebalance(
    inserted: *mut u32,
    tree: *mut u8,
    insert_left: u32,
    parent: *mut RedBlackTreeNode,
    key: *const u32,
) {
    let node = node_pool_acquire(tree);
    node.cast::<u8>().add(0x10).cast::<u32>().write(key.read());
    tree.add(0x14).cast::<u32>().write(tree.add(0x14).cast::<u32>().read().wrapping_add(1));

    let header = node_from_word(tree.add(0x10).cast::<u32>().read());
    if parent == header || insert_left != 0 || less_unsigned_alias_74dc(tree.add(0x19), key, node.cast::<u8>().add(0x10).cast()) != 0 {
        (*parent).left = node_word(node);
        if parent == header {
            (*header).parent = node_word(node);
            (*header).right = node_word(node);
        }
    } else {
        let replaces_rightmost = (*header).right == node_word(parent);
        (*parent).right = node_word(node);
        if replaces_rightmost {
            (*header).right = node_word(node);
        }
    }
    (*node).parent = node_word(parent);

    let mut current = node;
    while current != node_from_word((*header).parent) && (*node_from_word((*current).parent)).color == 0 {
        let grandparent = node_from_word((*node_from_word((*current).parent)).parent);
        if (*grandparent).left == node_word(node_from_word((*current).parent)) {
            let uncle = node_from_word((*grandparent).right);
            if uncle != core::ptr::null_mut() && (*uncle).color == 0 {
                (*node_from_word((*current).parent)).color = 1;
                (*uncle).color = 1;
                (*grandparent).color = 0;
                current = grandparent;
            } else {
                if (*node_from_word((*current).parent)).right == node_word(current) {
                    current = node_from_word((*current).parent);
                    red_black_tree_rotate_left(tree.cast(), current);
                }
                (*node_from_word((*current).parent)).color = 1;
                (*grandparent).color = 0;
                red_black_tree_rotate_right(tree.cast(), grandparent);
            }
        } else {
            let uncle = node_from_word((*grandparent).left);
            if uncle != core::ptr::null_mut() && (*uncle).color == 0 {
                (*node_from_word((*current).parent)).color = 1;
                (*uncle).color = 1;
                (*grandparent).color = 0;
                current = grandparent;
            } else {
                if (*node_from_word((*current).parent)).left == node_word(current) {
                    current = node_from_word((*current).parent);
                    red_black_tree_rotate_right(tree.cast(), current);
                }
                (*node_from_word((*current).parent)).color = 1;
                (*grandparent).color = 0;
                red_black_tree_rotate_left(tree.cast(), grandparent);
            }
        }
    }
    (*node_from_word((*header).parent)).color = 1;
    inserted.write(node_word(node));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::LazyLock;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| crate::testing::try_map_u32_slab(crate::testing::hints::RED_BLACK_TREE_INSERT_REBALANCE, 0x1000).map(|p| p as usize));
    static mut NEXT_NODE: *mut RedBlackTreeNode = core::ptr::null_mut();

    unsafe extern "C" fn acquire(_: *mut u8) -> *mut RedBlackTreeNode { NEXT_NODE }
    fn word(node: *mut RedBlackTreeNode) -> u32 { node as usize as u32 }

    unsafe fn setup(base: *mut u8) -> (*mut u8, *mut RedBlackTreeNode) {
        base.write_bytes(0, 0x1000);
        let tree = base.cast::<u8>();
        let header = base.add(0x100).cast::<RedBlackTreeNode>();
        tree.add(0x10).cast::<u32>().write(word(header));
        (*header).left = word(header); (*header).right = word(header);
        (tree, header)
    }

    #[test]
    fn inserts_root_and_rebalances_inner_child() {
        let Some(base) = (*SLAB).map(|p| p as *mut u8) else { crate::testing::note_missing_u32_fixture("cxx/red_black_tree_insert_rebalance"); return; };
        unsafe {
            let old = core::ptr::read_volatile(addr_of_mut!(RED_BLACK_TREE_INSERT_NODE_POOL_ACQUIRE));
            core::ptr::write_volatile(addr_of_mut!(RED_BLACK_TREE_INSERT_NODE_POOL_ACQUIRE), acquire);
            let (tree, header) = setup(base);
            let first = base.add(0x200).cast::<RedBlackTreeNode>(); NEXT_NODE = first;
            let mut result = 0; let key = 10;
            red_black_tree_insert_rebalance(&mut result, tree, 1, header, &key);
            assert_eq!(result, word(first)); assert_eq!((*header).parent, word(first)); assert_eq!((*first).color, 1); assert_eq!(tree.add(0x14).cast::<u32>().read(), 1);

            let parent = first; let right = base.add(0x220).cast::<RedBlackTreeNode>(); let inner = base.add(0x240).cast::<RedBlackTreeNode>();
            (*parent).color = 0; (*parent).parent = word(header); (*parent).right = word(right); (*right).parent = word(parent); (*right).color = 0;
            NEXT_NODE = inner; let inner_key = 15;
            red_black_tree_insert_rebalance(&mut result, tree, 1, right, &inner_key);
            assert_eq!((*header).parent, word(inner)); assert_eq!((*inner).left, word(parent)); assert_eq!((*inner).right, word(right)); assert_eq!((*inner).color, 1); assert_eq!((*parent).color, 0); assert_eq!((*right).color, 0);
            core::ptr::write_volatile(addr_of_mut!(RED_BLACK_TREE_INSERT_NODE_POOL_ACQUIRE), old);
        }
    }
}
