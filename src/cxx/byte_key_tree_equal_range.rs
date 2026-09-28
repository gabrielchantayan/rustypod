//! Equal-range lookup on the byte-keyed red-black tree.
//!
//! [`byte_key_tree_equal_range`] ports `FUN_083b8adc` at `0x083b8adc`.
//! Raw `osos.dec` establishes the true 160-byte extent
//! (`0x083b8adc..0x083b8b7c`) and exactly two plain, unconditional `bl`
//! instructions, both to `less_unsigned_byte` at `0x083d73bc`; no predicated
//! `bl` occurs. It performs two root-to-leaf walks: lower bound (`node < key`
//! goes right, otherwise remember node and go left), then upper bound (`key <
//! node` remembers node and goes left, otherwise goes right). The two
//! candidates become the half-open equal range.
//!
//! Deliberate deviations: the port uses typed `#[repr(C)]` node/container
//! fields instead of target byte offsets; host pointer fields widen but remain
//! disjoint. The two comparator calls target the already-ported comparator
//! rather than its retail address.

use super::byte_key_map::{ByteKeyTree, ByteKeyTreeNode};

/// A pair of tree iterators: lower bound at +0 and upper bound at +4 on the
/// 32-bit target.
#[repr(C)]
pub struct ByteKeyTreeEqualRange {
    pub lower: *mut ByteKeyTreeNode,
    pub upper: *mut ByteKeyTreeNode,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::size_of::<ByteKeyTreeEqualRange>()];

/// byte_key_tree_equal_range — original: `FUN_083b8adc` @ `0x083b8adc`
/// (160 bytes; two direct plain `bl` calls, both to `less_unsigned_byte` @
/// `0x083d73bc`; none predicated).
///
/// Finds the half-open equal range for `*key` in the byte-keyed red-black
/// tree. The result is `(lower_bound(key), upper_bound(key))`; either member
/// is the header node when no matching bound exists.
///
/// # Safety
/// `result` must be writable, `tree` must be a live byte-key tree with a live
/// header, and `key` must be readable. All reachable links must be valid tree
/// nodes or null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn byte_key_tree_equal_range(
    result: *mut ByteKeyTreeEqualRange,
    tree: *mut ByteKeyTree,
    key: *const u8,
) {
    let header = (*tree).header;
    let comparator = core::ptr::addr_of!((*tree).comparator);
    let mut node = (*header).parent;
    let mut lower = header;

    while !node.is_null() {
        let node_key = core::ptr::addr_of!((*node).key.key);
        if crate::cxx::templates::less_unsigned_byte(comparator, node_key, key) == 0 {
            lower = node;
            node = (*node).left;
        } else {
            node = (*node).right;
        }
    }

    node = (*header).parent;
    let mut upper = header;
    while !node.is_null() {
        let node_key = core::ptr::addr_of!((*node).key.key);
        if crate::cxx::templates::less_unsigned_byte(comparator, key, node_key) == 0 {
            node = (*node).right;
        } else {
            upper = node;
            node = (*node).left;
        }
    }

    result.write(ByteKeyTreeEqualRange { lower, upper });
}

/// byte_key_tree_equal_range_alias_7ff0 — original: `FUN_083b7ff0` @
/// `0x083b7ff0` (160 bytes; two direct plain `bl` calls, both to
/// `less_unsigned_byte` @ `0x083d73bc`; none predicated).
///
/// Raw words establish the extent `0x083b7ff0..0x083b8090`: `pop
/// {r4-r8,pc}` at `0x083b808c` returns, and the next real function starts at
/// `0x083b8090`. This equal-range instantiation makes two root-to-leaf walks:
/// lower bound follows right when `node < key`, otherwise retains the node and
/// follows left; upper bound follows left when `key < node`, otherwise retains
/// the node and follows right. The retained nodes form the half-open range.
///
/// Deliberate deviations: typed `#[repr(C)]` fields replace target offsets,
/// keeping ARM layout exact while host pointers widen safely; calls use the
/// already-ported comparator instead of its fixed retail address. Kept as a
/// distinct link section so identical-code folding cannot remove its hookable
/// label.
///
/// # Safety
/// `result` must be writable, `tree` must be a live byte-key tree with a live
/// header, and `key` must be readable. All reachable links must be valid tree
/// nodes or null.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.byte_key_tree_equal_range_alias_7ff0")]
#[inline(never)]
pub unsafe extern "C" fn byte_key_tree_equal_range_alias_7ff0(
    result: *mut ByteKeyTreeEqualRange,
    tree: *mut ByteKeyTree,
    key: *const u8,
) {
    let header = (*tree).header;
    let comparator = core::ptr::addr_of!((*tree).comparator);
    let mut node = (*header).parent;
    let mut lower = header;

    while !node.is_null() {
        let node_key = core::ptr::addr_of!((*node).key.key);
        if crate::cxx::templates::less_unsigned_byte(comparator, node_key, key) == 0 {
            lower = node;
            node = (*node).left;
        } else {
            node = (*node).right;
        }
    }

    node = (*header).parent;
    let mut upper = header;
    while !node.is_null() {
        let node_key = core::ptr::addr_of!((*node).key.key);
        if crate::cxx::templates::less_unsigned_byte(comparator, key, node_key) == 0 {
            node = (*node).right;
        } else {
            upper = node;
            node = (*node).left;
        }
    }

    result.write(ByteKeyTreeEqualRange { lower, upper });
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::byte_key_map::{ByteKeyNodePool, ByteKeyPair};
    use std::boxed::Box;

    fn node(key: u8) -> ByteKeyTreeNode {
        ByteKeyTreeNode {
            color: 1,
            _pad: [0; 3],
            parent: core::ptr::null_mut(),
            left: core::ptr::null_mut(),
            right: core::ptr::null_mut(),
            key: ByteKeyPair { key, pad: [0; 3], value: [0; 3] },
        }
    }

    #[test]
    fn returns_bounds_at_edges_duplicates_and_gaps() {
        unsafe {
            let mut header = Box::new(node(0));
            header.color = 0;
            let mut two = Box::new(node(2));
            let mut four = Box::new(node(4));
            let mut six = Box::new(node(6));
            let mut eight = Box::new(node(8));
            let mut twelve = Box::new(node(12));
            let mut fourteen = Box::new(node(14));
            let header_ptr = &mut *header as *mut ByteKeyTreeNode;
            let two_ptr = &mut *two as *mut ByteKeyTreeNode;
            let four_ptr = &mut *four as *mut ByteKeyTreeNode;
            let six_ptr = &mut *six as *mut ByteKeyTreeNode;
            let eight_ptr = &mut *eight as *mut ByteKeyTreeNode;
            let twelve_ptr = &mut *twelve as *mut ByteKeyTreeNode;
            let fourteen_ptr = &mut *fourteen as *mut ByteKeyTreeNode;
            header.parent = eight_ptr;
            header.left = two_ptr;
            header.right = fourteen_ptr;
            eight.parent = header_ptr;
            eight.left = four_ptr;
            eight.right = twelve_ptr;
            four.parent = eight_ptr;
            four.left = two_ptr;
            four.right = six_ptr;
            two.parent = four_ptr;
            six.parent = four_ptr;
            twelve.parent = eight_ptr;
            twelve.right = fourteen_ptr;
            fourteen.parent = twelve_ptr;
            let mut tree = ByteKeyTree {
                _opaque: [0; core::mem::size_of::<ByteKeyNodePool>()],
                header: header_ptr,
                node_count: 7,
                multi_insert: 0,
                comparator: 0,
            };

            for (key, expected_lower, expected_upper) in [
                (0, two_ptr, two_ptr),
                (2, two_ptr, four_ptr),
                (5, six_ptr, six_ptr),
                (8, eight_ptr, twelve_ptr),
                (14, fourteen_ptr, header_ptr),
                (15, header_ptr, header_ptr),
            ] {
                let mut result = ByteKeyTreeEqualRange {
                    lower: core::ptr::null_mut(),
                    upper: core::ptr::null_mut(),
                };
                byte_key_tree_equal_range(&mut result, &mut tree, &key);
                assert_eq!(result.lower, expected_lower, "key {key}");
                assert_eq!(result.upper, expected_upper, "key {key}");
                let mut alias_result = ByteKeyTreeEqualRange {
                    lower: core::ptr::null_mut(),
                    upper: core::ptr::null_mut(),
                };
                byte_key_tree_equal_range_alias_7ff0(&mut alias_result, &mut tree, &key);
                assert_eq!(alias_result.lower, expected_lower, "alias key {key}");
                assert_eq!(alias_result.upper, expected_upper, "alias key {key}");
            }
        }
    }
}
