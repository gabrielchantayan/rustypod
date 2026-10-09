//! Enabled child/sibling subtree lookup — retailOS 0x080d87f0.
//!
//! True extent: [0x080d87f0, 0x080d8840), 80 bytes, verified from raw A32
//! words. Two inbound plain BL sites (0x08094e48 and recursive 0x080d8820),
//! zero predicated; one outbound plain BL, to this function itself.
//! Test bit 0 of the byte at +0x1d; if clear, prune the entire subtree.
//! Otherwise return this node if its +0x14 identifier matches, or recursively
//! search children (+0x20) in sibling (+0x08) order, returning the first match.
//! Deliberate deviations: none in behavior. Links remain target-width u32
//! words on hosts; other flag bits are ignored. No NULL-root or cycle guard.

use core::ptr;

/// Searches a readable, aligned retail child/sibling tree.
///
/// # Safety
/// `root` must be non-NULL and readable through +0x1d. Enabled nonmatching
/// nodes must also expose +0x20; every nonzero traversed link must point to
/// another valid node. Links store 32-bit addresses, including on hosts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn enabled_subtree_find_identifier(
    root: *mut u32,
    identifier: u32,
) -> *mut u32 {
    if root.cast::<u8>().add(0x1d).read() & 1 == 0 {
        return ptr::null_mut();
    }
    if root.add(5).read() == identifier {
        return root;
    }
    let mut child = root.add(8).read() as usize as *mut u32;
    while !child.is_null() {
        let found = enabled_subtree_find_identifier(child, identifier);
        if !found.is_null() {
            return found;
        }
        child = child.add(2).read() as usize as *mut u32;
    }
    ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prunes_disabled_subtrees_and_returns_first_preorder_match() {
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::ENABLED_SUBTREE_FIND_IDENTIFIER, 0x1000,
        ).expect("target-width tree fixture");
        unsafe {
            slab.write_bytes(0, 0x1000);
            let root = slab.cast::<u32>();
            let first = root.add(16);
            let grandchild = root.add(32);
            let second = root.add(48);
            for node in [root, first, grandchild, second] {
                node.cast::<u8>().add(0x1d).write(0x81);
                node.add(5).write(u32::MAX);
            }
            root.add(5).write(0);
            first.add(5).write(17);
            root.add(8).write(first as usize as u32);
            first.add(8).write(grandchild as usize as u32);
            first.add(2).write(second as usize as u32);
            assert_eq!(enabled_subtree_find_identifier(root, 0), root);
            assert_eq!(enabled_subtree_find_identifier(root, 17), first);
            assert_eq!(enabled_subtree_find_identifier(root, u32::MAX), grandchild);
            assert_eq!(enabled_subtree_find_identifier(root, 99), ptr::null_mut());

            // A disabled node prunes even a matching descendant, but its
            // sibling remains searchable by the parent's traversal.
            first.cast::<u8>().add(0x1d).write(0xfe);
            assert_eq!(enabled_subtree_find_identifier(root, 17), ptr::null_mut());
            assert_eq!(enabled_subtree_find_identifier(root, u32::MAX), second);
            second.cast::<u8>().add(0x1d).write(0);
            assert_eq!(enabled_subtree_find_identifier(root, u32::MAX), ptr::null_mut());

            // Matching and disabled roots must not follow invalid children.
            root.add(8).write(1);
            assert_eq!(enabled_subtree_find_identifier(root, 0), root);
            root.cast::<u8>().add(0x1d).write(0x80);
            assert_eq!(enabled_subtree_find_identifier(root, 0), ptr::null_mut());
            root.cast::<u8>().add(0x1d).write(1);
            root.add(8).write(0);
            assert_eq!(enabled_subtree_find_identifier(root, 99), ptr::null_mut());
        }
    }
}
