//! Tree-root selection — FUN_082a6970 @ 0x082a6970.
//! True extent: 20 bytes, ending at the separately entered push instruction
//! at 0x082a6984. Whole-image aligned ARM decoding finds two inbound plain
//! BLs (0x0828aa38, 0x082a6940), zero predicated BLs and zero outgoing calls.
//!
//! Load the optional tree pointer at +0xd8. If non-NULL, return it unchanged;
//! otherwise return the embedded tree at +0x58. The caller at 0x082a6940
//! passes the result to object_tree_collect_characters; the other caller
//! casts it to class 0x4a00 before resolving a path. Neither tree is read here.
//!
//! Deliberate deviation: the optional pointer uses native pointer width on
//! hosts. Opaque storage preserves both target offsets without inventing the
//! owner's other fields or adding NULL guards.

/// Only the embedded storage and optional root pointer are established here.
#[repr(C)]
pub struct ObjectTreeOwner {
    pub unresolved: [u32; 0x58 / 4],
    pub embedded_tree: [u32; 0x80 / 4],
    pub root_override: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x58] = [(); core::mem::offset_of!(ObjectTreeOwner, embedded_tree)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0xd8] = [(); core::mem::offset_of!(ObjectTreeOwner, root_override)];

/// Select the override or embedded root without dereferencing either tree.
///
/// # Safety
/// `owner` must point to a live, aligned `ObjectTreeOwner`. The returned
/// pointer's validity for further operations is the caller's responsibility.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_tree_root(owner: *mut ObjectTreeOwner) -> *mut u8 {
    let root = (*owner).root_override;
    if root.is_null() {
        core::ptr::addr_of_mut!((*owner).embedded_tree).cast()
    } else {
        root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    fn owner(root_override: *mut u8) -> ObjectTreeOwner {
        ObjectTreeOwner {
            unresolved: [0xa5a5_a5a5; 0x58 / 4],
            embedded_tree: [0x5a5a_5a5a; 0x80 / 4],
            root_override,
        }
    }

    #[test]
    fn clearing_override_restores_embedded_root() {
        let mut external = owner(ptr::null_mut());
        let external_root = external.embedded_tree.as_mut_ptr().cast();
        let mut tree_owner = owner(external_root);
        let embedded = tree_owner.embedded_tree.as_mut_ptr().cast();
        assert_eq!(unsafe { object_tree_root(&mut tree_owner) }, external_root);
        tree_owner.root_override = ptr::null_mut();
        assert_eq!(unsafe { object_tree_root(&mut tree_owner) }, embedded);
        assert_eq!(tree_owner.unresolved, [0xa5a5_a5a5; 0x58 / 4]);
        assert_eq!(tree_owner.embedded_tree, [0x5a5a_5a5a; 0x80 / 4]);
        assert!(tree_owner.root_override.is_null());
    }

    #[test]
    fn nonnull_override_is_returned_without_reading_or_masking_it() {
        for address in [1usize, 3, 0x0800_0000, 0xffff_ffff] {
            let root = address as *mut u8;
            let mut tree_owner = owner(root);
            assert_eq!(unsafe { object_tree_root(&mut tree_owner) }, root);
            assert_eq!(tree_owner.root_override, root);
        }
        let mut tree_owner = owner(ptr::null_mut());
        let embedded = tree_owner.embedded_tree.as_mut_ptr().cast();
        tree_owner.root_override = embedded;
        assert_eq!(unsafe { object_tree_root(&mut tree_owner) }, embedded);
    }
}
