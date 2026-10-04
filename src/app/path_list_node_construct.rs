//! Path-list node construction from the directory-enumeration loop.

use crate::app::path_object_construct::PATH_OBJECT_VTABLE_ADDRESS;
use crate::cxx::string_object::{string_object_copy_construct, StringObject, StringObjectVtable};

/// Target layout: string at +0, entry kind at +8, untouched padding +9..+11,
/// and next node at +12. Named fields accommodate wider host pointers.
#[repr(C)]
pub struct PathListNode {
    pub path: StringObject,
    pub entry_kind: u8,
    pub padding: [u8; 3],
    pub next: *mut PathListNode,
}

/// path_list_node_construct — FUN_081ee728 @ 0x081ee728.
/// Verified extent: 40 bytes through the next function at 0x081ee750:
/// 36 code bytes and the literal 0x089a60d8 at 0x081ee74c.
/// Whole-image A32 decoding finds two plain inbound BLs (0x081ee874,
/// 0x081ee898), zero predicated inbound BLs; one internal plain BL to
/// string_object_copy_construct @ 0x082773e0 and no predicated internal BLs.
/// Copy-constructs the leading string, replaces its vtable with the path
/// identity, writes the entry-kind byte and next pointer, and returns this.
/// The base constructor's self-copy guard preserves the existing payload;
/// the three padding bytes are never initialized.
/// Deliberate deviations: direct call to the existing Rust base constructor;
/// repr(C) fields rather than target byte offsets on pointer-widened hosts.
/// The derived vtable remains the existing ROM identity, not a callable host
/// vtable. No additional validation or allocation is introduced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn path_list_node_construct(
    this: *mut PathListNode,
    source: *const StringObject,
    entry_kind: u8,
    next: *mut PathListNode,
) -> *mut PathListNode {
    let result = string_object_copy_construct(core::ptr::addr_of_mut!((*this).path), source);
    let node = result.cast::<PathListNode>();
    (*node).path.vtable = PATH_OBJECT_VTABLE_ADDRESS as *const StringObjectVtable;
    (*node).entry_kind = entry_kind;
    (*node).next = next;
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_construction_preserves_payload_and_padding_and_replaces_links() {
        for kind in [0, 1, 0x80, 0xff] {
            let mut payload = [b'x', 0];
            let mut node = PathListNode {
                path: StringObject { vtable: core::ptr::null(), payload: payload.as_mut_ptr() },
                entry_kind: !kind,
                padding: [0x12, 0x34, 0x56],
                next: core::ptr::null_mut(),
            };
            let ptr = &mut node as *mut PathListNode;
            let result = unsafe { path_list_node_construct(ptr, core::ptr::addr_of!((*ptr).path), kind, ptr) };
            assert_eq!(result, ptr);
            assert_eq!(node.path.payload, payload.as_mut_ptr());
            assert_eq!(payload, [b'x', 0]);
            assert_eq!(node.path.vtable as usize, PATH_OBJECT_VTABLE_ADDRESS);
            assert_eq!(node.entry_kind, kind);
            assert_eq!(node.padding, [0x12, 0x34, 0x56]);
            assert_eq!(node.next, ptr);
            unsafe { path_list_node_construct(ptr, core::ptr::addr_of!((*ptr).path), kind, core::ptr::null_mut()); }
            assert!(node.next.is_null());
            assert_eq!(node.padding, [0x12, 0x34, 0x56]);
        }
    }
}
