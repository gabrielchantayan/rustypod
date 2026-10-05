//! Track-list cleanup — FUN_081c38c0 at 0x081c38c0.
//! True extent: 160 bytes [0x081c38c0,0x081c3960), including the +0x2ba
//! selector literal. Raw whole-image decode: two inbound BLs (one plain,
//! one BLNE); seven outbound BLs (six plain, one BLNE).
//!
//! Find the signed-selector node; hash and clear nonselected type-3 handles.
//! Save each successor before two calls to the node-resource destructor and
//! operator delete. Clear the head, then clear the singleton record source
//! if nonnull; return zero. Both destructor calls are intentional.
//!
//! Deviations: native pointers widen host fixtures; target layouts retain
//! +0x1b0/+0x2ba provider and +0/+4/+0x10/+0x14 node fields. Unported
//! resource cleanup helpers retain fixed-address target calls and explicit
//! host operations. Ported search, hash, getter and delete are reused.

use crate::util::list_find::{list_find_by_id16, IdNode};
use crate::app::opaque_record_source_get::{opaque_record_source_get, OpaqueRecordSource};
use crate::util::hash_word::hash_word;
use crate::heap::veneers::operator_delete;

#[repr(C)]
pub struct TrackNode {
    pub link: IdNode,
    pub opaque_08: [u32; 2],
    pub kind: u8,
    pub opaque_11: [u8; 3],
    pub handle: u32,
    pub resources: [u32; 34],
}

#[repr(C)]
pub struct TrackListProvider {
    pub opaque_00: [u8; 0x1b0],
    pub head: *mut TrackNode,
    pub opaque_after_head: [u8; 0x2ba - 0x1b0 - core::mem::size_of::<*mut TrackNode>()],
    pub selector: i16,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(TrackNode, kind) == 0x10);
    assert!(core::mem::offset_of!(TrackNode, handle) == 0x14);
    assert!(core::mem::offset_of!(TrackListProvider, head) == 0x1b0);
    assert!(core::mem::offset_of!(TrackListProvider, selector) == 0x2ba);
};

/// Operations for the two unported, raw-verified resource cleanup helpers.
#[derive(Clone, Copy)]
pub struct TrackCleanupOps {
    pub destroy_resources: unsafe extern "C" fn(*mut TrackNode),
    pub clear_source: unsafe extern "C" fn(*mut OpaqueRecordSource),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_: *mut TrackNode) {
    panic!("track cleanup requires retail resource destructor 0x081c8d88")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_clear(_: *mut OpaqueRecordSource) {
    panic!("track cleanup requires retail source clear 0x082844b4")
}
#[cfg(not(target_os = "none"))]
pub static mut TRACK_CLEANUP_OPS: TrackCleanupOps = TrackCleanupOps {
    destroy_resources: missing_destroy, clear_source: missing_clear,
};

unsafe fn cleanup_ops() -> TrackCleanupOps {
    #[cfg(target_os = "none")]
    { TrackCleanupOps {
        destroy_resources: core::mem::transmute(0x081c8d88usize),
        clear_source: core::mem::transmute(0x082844b4usize),
    } }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of!(TRACK_CLEANUP_OPS).read_volatile() }
}

unsafe fn clear_list(
    provider: *mut TrackListProvider,
    mut mix: impl FnMut(u32),
    mut destroy: impl FnMut(*mut TrackNode),
    mut delete: impl FnMut(*mut TrackNode),
    mut clear_source: impl FnMut(),
) -> u32 {
    let mut node = (*provider).head;
    if !node.is_null() {
        let selected = list_find_by_id16(node.cast(), (*provider).selector as i32 as u32);
        loop {
            if (*node).handle != 0 && (*node).kind == 3 && node.cast::<IdNode>() != selected {
                mix((*node).handle);
                (*node).kind = 0;
                (*node).handle = 0;
            }
            let next = (*node).link.next.cast::<TrackNode>();
            destroy(node);
            destroy(node);
            delete(node);
            node = next;
            if node.is_null() { break; }
        }
        (*provider).head = core::ptr::null_mut();
    }
    clear_source();
    0
}

/// # Safety
/// Provider and its acyclic list must be valid writable firmware objects;
/// nodes must be heap allocations accepted by the resource destructor and delete.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn track_list_clear(provider: *mut TrackListProvider) -> u32 {
    let ops = cleanup_ops();
    clear_list(provider, |word| { hash_word(word); },
        |node| (ops.destroy_resources)(node),
        |node| operator_delete(node.cast()),
        || {
            let source = opaque_record_source_get();
            if !source.is_null() { (ops.clear_source)(source); }
        })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use self::std::vec;
    use super::*;
    use self::std::vec::Vec;
    use core::cell::RefCell;

    #[test]
    fn selectors_handles_and_successor_saved_before_destructor() {
        for selector in [-2, -1, 0, 2, 32767] {
            let mut nodes: [TrackNode; 4] = core::array::from_fn(|i| TrackNode {
                link: IdNode { next: core::ptr::null_mut(), id: i as u16 + 1 },
                opaque_08: [0; 2], kind: if i == 2 { 2 } else { 3 },
                opaque_11: [0xaa; 3], handle: if i == 3 { 0 } else { 100 + i as u32 },
                resources: [0; 34],
            });
            for i in 0..3 { nodes[i].link.next = (&mut nodes[i + 1] as *mut TrackNode).cast(); }
            let base = nodes.as_mut_ptr();
            let mut provider = TrackListProvider {
                opaque_00: [0; 0x1b0], head: base,
                opaque_after_head: [0; 0x2ba - 0x1b0 - core::mem::size_of::<*mut TrackNode>()], selector,
            };
            let events = RefCell::new(Vec::new());
            let mut mixed = Vec::new();
            let result = unsafe { clear_list(&mut provider, |w| mixed.push(w),
                |n| {
                    events.borrow_mut().push((0, n.offset_from(base) as usize));
                    (*n).link.next = core::ptr::null_mut();
                },
                |n| events.borrow_mut().push((1, n.offset_from(base) as usize)),
                || events.borrow_mut().push((2, 0))) };
            assert_eq!(result, 0);
            assert!(provider.head.is_null());
            let selected = match selector { -1 | 0 => Some(0), 2 => Some(1), _ => None };
            assert_eq!(mixed, (0..2).filter(|i| Some(*i) != selected).map(|i| 100 + i as u32).collect::<Vec<_>>());
            for i in 0..4 {
                assert_eq!(nodes[i].opaque_11, [0xaa; 3]);
                let cleared = i < 2 && Some(i) != selected;
                assert_eq!(nodes[i].kind, if cleared { 0 } else if i == 2 { 2 } else { 3 });
                assert_eq!(nodes[i].handle, if cleared || i == 3 { 0 } else { 100 + i as u32 });
            }
            assert_eq!(*events.borrow(), vec![(0,0),(0,0),(1,0),(0,1),(0,1),(1,1),
                (0,2),(0,2),(1,2),(0,3),(0,3),(1,3),(2,0)]);
        }
    }

    #[test]
    fn empty_list_still_clears_source_without_destroying_nodes() {
        let mut provider: TrackListProvider = unsafe { core::mem::zeroed() };
        let mut cleared = false;
        assert_eq!(unsafe { clear_list(&mut provider, |_| panic!("hash"),
            |_| panic!("destroy"), |_| panic!("delete"), || cleared = true) }, 0);
        assert!(cleared);
        assert!(provider.head.is_null());
    }
}
