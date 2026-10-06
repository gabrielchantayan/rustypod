//! Draw resource lookup — `FUN_0816e478` @ 0x0816e478.
//!
//! True extent: 20 bytes (16 code bytes and the 0x44726177 `Draw` literal);
//! the next real function starts at 0x0816e48c. Whole-image aligned ARM
//! decoding finds two plain inbound BLs at 0x0816e404 and 0x0816e5e4,
//! zero predicated inbound BLs. Body: zero BLs, one tail B to the existing
//! resource_chain_find @ 0x0827216c.
//!
//! Load the resource ID at +0x44 and provider head at +0x38, then look up
//! (Draw, ID). Callers NULL-check the result and consume its word at +4;
//! the payload format beyond that is not established here.
//!
//! Deviations: Rust calls replace the tail branch; repr(C) pointer-sized
//! opaque words widen on hosts while preserving target offsets. No new seams.

use crate::app::resource_chain::{resource_chain_find, ResourceKind, ResourceProvider};

/// Only the common resource-bearing prefix is decoded.
#[repr(C)]
pub struct DrawResourceObject {
    pub unresolved_000_034: [usize; 14],
    pub resources: *mut ResourceProvider,
    pub unresolved_03c_040: [usize; 2],
    pub resource_id: u32,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(DrawResourceObject, resources) == 0x38);
    assert!(core::mem::offset_of!(DrawResourceObject, resource_id) == 0x44);
};

/// # Safety
/// Object must be readable; its provider chain and virtual methods must
/// satisfy resource_chain_find's unchecked retail contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn draw_resource_lookup(object: *const DrawResourceObject) -> *mut u8 {
    let id = unsafe { (*object).resource_id };
    let head = unsafe { (*object).resources };
    unsafe { resource_chain_find(head, ResourceKind(0x4472_6177), id) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::resource_chain::ResourceProviderVTable;
    use core::ptr;

    #[repr(C)]
    struct Provider {
        base: ResourceProvider,
        expected_id: u32,
        answer: *mut u8,
        accepted: u32,
        calls: u32,
    }

    unsafe extern "C" fn find(node: *mut ResourceProvider, kind: ResourceKind, id: u32, out: *mut *mut u8) -> u32 {
        let node = unsafe { &mut *node.cast::<Provider>() };
        assert_eq!(kind, ResourceKind(0x4472_6177));
        assert_eq!(id, node.expected_id);
        node.calls += 1;
        if !node.answer.is_null() || node.accepted != 0 {
            unsafe { *out = node.answer; }
        }
        node.accepted
    }
    unsafe extern "C" fn read(_: *mut ResourceProvider, _: ResourceKind, _: u32) -> u32 { 0 }
    unsafe extern "C" fn replace(_: *mut ResourceProvider, _: *mut ResourceProvider) -> u32 { 0 }
    unsafe extern "C" fn write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: u32, _: u32) -> u32 { 0 }

    fn vtable() -> ResourceProviderVTable {
        ResourceProviderVTable {
            slots_below: [None; 22], read, slot_5c: None, replacement_allowed: replace, find, write,
        }
    }
    fn provider(vtable: &ResourceProviderVTable, id: u32) -> Provider {
        Provider {
            base: ResourceProvider { vtable, state_below_next: [ptr::null_mut(); 4], next: ptr::null_mut() },
            expected_id: id, answer: ptr::null_mut(), accepted: 0, calls: 0,
        }
    }
    fn object(head: *mut ResourceProvider, id: u32) -> DrawResourceObject {
        DrawResourceObject { unresolved_000_034: [usize::MAX; 14], resources: head,
            unresolved_03c_040: [usize::MAX; 2], resource_id: id }
    }

    #[test]
    fn empty_and_exhausted_chains_return_null_for_id_boundaries() {
        let table = vtable();
        for id in [0, 1, u32::MAX] {
            let empty = object(ptr::null_mut(), id);
            unsafe { assert!(draw_resource_lookup(&empty).is_null()); }
            let mut node = provider(&table, id);
            let receiver = object(&mut node.base, id);
            unsafe { assert!(draw_resource_lookup(&receiver).is_null()); }
            assert_eq!(node.calls, 1);
        }
    }

    #[test]
    fn child_answer_and_noncanonical_acceptance_stop_traversal() {
        let table = vtable();
        let mut payload = [0u32, 0x1234_5678];
        let mut last = provider(&table, u32::MAX);
        let mut child = provider(&table, u32::MAX);
        child.answer = payload.as_mut_ptr().cast();
        child.accepted = 0x8000_0000;
        child.base.next = &mut last.base;
        let mut first = provider(&table, u32::MAX);
        first.base.next = &mut child.base;
        let receiver = object(&mut first.base, u32::MAX);
        unsafe {
            let result = draw_resource_lookup(&receiver);
            assert_eq!(result, payload.as_mut_ptr().cast());
            assert_eq!(*result.cast::<u32>().add(1), 0x1234_5678);
        }
        assert_eq!((first.calls, child.calls, last.calls), (1, 1, 0));
        child.answer = ptr::null_mut();
        unsafe { assert!(draw_resource_lookup(&receiver).is_null()); }
        assert_eq!(last.calls, 0);
    }

    #[test]
    fn declining_provider_write_survives_later_miss() {
        let table = vtable();
        let mut payload = 42u32;
        let mut child = provider(&table, 7);
        let mut first = provider(&table, 7);
        first.answer = (&mut payload as *mut u32).cast();
        first.base.next = &mut child.base;
        let receiver = object(&mut first.base, 7);
        unsafe { assert_eq!(draw_resource_lookup(&receiver), first.answer); }
        assert_eq!((first.calls, child.calls), (1, 1));
    }
}
