//! Object selected-payload index lookup @ `0x082a3140`.
//!
//! Load address: `0x082a3140`; true size: 84 bytes (`0x54`), ending in
//! `pop {r4-r6, pc}` before the next real function at `0x082a3194`. Raw ARM
//! decoding verifies zero plain `bl` instructions and zero predicated `bl`
//! instructions; its only call is an indirect `blx` through vtable slot `+0x8`.
//!
//! The wrapper asks the object whether its selected payload is available. On a
//! nonzero result it reads the target-width pointer selected by bit 0 of the
//! payload descriptor at `object+0x08`, then tail-calls the stock indexed
//! payload lookup at `0x08044834`. Missing availability, an unselected
//! descriptor, or a NULL selected payload returns zero.
//!
//! Deliberate deviations: the indirect vtable dispatch and tail target are
//! replaceable host seams. Their concrete class and ownership identities are
//! unproven; their addresses and observed argument/return behavior are not.

#[cfg(target_os = "none")]
unsafe fn object_vtable_slot_8_query(object: *mut u8) -> u32 {
    let vtable = core::ptr::read(object as *const u32) as usize as *const u8;
    let method = core::ptr::read(vtable.add(8) as *const u32) as usize;
    (core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8) -> u32>(method))(object)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_vtable_slot_8_query(_: *mut u8) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
pub static mut OBJECT_VTABLE_SLOT_8_QUERY: unsafe extern "C" fn(*mut u8) -> u32 =
    missing_object_vtable_slot_8_query;

#[cfg(target_os = "none")]
unsafe fn resource_payload_index_lookup(payload: *mut u8, index: u32) -> u32 {
    (core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8, u32) -> u32>(0x0804_4834))(payload, index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resource_payload_index_lookup(_: *mut u8, _: u32) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
pub static mut RESOURCE_PAYLOAD_INDEX_LOOKUP: unsafe extern "C" fn(*mut u8, u32) -> u32 =
    missing_resource_payload_index_lookup;

/// Queries the selected payload of `object` for `index`.
///
/// `object` must point to the retail object's target-width layout. The vtable
/// query and, when selected, the payload lookup receive unchecked pointers,
/// exactly as in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_selected_payload_index(object: *mut u8, index: u32) -> u32 {
    #[cfg(target_os = "none")]
    if object_vtable_slot_8_query(object) == 0 { return 0; }
    #[cfg(not(target_os = "none"))]
    if OBJECT_VTABLE_SLOT_8_QUERY(object) == 0 { return 0; }

    let descriptor = core::ptr::read(object.add(8) as *const u32) as usize as *const u8;
    let flags = core::ptr::read(descriptor);
    if flags & 1 == 0 { return 0; }
    let payload = core::ptr::read(descriptor.add(0x14) as *const u32) as usize as *mut u8;
    if payload.is_null() { return 0; }

    #[cfg(target_os = "none")]
    return resource_payload_index_lookup(payload, index);
    #[cfg(not(target_os = "none"))]
    return RESOURCE_PAYLOAD_INDEX_LOOKUP(payload, index);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, OBJECT_SELECTED_PAYLOAD_INDEX_TEST_LOCK};

    static mut QUERY_RESULT: u32 = 0;
    static mut LOOKUP_ARGUMENTS: (*mut u8, u32) = (core::ptr::null_mut(), 0);
    unsafe extern "C" fn query(_: *mut u8) -> u32 { QUERY_RESULT }
    unsafe extern "C" fn lookup(payload: *mut u8, index: u32) -> u32 {
        LOOKUP_ARGUMENTS = (payload, index);
        0xdecafbad
    }

    #[test]
    fn only_selected_available_payloads_reach_index_lookup() {
        let _lock = OBJECT_SELECTED_PAYLOAD_INDEX_TEST_LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::OBJECT_SELECTED_PAYLOAD_INDEX, 0x1000) else {
            note_missing_u32_fixture("util/object_selected_payload_index"); return;
        };
        unsafe {
            let object = base;
            let descriptor = base.add(0x100);
            let payload = base.add(0x200);
            core::ptr::write_unaligned(object.add(8) as *mut u32, descriptor as usize as u32);
            core::ptr::write(descriptor, 1);
            core::ptr::write_unaligned(descriptor.add(0x14) as *mut u32, payload as usize as u32);
            let old_query = OBJECT_VTABLE_SLOT_8_QUERY;
            let old_lookup = RESOURCE_PAYLOAD_INDEX_LOOKUP;
            OBJECT_VTABLE_SLOT_8_QUERY = query;
            RESOURCE_PAYLOAD_INDEX_LOOKUP = lookup;
            QUERY_RESULT = 0;
            assert_eq!(object_selected_payload_index(object, 7), 0);
            QUERY_RESULT = 1;
            core::ptr::write(descriptor, 0);
            assert_eq!(object_selected_payload_index(object, 7), 0);
            core::ptr::write(descriptor, 1);
            core::ptr::write_unaligned(descriptor.add(0x14) as *mut u32, 0);
            assert_eq!(object_selected_payload_index(object, 7), 0);
            core::ptr::write_unaligned(descriptor.add(0x14) as *mut u32, payload as usize as u32);
            assert_eq!(object_selected_payload_index(object, 0x1234), 0xdecafbad);
            assert_eq!(LOOKUP_ARGUMENTS, (payload, 0x1234));
            OBJECT_VTABLE_SLOT_8_QUERY = old_query;
            RESOURCE_PAYLOAD_INDEX_LOOKUP = old_lookup;
        }
    }
}
