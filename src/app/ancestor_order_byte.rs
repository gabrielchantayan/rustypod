//! Ancestor ordering byte — FUN_080a6828 @ 0x080a6828.
//! True extent: [0x080a6828,0x080a6858), 48 bytes, no literals.
//! Verified raw A32: two plain BLs, zero predicated BLs; two incoming plain
//! BL sites (0x0826dc3c and 0x0826dcf8). The next function starts with PUSH.
//! Try class 0x1180 on the initial object, then successive parents at +0x34.
//! Return the first cast result's unsigned byte at +0xe8. Exhaustion is fatal.
//! The caller compares these bytes when inserting related UI objects.
//! Deviations: structured Rust loop rather than conditional load/return;
//! repr(C) pointer fields widen on hosts but retain target offsets on ARM.
//! No added initial NULL guard, cycle detection, or boolean normalization.

use super::registry::{object_cast_to_class, FrameworkObject};
use crate::heap::veneers::heap_panic;

#[repr(C)]
pub struct AncestorOrderNode {
    pub object: FrameworkObject,
    pub unresolved_04: [u32; 12],
    pub parent: *mut AncestorOrderNode,
}

/// # Safety
/// Each visited node must be live, with a valid framework vtable and parent
/// field. Successful casts must provide a readable byte at offset 0xe8.
/// An initial NULL pointer is invalid; a chain without a match is fatal.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ancestor_order_byte(mut node: *mut AncestorOrderNode) -> u32 {
    loop {
        let matched = object_cast_to_class(node.cast(), 0x1180);
        if !matched.is_null() {
            return matched.add(0xe8).read() as u32;
        }
        node = core::ptr::read_volatile(core::ptr::addr_of!((*node).parent));
        if node.is_null() { heap_panic(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::registry::FrameworkObjectVtable;

    #[repr(C)]
    struct Fixture {
        node: AncestorOrderNode,
        result: *mut u8,
    }

    unsafe extern "C" fn cast(object: *mut FrameworkObject, class: u32) -> *mut u8 {
        assert_eq!(class, 0x1180);
        (*(object as *mut Fixture)).result
    }

    static VTABLE: FrameworkObjectVtable = FrameworkObjectVtable {
        unresolved_00: [0; 5], cast_to_class: cast,
    };

    fn fixture(result: *mut u8, parent: *mut AncestorOrderNode) -> Fixture {
        Fixture {
            node: AncestorOrderNode {
                object: FrameworkObject { vtable: &VTABLE },
                unresolved_04: [0; 12], parent,
            },
            result,
        }
    }

    #[test]
    fn first_match_returns_full_unsigned_byte_without_visiting_parent() {
        for value in [0, 1, 0x7f, 0x80, 0xff] {
            let mut payload = [0xa5u8; 0xe9];
            payload[0xe8] = value;
            // A poison parent proves success does not dereference the link.
            let mut node = fixture(payload.as_mut_ptr(), 1usize as *mut AncestorOrderNode);
            assert_eq!(unsafe { ancestor_order_byte(&mut node.node) }, value as u32);
        }
    }

    #[test]
    fn rejected_nodes_are_skipped_and_nearest_matching_ancestor_wins() {
        let mut far_payload = [0u8; 0xe9];
        far_payload[0xe8] = 19;
        let mut near_payload = [0u8; 0xe9];
        near_payload[0xe8] = 243;
        let mut far = fixture(far_payload.as_mut_ptr(), core::ptr::null_mut());
        let mut near = fixture(near_payload.as_mut_ptr(), &mut far.node);
        let mut middle = fixture(core::ptr::null_mut(), &mut near.node);
        let mut start = fixture(core::ptr::null_mut(), &mut middle.node);
        assert_eq!(unsafe { ancestor_order_byte(&mut start.node) }, 243);
        near.result = core::ptr::null_mut();
        assert_eq!(unsafe { ancestor_order_byte(&mut start.node) }, 19);
    }
}
