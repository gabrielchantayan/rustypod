//! Indexed lookup of linked-record storage slots.

/// retailOS `FUN_08057e88` @ 0x08057e88, 68 bytes (next entry 0x08057ecc).
/// Verified raw A32: two plain inbound BLs, zero predicated inbound BLs;
/// zero outgoing BLs. Walk the chain rooted at owner word 3, comparing a
/// wrapping u32 ordinal before following each node's word-0 next pointer.
/// On success store the addresses of node words 5 and 4, in that order,
/// and return zero. Exhaustion returns -123 without touching the outputs.
/// No deliberate behavioral deviations; target pointer fields remain u32
/// even on hosts, while output pointer slots use the native pointer ABI.
///
/// # Safety
/// `owner` must have four readable aligned words. Every nonzero chain link
/// must address a readable aligned next-pointer word; a selected node must
/// contain at least six words. On success both output slots must be writable
/// and aligned. Outputs may alias; the second store wins.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_record_slots_at(
    owner: *const u32,
    index: u32,
    payload_slot: *mut *mut u32,
    value_slot: *mut *mut u32,
) -> i32 {
    let mut node = owner.add(3).read() as usize as *mut u32;
    let mut ordinal = 0u32;
    while !node.is_null() {
        if ordinal == index {
            let payload = node.add(5);
            let value = node.add(4);
            payload_slot.write(payload);
            value_slot.write(value);
            return 0;
        }
        node = node.read() as usize as *mut u32;
        ordinal = ordinal.wrapping_add(1);
    }
    -123
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_boundaries_slot_addresses_and_aliasing() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::LINKED_RECORD_SLOTS_AT, 4096,
        ) else {
            crate::testing::note_missing_u32_fixture("linked_record_slots_at");
            return;
        };
        unsafe {
            let first = slab.cast::<u32>();
            let second = first.add(8);
            let third = first.add(16);
            // Noncontiguous nodes: lookup must follow links, not stride.
            first.write(third as usize as u32);
            third.write(second as usize as u32);
            second.write(0);
            let mut owner = [0u32; 4];
            let sentinel = first.add(24);
            let mut payload = sentinel;
            let mut value = sentinel;
            for index in [0, 1, u32::MAX] {
                assert_eq!(linked_record_slots_at(owner.as_ptr(), index,
                    &mut payload, &mut value), -123);
                assert_eq!((payload, value), (sentinel, sentinel));
            }
            // Failure must not even dereference output slots.
            assert_eq!(linked_record_slots_at(owner.as_ptr(), 0,
                core::ptr::null_mut(), core::ptr::null_mut()), -123);
            owner[3] = first as usize as u32;
            for (index, node) in [first, third, second].into_iter().enumerate() {
                assert_eq!(linked_record_slots_at(owner.as_ptr(), index as u32,
                    &mut payload, &mut value), 0);
                assert_eq!(payload, node.add(5));
                assert_eq!(value, node.add(4));
                payload.write(0x1122_3344 + index as u32);
                value.write(0x5566_7788 + index as u32);
                assert_eq!(node.add(5).read(), 0x1122_3344 + index as u32);
                assert_eq!(node.add(4).read(), 0x5566_7788 + index as u32);
            }
            for index in [3, 4, u32::MAX] {
                payload = sentinel;
                value = sentinel;
                assert_eq!(linked_record_slots_at(owner.as_ptr(), index,
                    &mut payload, &mut value), -123);
                assert_eq!((payload, value), (sentinel, sentinel));
            }
            let output = &mut payload as *mut *mut u32;
            assert_eq!(linked_record_slots_at(owner.as_ptr(), 1, output, output), 0);
            assert_eq!(payload, third.add(4));
        }
    }
}
