//! Pending-event link search — `FUN_08139190` @ load address 0x08139190.
//! True extent: 92 bytes, [0x08139190, 0x081391ec): 88 code bytes and
//! the 0x0000ffff literal at 0x081391e8. The next entry is a branch veneer.
//! Raw whole-image A32 decoding verifies two inbound plain BLs (0x08138f4c,
//! 0x081390b0), zero predicated inbound BLs, and zero outbound BLs.
//!
//! Start at the session's +4 head word; follow target-width next pointers.
//! Return the address of the link pointing at the first node whose key is
//! exact and whose tags equal the full-width query or accept query 0xffff.
//! Return NULL on exhaustion. Callers use this link to unlink the node.
//! Ghidra's void return is incorrect; r0 retains the matching link address.
//! No deliberate behavioral deviations; LLVM may reorder ordinary reads.

use super::pending_event_take::PendingEventNode;
use core::ptr;

/// Search a readable, acyclic pending-event chain. The caller owns the
/// queue lock; all nonzero links must address live `PendingEventNode`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_event_find_link(
    session: *mut u8,
    key: u32,
    tag_a: u32,
    tag_b: u32,
) -> *mut u32 {
    let mut link = session.wrapping_add(4).cast::<u32>();
    while !link.is_null() {
        let node = ptr::read(link) as usize as *mut PendingEventNode;
        if node.is_null() {
            return ptr::null_mut();
        }
        if (*node).key == key
            && (tag_a == (*node).tag_a as u32 || tag_a == 0xffff)
            && (tag_b == (*node).tag_b as u32 || tag_b == 0xffff)
        {
            return link;
        }
        link = ptr::addr_of_mut!((*node).next);
    }
    ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn first_match_link_wildcards_and_full_width_queries() {
        unsafe {
            let Some(slab) = try_map_u32_slab(hints::PENDING_EVENT_FIND_LINK, 4096) else {
                note_missing_u32_fixture("app::pending_event_find_link");
                return;
            };
            let head = slab.add(4).cast::<u32>();
            let nodes = slab.add(32).cast::<PendingEventNode>();
            head.write(0);
            assert!(pending_event_find_link(slab, 7, 1, 2).is_null());
            for i in 0..4 {
                nodes.add(i).write(PendingEventNode {
                    next: if i == 3 { 0 } else { nodes.add(i + 1) as usize as u32 },
                    key: if i == 0 { 8 } else { 7 },
                    deadline_ms: 0,
                    tag_a: if i == 1 { 3 } else { 1 },
                    tag_b: if i == 2 { 4 } else { 2 },
                    payload: i as u32,
                });
            }
            head.write(nodes as usize as u32);
            let before = core::slice::from_raw_parts(slab, 112).to_vec();
            for (key, a, b, index) in [
                (8, 1, 2, 0), (7, 1, 2, 3), (7, 0xffff, 2, 1),
                (7, 1, 0xffff, 2), (7, 0xffff, 0xffff, 1),
            ] {
                let expected = if index == 0 { head } else {
                    ptr::addr_of_mut!((*nodes.add(index - 1)).next)
                };
                assert_eq!(pending_event_find_link(slab, key, a, b), expected);
            }
            for (key, a, b) in [(9, 0xffff, 0xffff), (7, 5, 2), (7, 1, 5),
                (7, 0x10001, 2), (7, 1, 0x10002), (7, 0x1ffff, 2)] {
                assert!(pending_event_find_link(slab, key, a, b).is_null());
            }
            assert_eq!(core::slice::from_raw_parts(slab, 112), before);
        }
    }
}
