//! Pending-event release — `FUN_0813908c` @ load address 0x0813908c.
//! True extent: 96 instruction bytes, [0x0813908c, 0x081390ec); next
//! function begins with push {r0-r8,lr}. Raw whole-image A32 decoding
//! verifies two inbound plain BLs (0x08138fa4, 0x08139548), zero predicated
//! inbound BLs, and two outbound plain BLs (find-link and heap-panic).
//!
//! Reject NULL fatally. Search by the node's key and halfword tags; a miss
//! returns 0x52 without mutation. A match must point at this exact node,
//! otherwise panic. Unlink it and push it onto the session's +0x18 free
//! list, returning zero. Tags equal to 0xffff retain search's wildcard
//! semantics, so an earlier matching node makes release fatal.
//! No deliberate behavioral deviations; both callees use existing ports.

use super::pending_event_find_link::pending_event_find_link;
use super::pending_event_take::{PendingEventNode, ERR_NO_PENDING_ENTRY};
use crate::heap::veneers::heap_panic;
use core::ptr;

/// Caller holds the queue lock. Session has writable head/free-list words
/// at +4/+0x18; node and all linked nodes are live, aligned target layouts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_event_release(
    session: *mut u8,
    node: *mut PendingEventNode,
) -> u32 {
    if node.is_null() { heap_panic(); }
    let link = pending_event_find_link(session, (*node).key,
        (*node).tag_a as u32, (*node).tag_b as u32);
    if link.is_null() { return ERR_NO_PENDING_ENTRY; }
    if ptr::read(link) != node as usize as u32 { heap_panic(); }
    ptr::write(link, (*node).next);
    let free_head = session.add(0x18).cast::<u32>();
    (*node).next = ptr::read(free_head);
    ptr::write(free_head, node as usize as u32);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn unlink_positions_recycle_and_miss_preserve_payloads() {
        unsafe {
            let Some(slab) = try_map_u32_slab(hints::PENDING_EVENT_RELEASE, 4096) else {
                note_missing_u32_fixture("app::pending_event_release");
                return;
            };
            let head = slab.add(4).cast::<u32>();
            let free = slab.add(0x18).cast::<u32>();
            let nodes = slab.add(64).cast::<PendingEventNode>();
            for index in 0..3 {
                for i in 0..5 {
                    nodes.add(i).write(PendingEventNode {
                        next: if i < 2 { nodes.add(i + 1) as usize as u32 } else { 0 },
                        key: i as u32, deadline_ms: 0x8000_0000 + i as u32,
                        tag_a: i as u16, tag_b: 0xfffe, payload: 0xffff_ffff - i as u32,
                    });
                }
                head.write(nodes as usize as u32);
                free.write(nodes.add(3) as usize as u32);
                let before = core::slice::from_raw_parts(slab, 164).to_vec();
                assert_eq!(pending_event_release(slab, nodes.add(4)), ERR_NO_PENDING_ENTRY);
                assert_eq!(core::slice::from_raw_parts(slab, 164), before);
                let released = nodes.add(index);
                assert_eq!(pending_event_release(slab, released), 0);
                let expected_live: std::vec::Vec<usize> = (0..3).filter(|&i| i != index).collect();
                let mut cursor = head.read();
                for i in expected_live {
                    assert_eq!(cursor, nodes.add(i) as usize as u32);
                    cursor = (*nodes.add(i)).next;
                }
                assert_eq!(cursor, 0);
                assert_eq!(free.read(), released as usize as u32);
                assert_eq!((*released).next, nodes.add(3) as usize as u32);
                for i in 0..5 {
                    assert_eq!((*nodes.add(i)).key, i as u32);
                    assert_eq!((*nodes.add(i)).deadline_ms, 0x8000_0000 + i as u32);
                    assert_eq!((*nodes.add(i)).tag_a, i as u16);
                    assert_eq!((*nodes.add(i)).tag_b, 0xfffe);
                    assert_eq!((*nodes.add(i)).payload, 0xffff_ffff - i as u32);
                }
                // Release the remaining head onto the now nonempty free list.
                let remaining = head.read() as usize as *mut PendingEventNode;
                assert_eq!(pending_event_release(slab, remaining), 0);
                assert_eq!(free.read(), remaining as usize as u32);
                assert_eq!((*remaining).next, released as usize as u32);
            }
            head.write(0);
            let before = core::slice::from_raw_parts(slab, 164).to_vec();
            assert_eq!(pending_event_release(slab, nodes), ERR_NO_PENDING_ENTRY);
            assert_eq!(core::slice::from_raw_parts(slab, 164), before);
        }
    }

    unsafe extern "C" fn invalid_release() -> ! {
        let mode = std::env::var("RUSTYPOD_PENDING_RELEASE_FATAL").unwrap();
        if mode == "null" {
            pending_event_release(ptr::null_mut(), ptr::null_mut());
        } else {
            let slab = try_map_u32_slab(hints::PENDING_EVENT_RELEASE, 4096).unwrap();
            let nodes = slab.add(64).cast::<PendingEventNode>();
            for i in 0..2 {
                nodes.add(i).write(PendingEventNode {
                    next: if i == 0 { nodes.add(1) as usize as u32 } else { 0 },
                    key: 7, deadline_ms: 0,
                    tag_a: if mode == "wildcard" && i == 0 { 1 } else { 0xffff },
                    tag_b: 2, payload: 0,
                });
            }
            slab.add(4).cast::<u32>().write(nodes as usize as u32);
            pending_event_release(slab, nodes.add(1));
        }
        std::process::exit(5);
    }

    #[test]
    fn null_duplicate_and_wildcard_predecessor_are_fatal() {
        for mode in ["null", "duplicate", "wildcard"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "app::pending_event_release::tests::fatal_child"])
                .env("RUSTYPOD_PENDING_RELEASE_FATAL", mode).status().unwrap();
            assert!(status.success(), "{mode}: {status}");
        }
    }

    #[test]
    fn fatal_child() {
        if std::env::var_os("RUSTYPOD_PENDING_RELEASE_FATAL").is_none() { return; }
        crate::heap::veneers::tests::assert_heap_panic_entry_fatal_path(
            "RUSTYPOD_PENDING_RELEASE_FATAL",
            "app::pending_event_release::tests::fatal_child", invalid_release);
    }
}
