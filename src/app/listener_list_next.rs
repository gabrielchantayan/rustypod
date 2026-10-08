//! Listener-list cursor advancement.

/// Advance the listener list cursor and return the current node's payload.
///
/// Original: `FUN_0811f244` @ 0x0811f244, 44 bytes through 0x0811f270.
/// Raw A32 words verify two inbound plain BL sites (0x0821af00 and
/// 0x0821b5ec), zero predicated inbound BLs, and zero outbound BLs.
/// Compare owner word 12 (+0x30) with sentinel word 10 (+0x28). If equal,
/// return NULL without touching the sentinel; otherwise save node word zero
/// as the next cursor and return node +8. Deliberate deviation: omit the
/// unused stack copy of the sentinel. Pointer fields remain target-width u32.
///
/// # Safety
/// `owner` must hold at least 13 aligned words. Unless cursor equals the
/// sentinel, it must identify a readable aligned node with a successor word
/// and payload at +8. NULL is not a special cursor unless it is the sentinel.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn listener_list_next(owner: *mut u32) -> *mut u32 {
    let sentinel = owner.add(10).read();
    let cursor = owner.add(12).read();
    if cursor == sentinel {
        core::ptr::null_mut()
    } else {
        let node = cursor as usize as *mut u32;
        owner.add(12).write(node.read());
        node.add(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_cursor_does_not_dereference_sentinel_or_change_owner() {
        for sentinel in [0, 1, 0xffff_fffc] {
            let mut owner = [0xa5a5_a5a5; 13];
            owner[10] = sentinel;
            owner[12] = sentinel;
            let before = owner;
            unsafe {
                assert!(listener_list_next(owner.as_mut_ptr()).is_null());
                assert!(listener_list_next(owner.as_mut_ptr()).is_null());
            }
            assert_eq!(owner, before);
        }
    }

    #[test]
    fn traverses_payloads_preserves_links_and_observes_cursor_reset() {
        use crate::testing::{hints, try_map_u32_slab};
        let Some(slab) = try_map_u32_slab(hints::LISTENER_LIST_NEXT, 0x100) else {
            assert!(crate::testing::note_missing_u32_fixture("listener_list_next"));
            return;
        };
        unsafe {
            let nodes = slab.cast::<u32>();
            let second = nodes.add(8);
            let sentinel = nodes.add(16);
            nodes.write(second as u32);
            nodes.add(1).write(sentinel as u32);
            nodes.add(2).write(0x1234);
            second.write(sentinel as u32);
            second.add(1).write(nodes as u32);
            second.add(2).write(0x5678);
            // A sentinel successor deliberately differs from the end marker.
            sentinel.write(nodes as u32);
            let mut owner = [0xdead_beef; 13];
            owner[10] = sentinel as u32;
            owner[12] = nodes as u32;
            let mut expected = owner;
            assert_eq!(listener_list_next(owner.as_mut_ptr()), nodes.add(2));
            expected[12] = second as u32;
            assert_eq!(owner, expected);
            let payload = listener_list_next(owner.as_mut_ptr());
            assert_eq!(payload, second.add(2));
            assert_eq!(payload.read(), 0x5678);
            payload.write(0xabcd);
            expected[12] = sentinel as u32;
            assert_eq!(owner, expected);
            assert!(listener_list_next(owner.as_mut_ptr()).is_null());
            assert_eq!(owner, expected);
            assert_eq!(nodes.read(), second as u32);
            assert_eq!(second.read(), sentinel as u32);
            assert_eq!(sentinel.read(), nodes as u32);
            assert_eq!(second.add(2).read(), 0xabcd);
            owner[12] = second as u32; // singleton traversal after external reset
            assert_eq!(listener_list_next(owner.as_mut_ptr()), second.add(2));
            assert!(listener_list_next(owner.as_mut_ptr()).is_null());
        }
    }
}
