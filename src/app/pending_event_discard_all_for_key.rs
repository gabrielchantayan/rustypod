//! `pending_event_discard_all_for_key` — original: `FUN_081e2d48` @
//! 0x081e2d48.
//!
//! **Extent:** 76 bytes of code, 0x081e2d48..0x081e2d94; the next function
//! starts at 0x081e2d98 and the intervening word is the 0x0000ffff literal.
//! **Call count:** raw osos.dec decoding finds one unconditional `bl` (to
//! [`super::pending_event_take::pending_event_take`]), zero predicated `bl`.
//!
//! Read the session's selected key at +0x2d0, then repeatedly take a pending
//! event with both tags wildcarded and discard its payload until the keyed take
//! reports no entry. The saved caller `r0` is restored on return.
//!
//! # Deliberate deviations
//!
//! The Rust port returns `this` explicitly rather than relying on the ARM
//! push/pop register restoration; both preserve the caller's original `r0`.

use super::pending_event_take::{pending_event_take, WILDCARD_TAG};

const SELECTED_KEY_OFFSET: usize = 0x2d0;

/// Discard every pending event for the session's selected key.
///
/// Original: `FUN_081e2d48` @ 0x081e2d48 (76 bytes; one unconditional `bl`,
/// zero predicated `bl`, binary-verified — see module header).
///
/// # Safety
/// `this` must name a queue-bearing playback session with a readable key at
/// +0x2d0 and the layout required by [`pending_event_take`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_event_discard_all_for_key(this: *mut u8) -> *mut u8 {
    let key = this.add(SELECTED_KEY_OFFSET).cast::<u32>().read();
    loop {
        let mut tag_a = WILDCARD_TAG;
        let mut tag_b = WILDCARD_TAG;
        let mut payload = 0u32;
        if pending_event_take(this, key, &mut tag_a, &mut tag_b, &mut payload) != 0 {
            return this;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::pending_event_take::{
        PendingEventNode, PendingEventTakeOps, PENDING_EVENT_TAKE_OPS,
    };
    use crate::testing::{
        hints, note_missing_u32_fixture, try_map_u32_slab, PENDING_EVENT_TAKE_OPS_TEST_LOCK,
    };

    const SESSION_LEN: usize = 0x400;
    const HEAD_OFFSET: usize = 0;
    const NODE_OFFSET: usize = 0x320;
    static mut SLAB: *mut u8 = core::ptr::null_mut();
    static mut FIND_CALLS: u32 = 0;

    unsafe fn slab() -> *mut u8 {
        if SLAB.is_null() {
            SLAB = try_map_u32_slab(hints::PENDING_EVENT_DISCARD_ALL_FOR_KEY, SESSION_LEN)
                .unwrap_or(core::ptr::null_mut());
        }
        SLAB
    }

    unsafe fn head() -> *mut u32 {
        slab().add(HEAD_OFFSET).cast()
    }

    unsafe extern "C" fn find_link(
        _this: *mut u8,
        key: u32,
        tag_a: u16,
        tag_b: u16,
    ) -> *mut u32 {
        FIND_CALLS += 1;
        let mut link = head();
        while *link != 0 {
            let node = *link as usize as *mut PendingEventNode;
            if (*node).key == key
                && (tag_a == WILDCARD_TAG || tag_a == (*node).tag_a)
                && (tag_b == WILDCARD_TAG || tag_b == (*node).tag_b)
            {
                return link;
            }
            link = core::ptr::addr_of_mut!((*node).next);
        }
        core::ptr::null_mut()
    }

    unsafe extern "C" fn release_node(_this: *mut u8, node: *mut PendingEventNode) -> u32 {
        let mut link = head();
        while (*link as usize as *mut PendingEventNode) != node {
            link = core::ptr::addr_of_mut!((*( *link as usize as *mut PendingEventNode)).next);
        }
        *link = (*node).next;
        0
    }

    unsafe extern "C" fn rearm_timer(_this: *mut u8) -> u32 { 0 }

    unsafe fn install_ops() -> PendingEventTakeOps {
        let previous = PENDING_EVENT_TAKE_OPS;
        PENDING_EVENT_TAKE_OPS = PendingEventTakeOps { find_link, release_node, rearm_timer };
        previous
    }

    #[test]
    fn discards_every_matching_key_and_keeps_other_entries() {
        let _lock = PENDING_EVENT_TAKE_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let slab = slab();
            if slab.is_null() {
                note_missing_u32_fixture("app::pending_event_discard_all_for_key");
                return;
            }
            core::ptr::write_bytes(slab, 0, SESSION_LEN);
            FIND_CALLS = 0;
            let previous = install_ops();
            let first = slab.add(NODE_OFFSET).cast::<PendingEventNode>();
            let middle = first.add(1);
            let last = first.add(2);
            *first = PendingEventNode { next: middle as usize as u32, key: 7, deadline_ms: 0, tag_a: 1, tag_b: 2, payload: 3 };
            *middle = PendingEventNode { next: last as usize as u32, key: 8, deadline_ms: 0, tag_a: 4, tag_b: 5, payload: 6 };
            *last = PendingEventNode { next: 0, key: 7, deadline_ms: 0, tag_a: 9, tag_b: 10, payload: 11 };
            *head() = first as usize as u32;
            slab.add(SELECTED_KEY_OFFSET).cast::<u32>().write(7);

            assert_eq!(pending_event_discard_all_for_key(slab), slab);
            assert_eq!(*head(), middle as usize as u32);
            assert_eq!((*middle).next, 0);
            assert_eq!(FIND_CALLS, 3);
            PENDING_EVENT_TAKE_OPS = previous;
        }
    }

    #[test]
    fn returns_this_after_the_first_miss() {
        let _lock = PENDING_EVENT_TAKE_OPS_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let slab = slab();
            if slab.is_null() {
                note_missing_u32_fixture("app::pending_event_discard_all_for_key");
                return;
            }
            core::ptr::write_bytes(slab, 0, SESSION_LEN);
            FIND_CALLS = 0;
            let previous = install_ops();
            slab.add(SELECTED_KEY_OFFSET).cast::<u32>().write(99);
            assert_eq!(pending_event_discard_all_for_key(slab), slab);
            assert_eq!(FIND_CALLS, 1);
            PENDING_EVENT_TAKE_OPS = previous;
        }
    }
}
