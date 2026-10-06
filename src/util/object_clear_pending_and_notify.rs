//! `object_clear_pending_and_notify` — `FUN_081660a4` @ 0x081660a4.
//! True extent: 28 bytes, 0x081660a4..0x081660c0. Whole-image A32 word
//! scanning finds two incoming plain BLs (0x081667bc, 0x082831dc), zero
//! predicated BLs, and no outgoing BLs. The next entry stores r1 at +0x4a.
//!
//! Clears the pending byte at +0x4a before invoking the optional callback
//! at +0x3c with the original object. Without a callback, tail-posts the
//! mailbox slot at +0x5c through the existing 0x0808e2a8 port. Callers first
//! write completion state 6 at +0x58 and a result at +0x40. The callback's
//! identity and the pending byte's wider lifecycle remain unresolved.
//!
//! Deliberate deviations: conditional Rust control flow replaces ARM
//! predication/tail branches. Native pointer fields in a repr(C) view keep
//! target offsets exact while allowing host fixtures without truncation;
//! host field offsets consequently differ. No invented callback service.

use crate::kernel::kobj::{mailbox_slot_post, Mailbox};

/// Partial object view; opaque fields are retained, not interpreted.
#[repr(C)]
pub struct NotificationObject {
    pub opaque_prefix: [u32; 15],
    /// Target +0x3c; callback receives this object, not the mailbox.
    pub callback: Option<unsafe extern "C" fn(*mut NotificationObject)>,
    pub opaque_before_pending: [u8; 10],
    /// Target +0x4a.
    pub pending: u8,
    pub opaque_before_mailbox: [u8; 17],
    /// Target +0x5c; dereferenced only when callback is absent.
    pub mailbox: *mut Mailbox,
}

/// # Safety
/// `object` must be a live, writable NotificationObject. Its callback must
/// be callable with this object, or its mailbox must be a live semaphore.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_clear_pending_and_notify(object: *mut NotificationObject) {
    (*object).pending = 0;
    if let Some(callback) = (*object).callback {
        callback(object);
    } else {
        mailbox_slot_post(core::ptr::addr_of_mut!((*object).mailbox));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(callback: Option<unsafe extern "C" fn(*mut NotificationObject)>, mailbox: *mut Mailbox) -> NotificationObject {
        NotificationObject {
            opaque_prefix: [0xa5a5_a5a5; 15], callback,
            opaque_before_pending: [0xa5; 10], pending: 0xff,
            opaque_before_mailbox: [0xa5; 17], mailbox,
        }
    }

    unsafe extern "C" fn complete(object: *mut NotificationObject) {
        // Observable callback effect depends on the clear happening first.
        (*object).opaque_prefix[0] = (*object).pending as u32 + 7;
        (*object).pending = 9;
    }

    #[test]
    fn callback_observes_clear_and_can_rearm_without_a_mailbox() {
        let mut object = fixture(Some(complete), core::ptr::null_mut());
        unsafe { object_clear_pending_and_notify(&mut object) };
        assert_eq!(object.opaque_prefix[0], 7);
        assert_eq!(object.pending, 9, "callback's rearm must survive return");
        assert_eq!(object.opaque_prefix[1..], [0xa5a5_a5a5; 14]);
        assert_eq!(object.opaque_before_pending, [0xa5; 10]);
        assert_eq!(object.opaque_before_mailbox, [0xa5; 17]);
    }

    #[test]
    fn absent_callback_clears_pending_and_posts_current_mailbox_with_wrapping_count() {
        let _guard = crate::kernel::kobj::tests::HOOKS_LOCK.lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut mailbox = Mailbox { state: 0, id: 0x1234 };
        let mut object = fixture(None, &mut mailbox);
        for (before, after) in [(0, 1), (7, 8), (i32::MAX as u32, i32::MIN as u32), (u32::MAX - 1, u32::MAX)] {
            mailbox.state = before;
            object.pending = 0xff;
            unsafe { object_clear_pending_and_notify(&mut object) };
            assert_eq!(object.pending, 0);
            assert_eq!(mailbox.state, after);
            assert_eq!(mailbox.id, 0x1234);
            assert_eq!(object.opaque_prefix, [0xa5a5_a5a5; 15]);
            assert_eq!(object.opaque_before_pending, [0xa5; 10]);
            assert_eq!(object.opaque_before_mailbox, [0xa5; 17]);
        }
    }
}
