//! Optional global object's mailbox notification.
//!
//! `global_mailbox_post` — original `FUN_080aac00` @ 0x080aac00.
//! True extent: 28 bytes, 0x080aac00..0x080aac1c: six instructions
//! (24 bytes) plus the literal 0x089caed0 at 0x080aac18. The next
//! function begins with `mov r0,r0,lsl #22` at 0x080aac1c. Full-image
//! A32 decoding finds two plain inbound BLs (0x080609b4, 0x080609ec),
//! zero predicated inbound BLs, and zero outbound BLs. One outbound
//! conditional tail branch reaches mailbox_slot_post @ 0x0808e2a8.
//!
//! Read the object pointer in global cell 0x089caed0. If null, return;
//! otherwise post the mailbox pointer slot at object +0x14 through the
//! existing mailbox_slot_post port. The object's wider identity remains
//! unknown; callers notify after handling event-mask bits 0x20 and 0x40.
//! Deliberate deviations: Rust branching replaces ARM predication; host
//! builds substitute a native-pointer global cell. A repr(C) object view
//! preserves target +0x14 while permitting native host pointer alignment.
//! The original leaves r0 zero on the null path; callers consume no return
//! value, and the posting path has no defined value, so the ABI returns void.

use crate::kernel::kobj::{mailbox_slot_post, Mailbox};
use core::ptr;

#[repr(C)]
pub struct GlobalMailboxObject {
    pub opaque_prefix: [u32; 5],
    /// Target +0x14; this is a pointer slot, not an embedded mailbox.
    pub mailbox: *mut Mailbox,
}

#[cfg(not(target_os = "none"))]
static mut HOST_GLOBAL_MAILBOX_OBJECT: *mut GlobalMailboxObject = ptr::null_mut();

/// # Safety
/// The global cell must be readable. Its nonnull object must contain a
/// live mailbox slot whose semaphore satisfies mailbox_slot_post's contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_mailbox_post() {
    #[cfg(target_os = "none")]
    let object = ptr::read_volatile(0x089c_aed0usize as *const *mut GlobalMailboxObject);
    #[cfg(not(target_os = "none"))]
    let object = ptr::read_volatile(ptr::addr_of!(HOST_GLOBAL_MAILBOX_OBJECT));

    if !object.is_null() {
        mailbox_slot_post(ptr::addr_of_mut!((*object).mailbox));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_object_skips_post_and_each_call_uses_current_object_and_slot() {
        let _guard = crate::kernel::kobj::tests::HOOKS_LOCK.lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut first = Mailbox { state: 7, id: 0x1234 };
        let mut second = Mailbox { state: i32::MAX as u32, id: 0x5678 };
        let mut object = GlobalMailboxObject { opaque_prefix: [0xa5a5_a5a5; 5], mailbox: &mut first };
        unsafe {
            HOST_GLOBAL_MAILBOX_OBJECT = ptr::null_mut();
            global_mailbox_post();
            assert_eq!(first.state, 7);
            HOST_GLOBAL_MAILBOX_OBJECT = &mut object;
            global_mailbox_post();
            assert_eq!(first.state, 8);
            object.mailbox = &mut second;
            global_mailbox_post();
            assert_eq!(second.state, i32::MIN as u32);
            assert_eq!(first.state, 8);
            second.state = u32::MAX - 1;
            global_mailbox_post();
            assert_eq!(second.state, u32::MAX);
            assert_eq!(object.opaque_prefix, [0xa5a5_a5a5; 5]);
            assert_eq!((first.id, second.id), (0x1234, 0x5678));
            HOST_GLOBAL_MAILBOX_OBJECT = ptr::null_mut();
            global_mailbox_post();
            assert_eq!(second.state, u32::MAX);
        }
    }
}
