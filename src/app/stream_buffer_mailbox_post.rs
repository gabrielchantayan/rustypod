//! Stream-buffer writer's global mailbox post.
//!
//! `stream_buffer_mailbox_post` — `FUN_0827dda8` @ 0x0827dda8.
//! True extent: 16 bytes (12 instruction bytes plus the literal at
//! 0x0827ddb4); next real function starts at 0x0827ddb8. Raw ARM scanning
//! finds 2 plain BL callers (0x08168040, 0x08168084), 0 predicated BL
//! callers, and no outgoing BL: the final instruction is a tail branch.
//!
//! Words `e59f0004 e3a01000 eaf973dc 089cfd40` load the address of the
//! mailbox pointer slot at 0x089cfd40, select mode zero, and tail-call
//! `mailbox_slot_post_dispatch` at 0x080dad28. The stream-buffer writer
//! at 0x08167f28 posts after advancing a filled buffer and observing at
//! most 0x180000 buffered bytes. No NULL checks or slot writes are added.
//! Deliberate deviations: Rust expresses the tail branch as a call;
//! host builds use a native-width substitute slot instead of firmware RAM.

use crate::kernel::kobj::{Mailbox, mailbox_slot_post_dispatch};

#[cfg(not(target_os = "none"))]
pub(crate) static mut STREAM_BUFFER_MAILBOX: *mut Mailbox = core::ptr::null_mut();

/// # Safety
/// The global slot must contain a live mailbox, initialized by firmware
/// (or by the host harness); the caller must obey its synchronization rules.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_buffer_mailbox_post() {
    #[cfg(target_os = "none")]
    let slot = 0x089cfd40usize as *mut *mut Mailbox;
    #[cfg(not(target_os = "none"))]
    let slot = core::ptr::addr_of_mut!(STREAM_BUFFER_MAILBOX);
    mailbox_slot_post_dispatch(slot, 0);
}
