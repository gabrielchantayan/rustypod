//! Posts a constructed kind-tagged message to the Silver framework root.
//!
//! [`framework_root_post_message_kind`] — original: `FUN_081d2018` @
//! **0x081d2018** (**32 bytes exactly**, `0x081d2018..0x081d2037`; eight
//! ARM instruction words). Raw `osos.dec` words place the next independently
//! entered function's `push {r1,r2,r3,r4,r5,lr}` at `0x081d2038`. A
//! binary-wide decode finds **3 unconditional `bl` callers**, no predicated
//! `bl` callers, and no tail-branch callers.
//!
//! # Algorithm
//!
//! Allocate eight bytes from the message-kind arena, construct that storage
//! with `kind`, then tail-post it to the framework root with `no_wait = 1`,
//! a zero reply queue, and zero flags. The tail post status remains in `r0`.
//!
//! Deliberate deviations: none. The stock tail branch first enters the
//! sibling wrapper at `0x081d1ff4`; this port calls its already-ported root
//! getter and queued-message post target directly.

use crate::app::class_6800::framework_root_instance;
use crate::app::message_kind::{message_kind_construct, MessageKind, MESSAGE_KIND_SIZE};
use crate::app::message_kind_arena::message_kind_arena_alloc;
use crate::app::queued_message::{queued_message_post, MessageTarget};

macro_rules! framework_root_post_message_kind_body {
    ($kind:expr; $alloc:path, $construct:path, $root:path, $post:path) => {{
        let storage = unsafe { $alloc(MESSAGE_KIND_SIZE) }.cast::<MessageKind>();
        let message = unsafe { $construct(storage, $kind) };
        unsafe { $post(message.cast(), $root().cast::<MessageTarget>(), 1, 0, 0) }
    }};
}

/// framework_root_post_message_kind — original: `FUN_081d2018` @
/// **0x081d2018** (**32 bytes**, `0x081d2018..0x081d2037`; **3 unconditional
/// `bl` callers and no predicated `bl` callers**), verified from raw ARM
/// words in `work/firmware/osos.dec`.
///
/// Allocates the eight-byte [`MessageKind`] envelope, constructs it with
/// `kind`, then fire-and-forget posts it to the framework root. The raw tail
/// branch preserves [`queued_message_post`]'s status in `r0`.
///
/// # Safety
///
/// The message-kind arena, framework-root holder, and root target chain must
/// be initialized. The retail code performs no NULL checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.framework_root_post_message_kind"))]
pub unsafe extern "C" fn framework_root_post_message_kind(kind: u32) -> u32 {
    framework_root_post_message_kind_body!(
        kind;
        message_kind_arena_alloc,
        message_kind_construct,
        framework_root_instance,
        queued_message_post
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 4] = [0; 4];
    static mut ALLOC_SIZE: usize = 0;
    static mut CONSTRUCT_ARGS: (*mut MessageKind, u32) = (core::ptr::null_mut(), 0);
    static mut POST_ARGS: (*mut MessageKind, *mut MessageTarget, u32, usize, u32) =
        (core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);
    static mut POST_RESULT: u32 = 0;

    unsafe extern "C" fn recording_alloc(size: usize) -> *mut u8 {
        CALLS[0] += 1;
        ALLOC_SIZE = size;
        0x2000usize as *mut u8
    }

    unsafe extern "C" fn recording_construct(storage: *mut MessageKind, kind: u32) -> *mut MessageKind {
        CALLS[1] += 1;
        CONSTRUCT_ARGS = (storage, kind);
        0x3000usize as *mut MessageKind
    }

    unsafe extern "C" fn recording_root() -> *mut u8 {
        CALLS[2] += 1;
        0x4000usize as *mut u8
    }

    unsafe extern "C" fn recording_post(
        message: *mut MessageKind,
        target: *mut MessageTarget,
        no_wait: u32,
        reply_queue: usize,
        flags: u32,
    ) -> u32 {
        CALLS[3] += 1;
        POST_ARGS = (message, target, no_wait, reply_queue, flags);
        POST_RESULT
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CALLS = [0; 4];
            ALLOC_SIZE = 0;
            CONSTRUCT_ARGS = (core::ptr::null_mut(), 0);
            POST_ARGS = (core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);
            POST_RESULT = 0;
        }
        guard
    }

    fn invoke(kind: u32) -> u32 {
        framework_root_post_message_kind_body!(
            kind;
            recording_alloc,
            recording_construct,
            recording_root,
            recording_post
        )
    }

    #[test]
    fn constructs_and_posts_the_message_kind() {
        let guard = reset();
        unsafe {
            POST_RESULT = 0x5a;
            assert_eq!(invoke(0x6000_0004), 0x5a);
            assert_eq!(CALLS, [1, 1, 1, 1]);
            assert_eq!(ALLOC_SIZE, MESSAGE_KIND_SIZE);
            assert_eq!(CONSTRUCT_ARGS, (0x2000usize as *mut MessageKind, 0x6000_0004));
            assert_eq!(POST_ARGS, (0x3000usize as *mut MessageKind, 0x4000usize as *mut MessageTarget, 1, 0, 0));
        }
        drop(guard);
    }

    #[test]
    fn preserves_zero_and_high_bit_kind_tags() {
        let guard = reset();
        unsafe {
            POST_RESULT = u32::MAX;
            assert_eq!(invoke(0), u32::MAX);
            assert_eq!(CONSTRUCT_ARGS.1, 0);
            POST_RESULT = 0;
            assert_eq!(invoke(0x8000_0000), 0);
            assert_eq!(CONSTRUCT_ARGS.1, 0x8000_0000);
            assert_eq!(CALLS, [2, 2, 2, 2]);
        }
        drop(guard);
    }
}
