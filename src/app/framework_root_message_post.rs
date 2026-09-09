//! Posts a zero-payload queued message to the Silver framework root.
//!
//! [`framework_root_post_message`] — original: `FUN_081d2408` @
//! **0x081d2408** (**44 bytes exactly**, 0x081d2408..0x081d2433; eleven
//! ARM instruction words). Ghidra's reported 76-byte extent is wrong: raw
//! bytes show the next function's `push {r3, lr}` at 0x081d2434. A
//! binary-wide decode of every ARM B/BL word in `work/firmware/osos.dec`
//! found **14 unconditional `bl` call sites**, no predicated `bl`, plus
//! eleven tail entries (nine unconditional `b`, two `bne`); there are no
//! data-word references.
//!
//! # Algorithm
//!
//! ```text
//! storage = fixed_block_pool_alloc(message_arena_pool(), 12)
//! message = queued_message_construct(storage, message_code, NULL, 0)
//! return queued_message_post(message, framework_root_instance(), 1, 0, 0)
//! ```
//!
//! The final post is a tail branch through the 28-byte sibling wrapper at
//! 0x081d1ff4, which loads the framework root from the +4 word of the global
//! holder at 0x089cc858. The Rust port invokes the already-ported root getter
//! directly and preserves the post result in `r0`; Ghidra's `void` signature
//! misses that observable return value. No other deviations.

use crate::app::class_6800::framework_root_instance;
use crate::app::message_arena::message_arena_pool;
use crate::app::queued_message::{queued_message_construct, queued_message_post, MessageTarget, QueuedMessage};
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

/// The exact `mov r1, #12` allocation request at 0x081d2414.
const QUEUED_MESSAGE_STORAGE_SIZE: usize = 12;

macro_rules! framework_root_post_message_body {
    ($message_code:expr; $pool:path, $alloc:path, $construct:path, $root:path, $post:path) => {{
        let storage = unsafe { $alloc($pool(), QUEUED_MESSAGE_STORAGE_SIZE) }.cast::<QueuedMessage>();
        let message = unsafe {
            $construct(
                storage,
                $message_code,
                core::ptr::null(),
                0,
            )
        };
        unsafe { $post(message, $root().cast::<MessageTarget>(), 1, 0, 0) }
    }};
}

/// framework_root_post_message — original: `FUN_081d2408` @ **0x081d2408**
/// (**44 bytes**, 0x081d2408..0x081d2433; **14 unconditional `bl` call sites,
/// no predicated `bl`, and 11 tail-branch entries**), verified by decoding
/// every ARM B/BL word in `work/firmware/osos.dec`.
///
/// Allocates the standard 12-byte queued-message envelope, constructs its
/// nested zero-length payload from `message_code`, and fire-and-forget posts
/// it to the framework root. The raw tail branch preserves
/// [`queued_message_post`]'s status in `r0`; this port returns that status
/// rather than repeating Ghidra's incorrect `void` declaration.
///
/// # Safety
///
/// The message arena, queued-message payload constructor, framework-root
/// holder, and root's target chain must all be initialized. The retail code
/// has no NULL guards on any of those paths.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.framework_root_post_message"))]
pub unsafe extern "C" fn framework_root_post_message(message_code: u32) -> u32 {
    framework_root_post_message_body!(
        message_code;
        message_arena_pool,
        fixed_block_pool_alloc,
        queued_message_construct,
        framework_root_instance,
        queued_message_post
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::fixed_block_pool::FixedBlockPool;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 5] = [0; 5];
    static mut ALLOC_POOL: *mut FixedBlockPool = core::ptr::null_mut();
    static mut ALLOC_SIZE: usize = 0;
    static mut CONSTRUCT_ARGS: (*mut QueuedMessage, u32, *const u8, u32) =
        (core::ptr::null_mut(), 0, core::ptr::null(), 0);
    static mut POST_ARGS: (*mut QueuedMessage, *mut MessageTarget, u32, usize, u32) =
        (core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);
    static mut POST_RESULT: u32 = 0;

    unsafe extern "C" fn recording_pool() -> *mut FixedBlockPool {
        CALLS[0] += 1;
        0x1000usize as *mut FixedBlockPool
    }

    unsafe extern "C" fn recording_alloc(pool: *mut FixedBlockPool, size: usize) -> *mut u8 {
        CALLS[1] += 1;
        ALLOC_POOL = pool;
        ALLOC_SIZE = size;
        0x2000usize as *mut u8
    }

    unsafe extern "C" fn recording_construct(
        storage: *mut QueuedMessage,
        message_code: u32,
        bytes: *const u8,
        byte_count: u32,
    ) -> *mut QueuedMessage {
        CALLS[2] += 1;
        CONSTRUCT_ARGS = (storage, message_code, bytes, byte_count);
        0x3000usize as *mut QueuedMessage
    }

    unsafe extern "C" fn recording_root() -> *mut u8 {
        CALLS[3] += 1;
        0x4000usize as *mut u8
    }

    unsafe extern "C" fn recording_post(
        message: *mut QueuedMessage,
        target: *mut MessageTarget,
        no_wait: u32,
        reply_queue: usize,
        flags: u32,
    ) -> u32 {
        CALLS[4] += 1;
        POST_ARGS = (message, target, no_wait, reply_queue, flags);
        POST_RESULT
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CALLS = [0; 5];
            ALLOC_POOL = core::ptr::null_mut();
            ALLOC_SIZE = 0;
            CONSTRUCT_ARGS = (core::ptr::null_mut(), 0, core::ptr::null(), 0);
            POST_ARGS = (core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);
            POST_RESULT = 0;
        }
        guard
    }

    fn invoke(message_code: u32) -> u32 {
        framework_root_post_message_body!(
            message_code;
            recording_pool,
            recording_alloc,
            recording_construct,
            recording_root,
            recording_post
        )
    }

    #[test]
    fn constructs_and_posts_the_zero_payload_envelope() {
        let guard = reset();
        unsafe {
            POST_RESULT = 0x5a;
            assert_eq!(invoke(0x6000_0004), 0x5a, "the tail post status remains observable");
            assert_eq!(CALLS, [1, 1, 1, 1, 1], "all four stages run once");
            assert_eq!(ALLOC_POOL, 0x1000usize as *mut FixedBlockPool);
            assert_eq!(ALLOC_SIZE, 12, "the stock allocation immediate");
            assert_eq!(CONSTRUCT_ARGS.0, 0x2000usize as *mut QueuedMessage);
            assert_eq!(CONSTRUCT_ARGS.1, 0x6000_0004, "message code is unchanged");
            assert!(CONSTRUCT_ARGS.2.is_null(), "zero payload uses NULL bytes");
            assert_eq!(CONSTRUCT_ARGS.3, 0, "zero payload length");
            assert_eq!(POST_ARGS, (0x3000usize as *mut QueuedMessage, 0x4000usize as *mut MessageTarget, 1, 0, 0));
        }
        drop(guard);
    }

    #[test]
    fn preserves_zero_and_high_bit_message_codes() {
        let guard = reset();
        unsafe {
            POST_RESULT = u32::MAX;
            assert_eq!(invoke(0), u32::MAX);
            assert_eq!(CONSTRUCT_ARGS.1, 0, "zero is not a sentinel or a guard");

            assert_eq!(invoke(0xdead_beef), u32::MAX);
            assert_eq!(CONSTRUCT_ARGS.1, 0xdead_beef, "the high-bit code is forwarded verbatim");
            assert_eq!(CALLS, [2, 2, 2, 2, 2], "there is no code-dependent branch");
        }
        drop(guard);
    }
}
