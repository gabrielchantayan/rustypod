//! `queued_message_create_and_post` — original: `FUN_0814b038` @
//! `0x0814b038` (80 bytes exactly, `0x0814b038..0x0814b088`; the next
//! separately linked function begins with `push {r3,r4,r5,lr}` at
//! `0x0814b088`).
//!
//! Five direct `bl` callers reach this wrapper. Its body has three plain
//! `bl` instructions and one predicated `blne`; raw ARM decoded from
//! `osos.dec` is the extent and call-count authority.
//!
//! # Algorithm
//!
//! Allocate a 12-byte queued-message envelope from the message arena,
//! construct it from the message code, byte count, and byte pointer, then
//! post it fire-and-forget to `target` with a zero reply queue and the
//! caller's stack-passed flags word. The `blne` makes the whole allocation /
//! construction / post sequence a no-op when allocation returns NULL.
//!
//! Deliberate deviations: none. Rust calls the already ported helpers directly;
//! the stock function discards the post status, so this port returns `()` too.

use crate::app::message_arena::message_arena_pool;
use crate::app::queued_message::{queued_message_construct, queued_message_post, MessageTarget, QueuedMessage};
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;
#[cfg(test)]
use crate::heap::fixed_block_pool::FixedBlockPool;

const QUEUED_MESSAGE_STORAGE_SIZE: usize = 12;

macro_rules! queued_message_create_and_post_body {
    ($target:expr, $message_code:expr, $byte_count:expr, $bytes:expr, $flags:expr;
     $pool:path, $alloc:path, $construct:path, $post:path) => {{
        let storage = unsafe { $alloc($pool(), QUEUED_MESSAGE_STORAGE_SIZE) };
        if !storage.is_null() {
            let message = unsafe {
                $construct(
                    storage.cast::<QueuedMessage>(),
                    $message_code,
                    $bytes,
                    $byte_count,
                )
            };
            unsafe { $post(message, $target, 1, 0, $flags) };
        }
    }};
}

/// Creates a queued-message envelope and fire-and-forget posts it to `target`.
///
/// The raw ABI orders the payload arguments as `byte_count` in `r2` and
/// `bytes` in `r3`; the wrapper swaps them for `queued_message_construct`'s
/// `(bytes, byte_count)` ABI before its call at `0x0814b068`.
///
/// # Safety
///
/// `target` must satisfy [`queued_message_post`]'s target-chain precondition.
/// When allocation succeeds, the message arena and payload-constructor seam
/// must be initialized. These are the stock code's unguarded requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queued_message_create_and_post(
    target: *mut MessageTarget,
    message_code: u32,
    byte_count: u32,
    bytes: *const u8,
    flags: u32,
) {
    queued_message_create_and_post_body!(
        target, message_code, byte_count, bytes, flags;
        message_arena_pool,
        fixed_block_pool_alloc,
        queued_message_construct,
        queued_message_post
    );
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 4] = [0; 4];
    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut CONSTRUCT_ARGS: (*mut QueuedMessage, u32, *const u8, u32) =
        (core::ptr::null_mut(), 0, core::ptr::null(), 0);
    static mut POST_ARGS: (*mut QueuedMessage, *mut MessageTarget, u32, usize, u32) =
        (core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);

    unsafe extern "C" fn recording_pool() -> *mut FixedBlockPool {
        CALLS[0] += 1;
        0x1000usize as *mut FixedBlockPool
    }

    unsafe extern "C" fn recording_alloc(pool: *mut FixedBlockPool, size: usize) -> *mut u8 {
        CALLS[1] += 1;
        assert_eq!(pool, 0x1000usize as *mut FixedBlockPool);
        assert_eq!(size, QUEUED_MESSAGE_STORAGE_SIZE);
        ALLOC_RESULT
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

    unsafe extern "C" fn recording_post(
        message: *mut QueuedMessage,
        target: *mut MessageTarget,
        no_wait: u32,
        reply_queue: usize,
        flags: u32,
    ) -> u32 {
        CALLS[3] += 1;
        POST_ARGS = (message, target, no_wait, reply_queue, flags);
        0
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CALLS = [0; 4];
            ALLOC_RESULT = core::ptr::null_mut();
            CONSTRUCT_ARGS = (core::ptr::null_mut(), 0, core::ptr::null(), 0);
            POST_ARGS = (core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);
        }
        guard
    }

    fn invoke(target: *mut MessageTarget, code: u32, count: u32, bytes: *const u8, flags: u32) {
        queued_message_create_and_post_body!(
            target, code, count, bytes, flags;
            recording_pool, recording_alloc, recording_construct, recording_post
        );
    }

    #[test]
    fn swaps_the_raw_payload_register_order_and_posts_with_fixed_arguments() {
        let guard = reset();
        let bytes = [0xa5u8, 0x5a];
        unsafe {
            ALLOC_RESULT = 0x2000usize as *mut u8;
            invoke(0x4000usize as *mut MessageTarget, 0xdead_beef, 2, bytes.as_ptr(), 0x8000_0001);
            assert_eq!(CALLS, [1, 1, 1, 1]);
            assert_eq!(CONSTRUCT_ARGS, (0x2000usize as *mut QueuedMessage, 0xdead_beef, bytes.as_ptr(), 2));
            assert_eq!(POST_ARGS, (0x3000usize as *mut QueuedMessage, 0x4000usize as *mut MessageTarget, 1, 0, 0x8000_0001));
        }
        drop(guard);
    }

    #[test]
    fn null_allocation_skips_construction_and_posting() {
        let guard = reset();
        invoke(core::ptr::null_mut(), 0, 0, core::ptr::null(), 0);
        unsafe {
            assert_eq!(CALLS, [1, 1, 0, 0]);
        }
        drop(guard);
    }
}
