//! `arena_message_post` — original: `FUN_08166d3c` @ **0x08166d3c**
//! (**76 bytes exactly**, 0x08166d3c..0x08166d87; nineteen ARM words). The
//! next function begins at 0x08166d8c (`and r0, r1, #0xff`), so Ghidra's
//! 80-byte extent includes that sibling's first word. **Three direct plain
//! `bl` callers, zero predicated forms, no tail branches or DATA-word
//! references** — verified by decoding every ARM B/BL word in `osos.dec`.
//!
//! # Algorithm
//!
//! Obtains the current queued-message arena, allocates its 12-byte envelope,
//! constructs the envelope from `(message_code, bytes, byte_count)`, then
//! posts it to `target` as fire-and-forget (`no_wait = 1`, `flags = 0`). The
//! incoming `ctx` in r0 is never read. `reply_queue` is the sixth ABI argument
//! and is forwarded unchanged to the post operation.
//!
//! # Deliberate deviations
//!
//! The stock routine retains r0 only incidentally; Rust names it `_ctx` and
//! does not preserve the meaningless return register value from the post call.

use crate::app::message_arena::message_arena_pool;
use crate::app::queued_message::{queued_message_construct, queued_message_post, MessageTarget, QueuedMessage};
use crate::heap::fixed_block_pool::fixed_block_pool_alloc;

const QUEUED_MESSAGE_SIZE: usize = 12;

unsafe fn arena_message_post_with(
    message_code: u32,
    target: *mut MessageTarget,
    bytes: *const u8,
    byte_count: u32,
    reply_queue: usize,
    pool: unsafe extern "C" fn() -> *mut crate::heap::fixed_block_pool::FixedBlockPool,
    alloc: unsafe extern "C" fn(*mut crate::heap::fixed_block_pool::FixedBlockPool, usize) -> *mut u8,
    construct: unsafe extern "C" fn(*mut QueuedMessage, u32, *const u8, u32) -> *mut QueuedMessage,
    post: unsafe extern "C" fn(*mut QueuedMessage, *mut MessageTarget, u32, usize, u32) -> u32,
) {
    let storage = unsafe { alloc(pool(), QUEUED_MESSAGE_SIZE).cast::<QueuedMessage>() };
    let message = unsafe { construct(storage, message_code, bytes, byte_count) };
    unsafe { post(message, target, 1, reply_queue, 0) };
}

/// arena_message_post — original: `FUN_08166d3c` @ **0x08166d3c**
/// (76 bytes; three direct plain `bl` callers, zero predicated forms).
///
/// Allocates and posts a normal queued-message envelope. `ctx` is present only
/// to preserve the retail six-argument ABI and is never read by the original.
///
/// # Safety
///
/// `target` and the arena/message subsystems must satisfy the preconditions of
/// [`queued_message_post`] and [`queued_message_construct`], respectively.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn arena_message_post(
    _ctx: *mut u8,
    message_code: u32,
    target: *mut MessageTarget,
    bytes: *const u8,
    byte_count: u32,
    reply_queue: usize,
) {
    unsafe {
        arena_message_post_with(
            message_code,
            target,
            bytes,
            byte_count,
            reply_queue,
            message_arena_pool,
            fixed_block_pool_alloc,
            queued_message_construct,
            queued_message_post,
        )
    };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOC_POOL: usize = 0;
    static mut ALLOC_SIZE: usize = 0;
    static mut CONSTRUCT: (usize, u32, usize, u32) = (0, 0, 0, 0);
    static mut POST: (usize, usize, u32, usize, u32) = (0, 0, 0, 0, 0);

    unsafe extern "C" fn pool() -> *mut crate::heap::fixed_block_pool::FixedBlockPool { 0x1000 as _ }
    unsafe extern "C" fn alloc(pool: *mut crate::heap::fixed_block_pool::FixedBlockPool, size: usize) -> *mut u8 {
        unsafe { ALLOC_POOL = pool as usize; ALLOC_SIZE = size };
        0x2000 as _
    }
    unsafe extern "C" fn construct(storage: *mut QueuedMessage, code: u32, bytes: *const u8, count: u32) -> *mut QueuedMessage {
        unsafe { CONSTRUCT = (storage as usize, code, bytes as usize, count) };
        0x3000 as _
    }
    unsafe extern "C" fn post(message: *mut QueuedMessage, target: *mut MessageTarget, no_wait: u32, reply: usize, flags: u32) -> u32 {
        unsafe { POST = (message as usize, target as usize, no_wait, reply, flags) };
        0
    }

    #[test]
    fn allocates_the_twelve_byte_envelope_and_posts_a_nonempty_payload() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { arena_message_post_with(0x6380_0026, 0x4000 as _, 0x5000 as _, 4, 0x6000, pool, alloc, construct, post) };
        assert_eq!(unsafe { (ALLOC_POOL, ALLOC_SIZE) }, (0x1000, 12));
        assert_eq!(unsafe { CONSTRUCT }, (0x2000, 0x6380_0026, 0x5000, 4));
        assert_eq!(unsafe { POST }, (0x3000, 0x4000, 1, 0x6000, 0));
    }

    #[test]
    fn forwards_null_empty_payload_and_word_sized_reply_unchanged() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { arena_message_post_with(u32::MAX, 0x4000 as _, core::ptr::null(), 0, usize::MAX, pool, alloc, construct, post) };
        assert_eq!(unsafe { CONSTRUCT }, (0x2000, u32::MAX, 0, 0));
        assert_eq!(unsafe { POST }, (0x3000, 0x4000, 1, usize::MAX, 0));
    }
}
