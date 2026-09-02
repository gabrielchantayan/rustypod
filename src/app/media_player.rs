//! TPodMediaPlayer methods: the kind-only notification poster.
//!
//! Ports:
//!
//! - [`media_player_post_kind`] — `FUN_0817cab0` @ 0x0817cab0
//!   (64 bytes exactly, 0x0817cab0..0x0817caf0; the next function opens
//!   at 0x0817caf0 with `ldrb r0, [r0, #0x93d]`, so Ghidra's 64 is the
//!   true extent; **23 `bl` call sites, 0 predicated, 0 tail branches**,
//!   binary-verified by decoding every B/BL word in osos.dec — Ghidra's
//!   listing shows only 22: the site @ 0x08179db4 is absent from
//!   decomp/osos.asm entirely; no DATA word holds the address, so it is
//!   never dispatched virtually).
//!
//! # Algorithm
//!
//! Decoded from the raw ARM at 0x0817cab0:
//!
//! ```text
//! push {r3, r4, r5, lr}        ; r3 is the flags stack slot
//! mov  r5, r1                  ; kind
//! mov  r4, r0                  ; this (the TPodMediaPlayer)
//! bl   0x082669e4              ; message_kind_arena_pool (ported)
//! mov  r1, #8                  ; sizeof(MessageKind)
//! bl   0x0826c0d8              ; fixed_block_pool_alloc (ported)
//! mov  r1, r5                  ; kind
//! bl   0x08266a48              ; message_kind_construct (ported)
//! mov  r3, #0
//! str  r3, [sp]                ; flags = 0 (the poster's 5th arg)
//! ldr  r1, [r4, #0x9ac]        ; this->message_target
//! mov  r2, #1                  ; no_wait
//! bl   0x08110fdc              ; queued_message_post (ported)
//! cmp  r0, #0
//! movne r0, #1                 ; collapse to 0/1
//! pop  {r3, r4, r5, pc}
//! ```
//!
//! The player's fire-and-forget notification: pop an 8-byte block off
//! the MessageKind arena (the pool's `block_size == 8` exact-equality
//! test always matches, so the `operator new` fallback only fires when
//! the arena is exhausted), construct a bare kind-tagged message in it —
//! no payload, no derived vtable, the base message vtable 0x089a3788 is
//! the final one — and post it to the player's own message target at
//! +0x9ac with `no_wait = 1`, `reply_queue = 0` (the poster substitutes
//! the current task's queue) and `flags = 0`. Returns 1 when the poster
//! accepted it, 0 otherwise — in which case the poster has already
//! released the envelope through its vtable +0x04 slot.
//!
//! There is **no NULL guard** on the allocation: an exhausted arena
//! whose `operator new` fallback also fails hands NULL to
//! `message_kind_construct`, which stores through it. Reproduced —
//! adding a guard would change the failure edge.
//!
//! # Context
//!
//! `this` is the TPodMediaPlayer, the 0xA6C-byte singleton
//! [`crate::app::singletons::media_player_get`] hands out: every one of
//! the 23 call sites sits inside a media-player method (the callers use
//! `param_1`'s vtable at +0x14, the same +0x14 interface
//! [`crate::app::singletons::media_player_interface_get`] returns), and
//! all but one pass a pool-literal kind tag. The observed literals are
//! the contiguous cluster 0x80008, 0x8000a, 0x8000b, 0x8000c, 0x8000d,
//! 0x8000e, 0x8000f (0x80009 presumably also exists); one site
//! (0x0817c9a0) forwards a computed value. Paired with the virtual call
//! on the +0x14 interface the callers make right after, these are
//! player state-change notifications.
//!
//! # Deviations
//!
//! - All four callees are ported and are the wired defaults of
//!   [`MEDIA_PLAYER_POST_OPS`]; the slots remain replaceable for
//!   host-side recording, the queued_message.rs precedent — a direct
//!   call is untestable on host because the arena accessor's host
//!   constructor default panics by design and the poster's failure edge
//!   dispatches the release through the firmware vtable word
//!   0x089a3788, unreadable on host.
//! - The message-target word is read through a `#[repr(C)]` struct
//!   field kept as a raw `u32` word: a host pointer at logical offset
//!   0x9ac would be padded to 0x9b0, so the field is stored and loaded
//!   as the target's 4-byte word exactly as the `ldr r1, [r4, #0x9ac]`
//!   reads it.

use crate::app::message_kind::{message_kind_construct, MessageKind, MESSAGE_KIND_SIZE};
use crate::app::message_kind_arena::message_kind_arena_pool;
use crate::app::queued_message::{queued_message_post, MessageTarget, QueuedMessage};
use crate::heap::fixed_block_pool::{fixed_block_pool_alloc, FixedBlockPool};

/// `ldr r1, [r4, #0x9ac]` @ 0x0817cad8 — the offset of the player's
/// message-target word in the 0xA6C-byte TPodMediaPlayer object
/// ([`crate::app::singletons::MEDIA_PLAYER_SIZE`]).
pub const MEDIA_PLAYER_TARGET_OFFSET: usize = 0x9ac;

/// `mov r2, #1` @ 0x0817cae0 — the post is always fire-and-forget.
const NO_WAIT: u32 = 1;

/// The slice of the TPodMediaPlayer object this method touches. Only
/// the prefix through the +0x9ac message-target word is modelled; the
/// object runs on to +0xA6C.
#[repr(C)]
pub struct MediaPlayer {
    /// +0x000..+0x9ac: untouched here (the root subobject, the +0x14
    /// interface vtable, and the rest of the player's state).
    pub unused_000: [u32; MEDIA_PLAYER_TARGET_OFFSET / 4],
    /// +0x9ac: the player's own message target, the destination every
    /// kind-only notification is posted to. A raw target word — see the
    /// module header's deviation.
    pub message_target: u32,
}

const _: [u8; MEDIA_PLAYER_TARGET_OFFSET] = [0; core::mem::offset_of!(MediaPlayer, message_target)];
const _: [u8; MEDIA_PLAYER_TARGET_OFFSET + 4] = [0; core::mem::size_of::<MediaPlayer>()];

/// The four callees, in call order. Every one is ported; the slots are
/// the wired ports and stay replaceable for host-side recording (see
/// the module header's deviation).
#[derive(Clone, Copy)]
pub struct MediaPlayerPostOps {
    /// `FUN_082669e4()` @ 0x082669e4 — the MessageKind arena's
    /// singleton pool accessor.
    pub pool: unsafe extern "C" fn() -> *mut FixedBlockPool,
    /// `FUN_0826c0d8(pool, 8)` @ 0x0826c0d8 — pops one 8-byte block.
    pub alloc: unsafe extern "C" fn(pool: *mut FixedBlockPool, size: usize) -> *mut u8,
    /// `FUN_08266a48(storage, kind)` @ 0x08266a48 — the base
    /// constructor; not an allocator.
    pub construct: unsafe extern "C" fn(storage: *mut MessageKind, kind: u32) -> *mut MessageKind,
    /// `FUN_08110fdc(message, target, 1, 0, 0)` @ 0x08110fdc — the
    /// poster; takes ownership of the envelope on every path.
    pub post: unsafe extern "C" fn(
        message: *mut QueuedMessage,
        target: *mut MessageTarget,
        no_wait: u32,
        reply_queue: usize,
        flags: u32,
    ) -> u32,
}

/// The wired defaults: the four real ports.
pub const DEFAULT_MEDIA_PLAYER_POST_OPS: MediaPlayerPostOps = MediaPlayerPostOps {
    pool: message_kind_arena_pool,
    alloc: fixed_block_pool_alloc,
    construct: message_kind_construct,
    post: queued_message_post,
};

/// The active callee set. Host tests install recording mocks.
pub static mut MEDIA_PLAYER_POST_OPS: MediaPlayerPostOps = DEFAULT_MEDIA_PLAYER_POST_OPS;

/// Reads the callee set. Volatile so a build in which nothing rewrites
/// the slots cannot constant-fold the defaults in and delete the
/// dispatch (house rule, see stdio/semihost.rs).
#[inline(always)]
unsafe fn ops() -> MediaPlayerPostOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(MEDIA_PLAYER_POST_OPS)) }
}

/// media_player_post_kind — original: `FUN_0817cab0` @ 0x0817cab0
/// (64 bytes; **23 `bl` call sites**, binary-verified).
///
/// Posts a bare kind-tagged message — no payload — to the player's own
/// message target at +0x9ac and returns whether the poster accepted it
/// (the original's `cmp r0, #0; movne r0, #1`: 1 for any non-zero
/// poster result, 0 otherwise). See the module header for the full
/// instruction sequence.
///
/// # Safety
///
/// `this` must be the live TPodMediaPlayer object (or at least cover
/// the +0x9ac target word); the target chain under it is dereferenced
/// unguarded by the poster, the original's precondition. A failed
/// arena allocation is **not** NULL-checked, exactly as in the
/// original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_post_kind(this: *mut MediaPlayer, kind: u32) -> u32 {
    let ops = ops();
    let storage = unsafe { (ops.alloc)((ops.pool)(), MESSAGE_KIND_SIZE) };
    let message = unsafe { (ops.construct)(storage.cast::<MessageKind>(), kind) };
    let target = unsafe { (*this).message_target } as usize as *mut MessageTarget;
    let posted = unsafe { (ops.post)(message.cast::<QueuedMessage>(), target, NO_WAIT, 0, 0) };
    if posted != 0 { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes swaps of [`MEDIA_PLAYER_POST_OPS`].
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// What the recording mocks saw, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Call {
        Pool,
        Alloc(usize, usize),
        Construct(usize, u32),
        Post(usize, usize, u32, usize, u32),
    }

    static mut CALLS: std::vec::Vec<Call> = std::vec::Vec::new();
    static mut POOL_RESULT: *mut FixedBlockPool = ptr::null_mut();
    static mut ALLOC_RESULT: *mut u8 = ptr::null_mut();
    static mut CONSTRUCT_RESULT: *mut MessageKind = ptr::null_mut();
    static mut POST_RESULT: u32 = 0;

    unsafe extern "C" fn recording_pool() -> *mut FixedBlockPool {
        unsafe {
            (*ptr::addr_of_mut!(CALLS)).push(Call::Pool);
            POOL_RESULT
        }
    }

    unsafe extern "C" fn recording_alloc(
        pool: *mut FixedBlockPool,
        size: usize,
    ) -> *mut u8 {
        unsafe {
            (*ptr::addr_of_mut!(CALLS)).push(Call::Alloc(pool as usize, size));
            ALLOC_RESULT
        }
    }

    unsafe extern "C" fn recording_construct(
        storage: *mut MessageKind,
        kind: u32,
    ) -> *mut MessageKind {
        unsafe {
            (*ptr::addr_of_mut!(CALLS)).push(Call::Construct(storage as usize, kind));
            CONSTRUCT_RESULT
        }
    }

    unsafe extern "C" fn recording_post(
        message: *mut QueuedMessage,
        target: *mut MessageTarget,
        no_wait: u32,
        reply_queue: usize,
        flags: u32,
    ) -> u32 {
        unsafe {
            (*ptr::addr_of_mut!(CALLS)).push(Call::Post(
                message as usize,
                target as usize,
                no_wait,
                reply_queue,
                flags,
            ));
            POST_RESULT
        }
    }

    fn install_mocks() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            MEDIA_PLAYER_POST_OPS = MediaPlayerPostOps {
                pool: recording_pool,
                alloc: recording_alloc,
                construct: recording_construct,
                post: recording_post,
            };
            (*ptr::addr_of_mut!(CALLS)).clear();
            POST_RESULT = 0;
        }
        guard
    }

    fn restore_mocks(guard: MutexGuard<'static, ()>) {
        unsafe { MEDIA_PLAYER_POST_OPS = DEFAULT_MEDIA_PLAYER_POST_OPS };
        drop(guard);
    }

    fn calls() -> std::vec::Vec<Call> {
        unsafe { (*ptr::addr_of!(CALLS)).clone() }
    }

    /// Sentinel target word planted at +0x9ac. Never dereferenced: the
    /// recording post only records it.
    const TARGET_WORD: u32 = 0x089c_d010;

    fn player_with_target(target: u32) -> MediaPlayer {
        MediaPlayer { unused_000: [0; MEDIA_PLAYER_TARGET_OFFSET / 4], message_target: target }
    }

    #[test]
    fn routes_alloc_construct_post_in_order_and_collapses_to_one() {
        let guard = install_mocks();
        let mut player = player_with_target(TARGET_WORD);
        unsafe {
            POOL_RESULT = 0xA11E_0000usize as *mut FixedBlockPool;
            ALLOC_RESULT = 0xA11E_1000usize as *mut u8;
            CONSTRUCT_RESULT = 0xA11E_2000usize as *mut MessageKind;
            POST_RESULT = 7;

            let ret = media_player_post_kind(&mut player, 0x8000b);

            assert_eq!(ret, 1, "any non-zero poster result collapses to 1");
            assert_eq!(
                calls(),
                std::vec![
                    Call::Pool,
                    Call::Alloc(0xA11E_0000, MESSAGE_KIND_SIZE),
                    Call::Construct(0xA11E_1000, 0x8000b),
                    Call::Post(0xA11E_2000, TARGET_WORD as usize, 1, 0, 0),
                ],
                "pool -> alloc(pool, 8) -> construct(block, kind) -> post(message, target, 1, 0, 0)"
            );
        }
        restore_mocks(guard);
    }

    #[test]
    fn returns_zero_when_the_poster_rejects() {
        let guard = install_mocks();
        let mut player = player_with_target(TARGET_WORD);
        unsafe {
            ALLOC_RESULT = 0xA11E_1000usize as *mut u8;
            CONSTRUCT_RESULT = 0xA11E_2000usize as *mut MessageKind;
            POST_RESULT = 0;

            let ret = media_player_post_kind(&mut player, 0x80008);

            assert_eq!(ret, 0, "the poster's 0 passes the cmp unchanged");
            assert_eq!(calls().len(), 4, "the post is still attempted");
        }
        restore_mocks(guard);
    }

    #[test]
    fn reads_the_target_word_from_exactly_0x9ac() {
        let guard = install_mocks();
        // Two players whose words differ everywhere except +0x9ac would
        // catch an off-by-one-field read; here one poisoned neighbour on
        // each side does the same job through the struct layout assert
        // and the planted word.
        let mut player = player_with_target(TARGET_WORD);
        player.unused_000[0] = 0xdead_beef;
        player.unused_000[MEDIA_PLAYER_TARGET_OFFSET / 4 - 1] = 0xdead_beef;
        unsafe {
            ALLOC_RESULT = 0xA11E_1000usize as *mut u8;
            CONSTRUCT_RESULT = 0xA11E_2000usize as *mut MessageKind;
            POST_RESULT = 1;

            media_player_post_kind(&mut player, 0);

            match calls()[3] {
                Call::Post(_, target, _, _, _) => {
                    assert_eq!(target, TARGET_WORD as usize, "r1 is [r4, #0x9ac], not a neighbour")
                }
                other => panic!("expected the post call, saw {other:?}"),
            }
        }
        restore_mocks(guard);
    }

    #[test]
    fn forwards_every_observed_kind_tag_verbatim() {
        let guard = install_mocks();
        let mut player = player_with_target(TARGET_WORD);
        unsafe {
            ALLOC_RESULT = 0xA11E_1000usize as *mut u8;
            CONSTRUCT_RESULT = 0xA11E_2000usize as *mut MessageKind;
            POST_RESULT = 1;

            // The pool literals decoded at the call sites, plus the one
            // computed-value site's stand-in.
            for kind in [0x80008u32, 0x8000a, 0x8000b, 0x8000c, 0x8000d, 0x8000e, 0x8000f, 0x12345] {
                media_player_post_kind(&mut player, kind);
            }

            let kinds: std::vec::Vec<u32> = calls()
                .iter()
                .filter_map(|c| match c {
                    Call::Construct(_, kind) => Some(*kind),
                    _ => None,
                })
                .collect();
            assert_eq!(
                kinds,
                std::vec![0x80008, 0x8000a, 0x8000b, 0x8000c, 0x8000d, 0x8000e, 0x8000f, 0x12345],
                "r1 passes through the alloc call untouched into the constructor"
            );
        }
        restore_mocks(guard);
    }

    #[test]
    fn a_failed_allocation_is_constructed_through_null_unguarded() {
        let guard = install_mocks();
        let mut player = player_with_target(TARGET_WORD);
        unsafe {
            ALLOC_RESULT = ptr::null_mut();
            CONSTRUCT_RESULT = ptr::null_mut();
            POST_RESULT = 0;

            media_player_post_kind(&mut player, 0x8000f);

            assert_eq!(
                calls()[2..],
                std::vec![
                    Call::Construct(0, 0x8000f),
                    Call::Post(0, TARGET_WORD as usize, 1, 0, 0),
                ],
                "no NULL guard: NULL reaches the base constructor and the poster verbatim"
            );
        }
        restore_mocks(guard);
    }
}
