//! `own_target_notification_post` — original: `FUN_08167028` @
//! **0x08167028** (**36 bytes exactly**, 0x08167028..0x0816704b; nine
//! instruction words, no literal pool — the next function opens with its
//! own `push {r2, r3, r4, lr}` @ 0x0816704c, so Ghidra's 36 is right).
//! **16 call sites, all plain unconditional `bl`, no predicated forms, no
//! tail `b`, no DATA-word references** — binary-verified by decoding every
//! ARM B/BL word in `work/firmware/osos.dec` and scanning for the address
//! as a data word. Ghidra's listing shows only 15 of the 16: the site @
//! 0x08166ea0 is absent from `decomp/osos.asm`.
//!
//! # Algorithm
//!
//! The notification dispatch of the notifier class constructed @
//! 0x081671f4 (vtable literal 0x08987f18, the class immediately after the
//! UI animation class): every sibling method @ 0x08166d14..0x081671e4
//! raises its `0x638000xx` notification code through this one forwarder.
//! `FUN_08166d3c` @ 0x08166d3c, now
//! [`crate::app::arena_message_post::arena_message_post`], inserting the
//! object's own message target word `+0x14` as the callee's third argument:
//!
//! ```text
//! own_target_notification_post(this, code, bytes, byte_count, reply_queue):
//!     FUN_08166d3c(this, code, this->target /* +0x14 */, bytes,
//!                  byte_count, reply_queue)
//! ```
//!
//! The stock nine words, decoded from `osos.dec`:
//!
//! ```text
//! 08167028  push {r2, r3, r4, lr}   ; 16-byte frame: 2 scratch words + r4/lr
//! 0816702c  mov  ip, r2             ; ip  = bytes (incoming r2)
//! 08167030  mov  r2, r3             ; r2  = byte_count (incoming r3)
//! 08167034  ldr  r3, [sp, #16]      ; r3  = reply_queue (incoming stack arg)
//! 08167038  strd r2, [sp]           ; callee stack args = byte_count, reply_queue
//! 0816703c  ldr  r2, [r0, #20]      ; r2  = this->target (+0x14)
//! 08167040  mov  r3, ip             ; r3  = bytes
//! 08167044  bl   0x08166d3c         ; arena-message poster
//! 08167048  pop  {r2, r3, r4, pc}
//! ```
//!
//! The callee @ 0x08166d3c (fully decoded, 76 bytes) never reads its r0 —
//! `this` passes through only because it occupies the register. It allocates
//! a 12-byte envelope from the current message arena, builds it with
//! [`crate::app::queued_message::queued_message_construct`], then posts it
//! with [`crate::app::queued_message::queued_message_post`] as
//! fire-and-forget (`no_wait = 1`, `flags = 0`). The effective behavior of
//! one call here is: post a queued message carrying `code` and an owned copy
//! of `bytes[0..byte_count]` to this object's `+0x14` target with
//! `reply_queue` as the reply handle.
//!
//! # Behavioral facts
//!
//! - **No NULL guards anywhere.** `this` is dereferenced unconditionally
//!   (`ldr r2, [r0, #20]`); a NULL `target` word is forwarded as-is and
//!   the callee chain dereferences the target before any test. The zero
//!   predicated-`bl` call-site count matches: callers never guard.
//! - The stock wrapper's `pop {r2, r3, r4, pc}` returns with r0 still
//!   holding `queued_message_post`'s status, so the post result is
//!   observable in r0 even though the C-level type is `void`. Callers
//!   ignore it; the port is typed `void` and leaves r0 as the seam call
//!   left it, exactly like the original.
//!
//! No deviations: the shared poster is now ported in
//! [`crate::app::arena_message_post`].


/// Word offset of the object's own message target.
pub const OWN_TARGET_OFFSET: usize = 0x14;

/// The notifier object, as far as this dispatch reads it.
#[repr(C)]
pub struct OwnTargetNotifier {
    pub unused_00: [u32; 5],
    pub target: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(OwnTargetNotifier, target)];

/// own_target_notification_post — original: `FUN_08167028` @ **0x08167028**
/// (36 bytes; 16 `bl` call sites, all unconditional — see the module
/// header).
///
/// Posts a notification to the object's own `+0x14` message target through
/// the shared arena-message poster @ 0x08166d3c, passing `this` through in
/// r0 and inserting the target word as the callee's third argument. The
/// poster's fire-and-forget status is left in r0 but typed away, exactly
/// like the stock `void` wrapper.
///
/// # Safety
///
/// `this` must name a live notifier object: the original dereferences
/// `this + 0x14` unconditionally, and a NULL or dangling target word is
/// forwarded to a callee chain that dereferences it before any NULL test.
/// These are the original's preconditions, not added ones.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.own_target_notification_post"))]
pub unsafe extern "C" fn own_target_notification_post(
    this: *mut OwnTargetNotifier,
    message_code: u32,
    bytes: *const u8,
    byte_count: u32,
    reply_queue: usize,
) {
    let target = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*this).target)) };
    unsafe {
        crate::app::arena_message_post::arena_message_post(
            this.cast(),
            message_code,
            target as usize as *mut crate::app::queued_message::MessageTarget,
            bytes,
            byte_count,
            reply_queue,
        )
    };
}

