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
//! It is a pure ABI adapter into the shared arena-message poster
//! `FUN_08166d3c` @ 0x08166d3c (unported), inserting the object's own
//! message target word `+0x14` as the callee's third argument:
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
//! `this` passes through only because it occupies the register. It
//! allocates a 12-byte envelope from the current message arena
//! (`message_arena_pool` @ 0x08103400 + `fixed_block_pool_alloc(.., 0xc)`
//! @ 0x0826c0d8, both ported), builds it with
//! [`crate::app::queued_message::queued_message_construct`] (ported), and
//! posts it with [`crate::app::queued_message::queued_message_post`]
//! (ported) as fire-and-forget (`no_wait = 1`, `flags = 0`), so the
//! effective behavior of one call here is: post a queued message carrying
//! `code` and an owned copy of `bytes[0..byte_count]` to this object's
//! `+0x14` target with `reply_queue` as the reply handle.
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
//! # Deviations
//!
//! - The unported callee @ 0x08166d3c rides the [`ARENA_MESSAGE_POST`]
//!   seam: transmuted to its firmware load address on target, a
//!   documenting `panic!` on host until a test installs a recording op.
//!   The six-argument ABI (including the unread `this` in r0) is kept so
//!   the seam matches the retail register/stack layout exactly.

use core::ptr::addr_of_mut;

/// Word offset of the object's own message target: the `ldr r2, [r0,
/// #20]` the original runs unconditionally. The class constructor @
/// 0x081671f4 stores its second argument here.
pub const OWN_TARGET_OFFSET: usize = 0x14;

/// The notifier object, as far as this dispatch reads it. `+0x00..+0x14`
/// belongs to the base class (constructor 0x0811113c, unported); only the
/// target link is consumed here. The link is a `u32` wire word (like
/// [`crate::app::queued_message::PostedTaskMessage`]'s pointer fields),
/// not a pointer, so the +0x14 offset is exact on both pointer widths.
#[repr(C)]
pub struct OwnTargetNotifier {
    /// +0x00..+0x14: base-class storage, untouched here.
    pub unused_00: [u32; 5],
    /// +0x14: the destination this object's notifications are posted to.
    pub target: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(OwnTargetNotifier, target)];

/// ABI of the shared arena-message poster `FUN_08166d3c` @ 0x08166d3c:
/// `(ctx, message_code, target, bytes, byte_count, reply_queue)`. `ctx`
/// is the caller's `this` passed through in r0; the retail body never
/// reads it.
pub type ArenaMessagePost = unsafe extern "C" fn(
    ctx: *mut OwnTargetNotifier,
    message_code: u32,
    target: *mut crate::app::queued_message::MessageTarget,
    bytes: *const u8,
    byte_count: u32,
    reply_queue: usize,
);

/// RetailOS load address of the six-argument arena-message poster.
pub const ARENA_MESSAGE_POST_ADDRESS: usize = 0x0816_6d3c;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_arena_message_post(
    ctx: *mut OwnTargetNotifier,
    message_code: u32,
    target: *mut crate::app::queued_message::MessageTarget,
    bytes: *const u8,
    byte_count: u32,
    reply_queue: usize,
) {
    let post: ArenaMessagePost = unsafe { core::mem::transmute(ARENA_MESSAGE_POST_ADDRESS) };
    unsafe { post(ctx, message_code, target, bytes, byte_count, reply_queue) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_arena_message_post(
    _ctx: *mut OwnTargetNotifier,
    _message_code: u32,
    _target: *mut crate::app::queued_message::MessageTarget,
    _bytes: *const u8,
    _byte_count: u32,
    _reply_queue: usize,
) {
    panic!("own_target_notification_post requires arena-message poster 0x08166d3c")
}

/// Active boundary for the unported arena-message poster @ 0x08166d3c. On
/// the target it calls directly into retailOS; host tests replace it with
/// a recording implementation.
#[cfg(target_os = "none")]
pub static mut ARENA_MESSAGE_POST: ArenaMessagePost = retail_arena_message_post;

/// Active host boundary for the unported arena-message poster.
#[cfg(not(target_os = "none"))]
pub static mut ARENA_MESSAGE_POST: ArenaMessagePost = missing_arena_message_post;

#[inline(always)]
fn arena_message_post() -> ArenaMessagePost {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ARENA_MESSAGE_POST)) }
}

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
    let post = arena_message_post();
    unsafe {
        post(
            this,
            message_code,
            target as usize as *mut crate::app::queued_message::MessageTarget,
            bytes,
            byte_count,
            reply_queue,
        )
    };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Post {
        ctx: usize,
        message_code: u32,
        target: usize,
        bytes: usize,
        byte_count: u32,
        reply_queue: usize,
    }

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALLS: Vec<Post> = Vec::new();

    unsafe extern "C" fn recording_arena_message_post(
        ctx: *mut OwnTargetNotifier,
        message_code: u32,
        target: *mut crate::app::queued_message::MessageTarget,
        bytes: *const u8,
        byte_count: u32,
        reply_queue: usize,
    ) {
        unsafe {
            (*addr_of_mut!(CALLS)).push(Post {
                ctx: ctx as usize,
                message_code,
                target: target as usize,
                bytes: bytes as usize,
                byte_count,
                reply_queue,
            })
        };
    }

    struct SeamReset;
    impl Drop for SeamReset {
        fn drop(&mut self) {
            unsafe { core::ptr::write_volatile(addr_of_mut!(ARENA_MESSAGE_POST), missing_arena_message_post) };
            unsafe { (*addr_of_mut!(CALLS)).clear() };
        }
    }

    fn install_recorder() -> (parking_lot::MutexGuard<'static, ()>, SeamReset) {
        let guard = TEST_LOCK.lock();
        unsafe { (*addr_of_mut!(CALLS)).clear() };
        unsafe { core::ptr::write_volatile(addr_of_mut!(ARENA_MESSAGE_POST), recording_arena_message_post) };
        (guard, SeamReset)
    }

    fn notifier(target: usize) -> OwnTargetNotifier {
        OwnTargetNotifier {
            unused_00: [0xdead_beef; 5],
            target: target as u32,
        }
    }

    fn calls() -> Vec<Post> {
        unsafe { (*addr_of_mut!(CALLS)).clone() }
    }

    #[test]
    fn target_field_sits_at_word_offset_0x14() {
        assert_eq!(core::mem::offset_of!(OwnTargetNotifier, target), OWN_TARGET_OFFSET);
    }

    #[test]
    fn forwards_all_arguments_with_the_own_target_inserted_third() {
        let (_guard, _reset) = install_recorder();
        let mut this = notifier(0x089c_a674);
        let payload = [0x11u8, 0x22, 0x33, 0x44];
        unsafe {
            own_target_notification_post(
                core::ptr::addr_of_mut!(this),
                0x6380_0026,
                payload.as_ptr(),
                4,
                0x2200_1234,
            )
        };
        assert_eq!(
            calls(),
            [Post {
                ctx: core::ptr::addr_of_mut!(this) as usize,
                message_code: 0x6380_0026,
                target: 0x089c_a674,
                bytes: payload.as_ptr() as usize,
                byte_count: 4,
                reply_queue: 0x2200_1234,
            }]
        );
    }

    #[test]
    fn a_null_target_word_is_forwarded_unguarded() {
        let (_guard, _reset) = install_recorder();
        let mut this = notifier(0);
        unsafe {
            own_target_notification_post(core::ptr::addr_of_mut!(this), 0x6380_0001, core::ptr::null(), 0, 0)
        };
        let seen = calls();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].target, 0);
        assert_eq!(seen[0].bytes, 0);
        assert_eq!(seen[0].byte_count, 0);
        assert_eq!(seen[0].reply_queue, 0);
    }

    #[test]
    fn extreme_message_code_and_counts_pass_through_unchanged() {
        let (_guard, _reset) = install_recorder();
        let mut this = notifier(u32::MAX as usize);
        unsafe {
            own_target_notification_post(
                core::ptr::addr_of_mut!(this),
                u32::MAX,
                usize::MAX as *const u8,
                u32::MAX,
                usize::MAX,
            )
        };
        let seen = calls();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].target, u32::MAX as usize);
        assert_eq!(seen[0].message_code, u32::MAX);
        assert_eq!(seen[0].bytes, usize::MAX);
        assert_eq!(seen[0].byte_count, u32::MAX);
        assert_eq!(seen[0].reply_queue, usize::MAX);
    }

    #[test]
    fn reads_the_target_word_from_the_object_each_call() {
        let (_guard, _reset) = install_recorder();
        let mut this = notifier(0x1000);
        unsafe {
            own_target_notification_post(core::ptr::addr_of_mut!(this), 1, core::ptr::null(), 0, 0);
            this.target = 0x2000;
            own_target_notification_post(core::ptr::addr_of_mut!(this), 2, core::ptr::null(), 0, 0);
        }
        let seen = calls();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].target, 0x1000);
        assert_eq!(seen[1].target, 0x2000);
    }
}
