//! `queue_refresh_and_match_kind_two` — original: `FUN_08240a14` @
//! `0x08240a14` (36 bytes; three inbound plain `bl` callers, zero predicated
//! inbound `bl` forms, one plain outbound `bl`, zero predicated outbound `bl`
//! forms, and one tail `b`).
//!
//! Raw `osos.dec` establishes the exact extent `0x08240a14..0x08240a38`:
//! `push {r4,lr}` starts this wrapper and the next `push` at `0x08240a38`
//! starts a distinct function. It refreshes the queue-match state through
//! `FUN_082419b0`, then tail-dispatches kind 2 to `queue_match_and_promote`
//! (`FUN_08243778`) with the context's words +0x44 and +0x40 and its +0x6c
//! subobject.
//!
//! # Deliberate deviations
//!
//! `FUN_082419b0` has no recovered semantic identity or port. Device builds
//! call its verified retail address; host tests replace both fixed calls with
//! recording seams. The device implementation uses literal veneers because a
//! relocated payload cannot retain the original PC-relative call encodings.

#[cfg(not(target_arch = "arm"))]
use core::ptr;

pub type RefreshQueueMatchState = unsafe extern "C" fn(*mut u32);
pub type MatchQueueKindTwo = unsafe extern "C" fn(*mut u32, u32, u32, *mut u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_refresh_queue_match_state(_context: *mut u32) {}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_match_queue_kind_two(_queue: *mut u32, _kind: u32, _value: u32, _miss_context: *mut u32) -> u32 { 0 }

#[cfg(not(target_arch = "arm"))]
pub static mut REFRESH_QUEUE_MATCH_STATE: RefreshQueueMatchState = missing_refresh_queue_match_state;
#[cfg(not(target_arch = "arm"))]
pub static mut MATCH_QUEUE_KIND_TWO: MatchQueueKindTwo = missing_match_queue_kind_two;

#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn queue_refresh_and_match_kind_two(context: *mut u32) -> u32 {
    unsafe {
        ptr::read_volatile(ptr::addr_of!(REFRESH_QUEUE_MATCH_STATE))(context);
        let queue = context.add(17).read() as usize as *mut u32;
        let value = context.add(16).read();
        ptr::read_volatile(ptr::addr_of!(MATCH_QUEUE_KIND_TWO))(queue, 2, value, context.add(27))
    }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl queue_refresh_and_match_kind_two
    .type queue_refresh_and_match_kind_two, %function
queue_refresh_and_match_kind_two:
    push    {{r4, lr}}
    mov     r4, r0
    ldr     r12, 1f
    blx     r12
    ldr     r0, [r4, #0x44]
    ldr     r2, [r4, #0x40]
    add     r3, r4, #0x6c
    mov     r1, #2
    pop     {{r4, lr}}
    ldr     pc, 2f
1:  .word   0x082419b0
2:  .word   0x08243778
    .size queue_refresh_and_match_kind_two, . - queue_refresh_and_match_kind_two
"#
);

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x100;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::QUEUE_REFRESH_AND_MATCH_KIND_TWO, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static mut REFRESHED: *mut u32 = ptr::null_mut();
    static mut MATCH_ARGS: (*mut u32, u32, u32, *mut u32) = (ptr::null_mut(), 0, 0, ptr::null_mut());

    unsafe extern "C" fn record_refresh(context: *mut u32) { unsafe { REFRESHED = context }; }
    unsafe extern "C" fn record_match(queue: *mut u32, kind: u32, value: u32, miss_context: *mut u32) -> u32 {
        unsafe { MATCH_ARGS = (queue, kind, value, miss_context) };
        0xcafe_babe
    }

    struct Restore(RefreshQueueMatchState, MatchQueueKindTwo);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { REFRESH_QUEUE_MATCH_STATE = self.0; MATCH_QUEUE_KIND_TWO = self.1; }
        }
    }

    #[test]
    fn refreshes_then_forwards_kind_two_fields_and_tail_result() {
        let _lock = LOCK.lock();
        let Some(address) = *FIXTURE else { assert!(note_missing_u32_fixture("util/queue_refresh_and_match_kind_two")); return; };
        let context = address as *mut u32;
        unsafe {
            context.cast::<u8>().write_bytes(0, FIXTURE_LEN);
            let queue = context.add(48);
            context.add(16).write(0x1234_5678);
            context.add(17).write(queue as usize as u32);
            let previous = (REFRESH_QUEUE_MATCH_STATE, MATCH_QUEUE_KIND_TWO);
            REFRESH_QUEUE_MATCH_STATE = record_refresh;
            MATCH_QUEUE_KIND_TWO = record_match;
            REFRESHED = ptr::null_mut();
            MATCH_ARGS = (ptr::null_mut(), 0, 0, ptr::null_mut());
            let _restore = Restore(previous.0, previous.1);
            assert_eq!(queue_refresh_and_match_kind_two(context), 0xcafe_babe);
            assert_eq!(REFRESHED, context);
            assert_eq!(MATCH_ARGS, (queue, 2, 0x1234_5678, context.add(27)));
        }
    }
}
