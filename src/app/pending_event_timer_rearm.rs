//! `pending_event_timer_rearm` — original: `FUN_0813957c` @ 0x0813957c
//! (124 bytes, 0x0813957c..0x081395f8).
//!
//! Raw `osos.dec` A32 decoding establishes the extent: `push {r0-r6,lr}`
//! opens at 0x0813957c, `pop {r4-r6,pc}` ends at 0x081395f4, and the next
//! independently linked function opens at 0x081395f8. The body has nine
//! unconditional plain `bl` instructions and one dynamic `blx` through the
//! clock vtable; no predicated `bl` instructions. Three incoming calls are
//! unconditional plain `bl`; no predicated incoming calls.
//!
//! Poll the IAP-thread timer slot held at `session+0x2c8`. If the pending
//! event live-list head (`session+0x04`) exists, read the clock through its
//! vtable's +0x0c slot, convert the `{sec,nsec}` pair to milliseconds, set the
//! slot deadline to `head.deadline_ms - now_ms`, then wait for that slot. It
//! always returns zero.
//!
//! # Deliberate deviations
//!
//! The clock's vtable slot is a runtime-installed mid-function address, not a
//! named ROM callee. Target builds re-read and call it exactly as retailOS;
//! host tests inject a clock reader through the private helper.

use core::ffi::c_void;

use super::iap_incoming_process_thread::{
    iap_incoming_process_thread_instance, iap_incoming_process_thread_set_slot_deadline,
    iap_incoming_process_thread_slot_poll, iap_incoming_process_thread_slot_wait,
};
use super::pending_event_take::PendingEventNode;
use crate::cxx::clock_source_construct::clock_source_construct;
use crate::cxx::clock_source_destroy::clock_source_destroy;
use crate::fp::fp_misc::timespec_to_milliseconds;

const CLOCK_OBJECT_LEN: usize = 8;
const HEAD_OFFSET: usize = 0x04;
const TIMER_SLOT_OFFSET: usize = 0x2c8;

type ClockRead = unsafe extern "C" fn(*mut u8, *mut i32);
type ThreadInstance = unsafe extern "C" fn() -> *mut u8;
type SlotPoll = unsafe extern "C" fn(*mut u8, u32) -> u32;
type SetSlotDeadline = unsafe extern "C" fn(*mut u8, u32, i32) -> i32;
type SlotWait = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_clock_read_time(clock: *mut u8, ts_out: *mut i32) {
    let vtable = (clock as *const u32).read_volatile() as usize;
    let slot = (vtable as *const u32).add(3).read_volatile() as usize;
    let read_time: ClockRead = core::mem::transmute(slot);
    read_time(clock, ts_out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_clock_read_time(_clock: *mut u8, ts_out: *mut i32) {
    ts_out.write(0);
    ts_out.add(1).write(0);
}

#[inline(always)]
unsafe fn pending_event_timer_rearm_with_ops(
    this: *mut u8,
    clock_read: ClockRead,
    thread_instance: ThreadInstance,
    slot_poll: SlotPoll,
    set_slot_deadline: SetSlotDeadline,
    slot_wait: SlotWait,
) -> u32 {
    let slot = (this.add(TIMER_SLOT_OFFSET) as *const u32).read();
    slot_poll(thread_instance(), slot);

    let node = (this.add(HEAD_OFFSET) as *const u32).read() as usize as *mut PendingEventNode;
    if !node.is_null() {
        let mut clock = [0u8; CLOCK_OBJECT_LEN];
        clock_source_construct(clock.as_mut_ptr());
        let mut timespec = [0i32; 2];
        clock_read(clock.as_mut_ptr(), timespec.as_mut_ptr());
        let now_ms = timespec_to_milliseconds(timespec.as_ptr()) as u32;
        let timeout_millis = (*node).deadline_ms.wrapping_sub(now_ms) as i32;
        set_slot_deadline(thread_instance(), slot, timeout_millis);
        slot_wait(thread_instance(), slot);
        clock_source_destroy(clock.as_mut_ptr() as *mut c_void);
    }
    0
}

/// Rearms the IAP incoming-process timer for the current pending-event head.
///
/// # Safety
/// `this` must be a session object readable through +0x2c8 and +0x04; a
/// non-null head must be a valid [`PendingEventNode`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pending_event_timer_rearm(this: *mut u8) -> u32 {
    pending_event_timer_rearm_with_ops(
        this,
        firmware_clock_read_time,
        iap_incoming_process_thread_instance,
        iap_incoming_process_thread_slot_poll,
        iap_incoming_process_thread_set_slot_deadline,
        iap_incoming_process_thread_slot_wait,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: Vec<(u8, u32, i32)> = Vec::new();
    static mut NOW_MS: u32 = 0;
    static mut THREAD: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn clock_read(_clock: *mut u8, out: *mut i32) {
        out.write((NOW_MS / 1000) as i32);
        out.add(1).write(((NOW_MS % 1000) * 1_000_000) as i32);
    }
    unsafe extern "C" fn instance() -> *mut u8 { THREAD }
    unsafe extern "C" fn poll(_thread: *mut u8, slot: u32) -> u32 { CALLS.push((0, slot, 0)); 0 }
    unsafe extern "C" fn wait(_thread: *mut u8, slot: u32) -> u32 { CALLS.push((2, slot, 0)); 0 }
    unsafe extern "C" fn set_deadline(_thread: *mut u8, slot: u32, timeout: i32) -> i32 { CALLS.push((1, slot, timeout)); 0 }
    #[test]
    fn rearms_head_after_poll_with_wrapping_signed_timeout() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = (unsafe { try_map_u32_slab(hints::PENDING_EVENT_TIMER_REARM, 0x400) }) else {
            note_missing_u32_fixture("app::pending_event_timer_rearm");
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x400);
            THREAD = slab.add(0x300);
            NOW_MS = 0xffff_fff0;
            let node = slab.add(0x200) as *mut PendingEventNode;
            *node = PendingEventNode { next: 0, key: 0, deadline_ms: NOW_MS.wrapping_add(0x8000_0000), tag_a: 0, tag_b: 0, payload: 0 };
            (slab.add(HEAD_OFFSET) as *mut u32).write(node as usize as u32);
            (slab.add(TIMER_SLOT_OFFSET) as *mut u32).write(7);
            CALLS.clear();
            assert_eq!(pending_event_timer_rearm_with_ops(slab, clock_read, instance, poll, set_deadline, wait), 0);
            assert_eq!(*CALLS, [(0, 7, 0), (1, 7, i32::MIN), (2, 7, 0)]);
        }
    }

    #[test]
    fn empty_list_only_polls() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(slab) = (unsafe { try_map_u32_slab(hints::PENDING_EVENT_TIMER_REARM, 0x400) }) else {
            note_missing_u32_fixture("app::pending_event_timer_rearm");
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, 0x400);
            THREAD = slab.add(0x300);
            (slab.add(TIMER_SLOT_OFFSET) as *mut u32).write(3);
            CALLS.clear();
            pending_event_timer_rearm_with_ops(slab, clock_read, instance, poll, set_deadline, wait);
            assert_eq!(*CALLS, [(0, 3, 0)]);
        }
    }
}
