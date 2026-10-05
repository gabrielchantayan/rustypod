//! Refresh pending Showcase queues and commit their slot positions.
//!
//! Original: `FUN_081b7824` @ **0x081b7824**, **108 bytes** including
//! the request literal at 0x081b788c; next real function: 0x081b7890.
//! Raw-image decoding finds two inbound plain BLs (0x081b6ad8 and
//! 0x081b6eac), zero predicated inbound BLs; four plain outbound BLs and
//! one BLEQ. Require a pending selected queue, clear timer slots and stop
//! the timer, then visit all four queues. Dispatch pending contexts with
//! request 10,000,000 and argument 0x80000; afterward copy each slot's
//! position at +0x2c to its committed position at +0x34.
//!
//! Deviations: reuse existing Rust lookup, panic, timer and predicate ports.
//! Preserve target-width word offsets on hosts. The unported dispatch uses
//! verified address 0x0822b2a8 (raw 28-byte gate, not Ghidra's merged body),
//! forwarding all three registers. Host dispatch is unsupported. A private
//! callback core allows isolated behavioral tests. The incoming r2 is unused.

use super::showcase_clear_timer_slots::showcase_clear_timer_slots_and_stop;
use super::showcase_queue_has_pending_entry::showcase_queue_has_pending_entry;
use super::showcase_slot_pending_queue::showcase_slot_pending_queue;
use crate::heap::veneers::heap_panic;

#[inline(always)]
unsafe fn refresh_queues(showcase: *mut u32, mut dispatch: impl FnMut(u32, u32, u32)) {
    for slot in 0..4 {
        let record = showcase.add(slot * 6);
        let queue = record.add(0x22);
        if showcase_queue_has_pending_entry(queue) != 0 {
            dispatch(queue.read(), 10_000_000, 0x80000);
            record.add(0x0d).write(record.add(0x0b).read());
        }
    }
}

#[inline(always)]
unsafe fn dispatch_context(context: u32, request: u32, argument: u32) {
    #[cfg(target_os = "none")]
    {
        let dispatch: unsafe extern "C" fn(u32, u32, u32) =
            core::mem::transmute(0x0822_b2a8usize);
        dispatch(context, request, argument);
    }
    #[cfg(not(target_os = "none"))]
    { let _ = (context, request, argument); panic!("requires retailOS context dispatch at 0x0822b2a8"); }
}

/// # Safety
/// `showcase` must be an aligned writable retail object through +0x1d4;
/// its selected slot must have pending work. Timer and queue context pointers
/// must satisfy the existing timer-stop and retail dispatch contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn showcase_pending_queues_refresh(showcase: *mut u32, slot: u32) {
    if showcase_slot_pending_queue(showcase, slot).is_null() {
        heap_panic();
    }
    showcase_clear_timer_slots_and_stop(showcase.cast());
    refresh_queues(showcase, |context, request, argument| {
        dispatch_context(context, request, argument);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_queues_leave_positions_and_neighbors_untouched() {
        let mut object = [0xabad_cafe; 0x75];
        for slot in 0..4 { object[0x24 + slot * 6] = object[0x23 + slot * 6]; }
        let before = object;
        unsafe { refresh_queues(object.as_mut_ptr(), |_, _, _| panic!("empty dispatch")); }
        assert_eq!(object, before);
    }

    #[test]
    fn dispatch_changes_are_read_before_commit_and_later_queue_checks() {
        let mut object = [0; 0x75];
        object[0x23] = 1;
        for slot in 0..4 {
            object[0x22 + slot * 6] = slot as u32;
            object[0x0b + slot * 6] = 100 + slot as u32;
            object[0x0d + slot * 6] = u32::MAX;
        }
        let pointer = object.as_mut_ptr();
        let before = object;
        let mut calls = 0;
        unsafe {
            refresh_queues(pointer, |context, request, argument| {
                assert_eq!(context, [0, 3][calls]);
                assert_eq!((request, argument), (10_000_000, 0x80000));
                let slot = context as usize;
                assert_eq!(pointer.add(0x0d + slot * 6).read(), u32::MAX);
                pointer.add(0x0b + slot * 6).write(0xf000_0000 + context);
                if calls == 0 { pointer.add(0x23 + 3 * 6).write(1); }
                else { assert_eq!(pointer.add(0x0d).read(), 0xf000_0000); }
                calls += 1;
            });
        }
        assert_eq!(calls, 2);
        let mut expected = before;
        expected[0x23 + 3 * 6] = 1;
        for slot in [0, 3] {
            expected[0x0b + slot * 6] = 0xf000_0000 + slot as u32;
            expected[0x0d + slot * 6] = 0xf000_0000 + slot as u32;
        }
        assert_eq!(object, expected);
    }
}
