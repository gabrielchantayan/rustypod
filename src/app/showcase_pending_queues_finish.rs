//! Finish the Showcase pending-queue phase.
//!
//! Original `FUN_081b6ee8` @ 0x081b6ee8, 172 bytes; the independent
//! flag-update function starts at 0x081b6f94. Raw A32 decoding verifies
//! two inbound plain BLs (0x0822e050, 0x08230658), no predicated inbound
//! BLs, four plain outbound BLs and one BLEQ (slot initialization).
//!
//! Lock +0x18. State zero, or state one without a resource at +0xf0,
//! returns unchanged. Other resource-less states panic. Initialize slots
//! when +0xe9 is zero. With a signed selected slot other than -1 and no
//! completion flag, complete pending queues. Re-read completion and slot
//! after that call; schedule when completion is set, requiring a slot.
//! Store state three only after successful processing, then unlock.
//!
//! Deviations: reuse existing Rust callees, discarding dead r1/r2 residue
//! (the verified completion and scheduling ports do not consume it).
//! Target-width aligned words and byte offsets preserve the retail layout.
//! A callback core isolates mutation-sensitive transitions for host tests;
//! its failure result invokes the existing nonreturning panic without unlock.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock};

#[cfg(target_os = "none")]
unsafe extern "C" {
    #[link_name = "resource_slot_table_initialize"]
    fn retail_resource_slot_table_initialize(showcase: *mut u8);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation { Initialize, Complete, Schedule(u32) }

#[inline(always)]
unsafe fn finish_phase(showcase: *mut u8, mut operate: impl FnMut(Operation)) -> bool {
    let state = showcase.add(0x20).read();
    if state == 0 { return true; }
    if showcase.add(0xf0).cast::<u32>().read() == 0 { return state == 1; }
    if showcase.add(0xe9).read() == 0 { operate(Operation::Initialize); }
    let slot = showcase.add(0xec).cast::<i8>().read();
    if slot != -1 && showcase.add(0xea).read() == 0 {
        operate(Operation::Complete);
    }
    if showcase.add(0xea).read() != 0 {
        let slot = showcase.add(0xec).cast::<i8>().read();
        if slot == -1 { return false; }
        operate(Operation::Schedule(slot as i32 as u32));
    }
    showcase.add(0x20).write(3);
    true
}

/// # Safety
/// `showcase` must be an aligned writable retail Showcase object. Its mutex
/// at +0x18, resource slots, selected queue, and dispatch context must satisfy
/// the existing initialization, completion, and scheduling contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn showcase_pending_queues_finish(showcase: *mut u8) {
    let mutex = showcase.add(0x18).cast();
    mutex_lock(mutex);
    let success = finish_phase(showcase, |operation| match operation {
        Operation::Initialize => {
            #[cfg(target_os = "none")]
            retail_resource_slot_table_initialize(showcase);
            #[cfg(not(target_os = "none"))]
            crate::app::resource_slot_table_initialize::resource_slot_table_initialize(showcase);
        }
        Operation::Complete =>
            crate::app::showcase_pending_queues_complete::showcase_pending_queues_complete(showcase),
        Operation::Schedule(slot) =>
            crate::app::showcase_pending_queues_schedule::showcase_pending_queues_schedule(showcase.cast(), slot),
    });
    if !success { crate::heap::veneers::heap_panic(); }
    mutex_unlock(mutex);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_resource_and_slot_boundaries() {
        for state in [0, 1, 2, 3, 255] {
            for resource in [0, 1, u32::MAX] {
                for slot in [-128i8, -1, 0, 3, 127] {
                    for ready in [0, 1, 255] {
                        let mut object = [0u32; 0x75];
                        let pointer = object.as_mut_ptr().cast::<u8>();
                        unsafe {
                            pointer.add(0x20).write(state);
                            pointer.add(0xf0).cast::<u32>().write(resource);
                            pointer.add(0xe9).write(1);
                            pointer.add(0xea).write(ready);
                            pointer.add(0xec).cast::<i8>().write(slot);
                        }
                        let before = object;
                        let active = state != 0 && resource != 0;
                        let complete = active && slot != -1 && ready == 0;
                        let schedule = active && (ready != 0 || complete) && slot != -1;
                        let success = state == 0 || (resource == 0 && state == 1)
                            || (active && !(slot == -1 && ready != 0));
                        let mut completed = false;
                        let mut scheduled = false;
                        unsafe {
                            assert_eq!(finish_phase(pointer, |operation| match operation {
                                Operation::Initialize => panic!("already initialized"),
                                Operation::Complete => {
                                    assert!(complete);
                                    assert_eq!(pointer.add(0x20).read(), state);
                                    completed = true;
                                    pointer.add(0xea).write(1);
                                }
                                Operation::Schedule(selected) => {
                                    assert!(schedule);
                                    assert_eq!(selected, slot as i32 as u32);
                                    assert_eq!(completed, complete);
                                    assert_eq!(pointer.add(0x20).read(), state);
                                    scheduled = true;
                                }
                            }), success);
                        }
                        assert_eq!((completed, scheduled), (complete, schedule));
                        let mut expected = before;
                        let bytes = expected.as_mut_ptr().cast::<u8>();
                        unsafe {
                            if complete { bytes.add(0xea).write(1); }
                            if active && success { bytes.add(0x20).write(3); }
                        }
                        assert_eq!(object, expected);
                    }
                }
            }
        }
    }

    #[test]
    fn callback_mutations_control_later_decisions() {
        let mut object = [0u32; 0x75];
        let pointer = object.as_mut_ptr().cast::<u8>();
        unsafe {
            pointer.add(0x20).write(2);
            pointer.add(0xf0).cast::<u32>().write(1);
            pointer.add(0xec).write(0xff);
            let mut step = 0;
            assert!(finish_phase(pointer, |operation| {
                match step {
                    0 => {
                        assert_eq!(operation, Operation::Initialize);
                        pointer.add(0xec).write(2);
                    }
                    1 => {
                        assert_eq!(operation, Operation::Complete);
                        pointer.add(0xea).write(1);
                        pointer.add(0xec).write(3);
                    }
                    2 => assert_eq!(operation, Operation::Schedule(3)),
                    _ => panic!("unexpected operation"),
                }
                step += 1;
            }));
            assert_eq!(step, 3);
            assert_eq!(pointer.add(0x20).read(), 3);
            pointer.add(0x20).write(2);
            pointer.add(0xe9).write(1);
            pointer.add(0xea).write(0);
            assert!(!finish_phase(pointer, |operation| {
                assert_eq!(operation, Operation::Complete);
                pointer.add(0xea).write(1);
                pointer.add(0xec).write(0xff);
            }));
            assert_eq!(pointer.add(0x20).read(), 2);
        }
    }

    #[test]
    fn exported_idle_path_preserves_object() {
        let mut object = [0u64; 0x3b];
        unsafe { showcase_pending_queues_finish(object.as_mut_ptr().cast()); }
        assert_eq!(object, [0; 0x3b]);
    }
}
