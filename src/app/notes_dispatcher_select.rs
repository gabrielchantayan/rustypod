//! Notes dispatcher selection — `FUN_0828ae88` @ `0x0828ae88`.
//! True extent: 160 bytes to `0x0828af28`: 144 code bytes and 16 literal
//! bytes. Raw-word scan: five outgoing plain BL, zero predicated BL;
//! two incoming plain BL, zero predicated BL.
//!
//! Cast the candidate to class 0x4a80. Reject a failed cast with 0x41a2.
//! A nonzero byte +0x71 selects it immediately and returns 0x41a9.
//! Otherwise query the previous target's virtual slot +0x18; only a zero
//! result toggles mode (0 -> 1, any other value -> 0). Store the original
//! candidate, set the embedded timer's delay to 500, restart it, display
//! status strings, and return 0x41a4. Resource text is not established.
//!
//! Deviation: the shared typed dispatcher and vtables widen pointers on
//! hosts. ARM retains offsets +0xdc, +0x4e8 and +0x548. All five callees
//! use their existing ports, with no additional seams.

use super::notes_dispatcher_status_strings::{NotesDispatcher, notes_dispatcher_status_strings};
use super::registry::{FrameworkObject, object_cast_to_class};
use crate::cxx::optional_vtable_slot_18_result::{OptionalVtableSlot18Owner, optional_vtable_slot_18_result};
use crate::drivers::timer::{timer_start_after, timer_restart};

#[cfg(target_pointer_width = "32")]
const _: [(); 0xdc] = [(); core::mem::offset_of!(NotesDispatcher, target)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0x4e8] = [(); core::mem::offset_of!(NotesDispatcher, mode)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0x548] = [(); core::mem::offset_of!(NotesDispatcher, timer)];

/// Selects a checked notes candidate and returns its status resource ID.
///
/// # Safety
/// Dispatcher and candidate must have valid framework vtables and fields.
/// The cast result must contain byte +0x71; the embedded timer must be live.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn notes_dispatcher_select(
    dispatcher: *mut NotesDispatcher, candidate: *mut FrameworkObject,
) -> u32 {
    let checked = object_cast_to_class(candidate, 0x4a80);
    if checked.is_null() { return 0x41a2; }
    if checked.add(0x71).read() != 0 {
        (*dispatcher).target = candidate.cast();
        return 0x41a9;
    }
    if optional_vtable_slot_18_result(dispatcher.cast::<OptionalVtableSlot18Owner>()) == 0 {
        (*dispatcher).mode = u32::from((*dispatcher).mode == 0);
    }
    (*dispatcher).target = candidate.cast();
    let timer = core::ptr::addr_of_mut!((*dispatcher).timer).cast();
    timer_start_after(timer, 500);
    timer_restart(timer);
    notes_dispatcher_status_strings(dispatcher);
    0x41a4
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::registry::FrameworkObjectVtable;
    use crate::cxx::optional_vtable_slot_18_result::OptionalVtableSlot18Target;
    use crate::drivers::timer::{TIMER_OPS, TIMER_CLASS_MUTEX};
    use crate::kernel::sync_mutex::Mutex;

    #[repr(C)]
    struct Candidate { vtable: *const FrameworkObjectVtable, bytes: [u8; 0x80] }
    unsafe extern "C" fn cast(object: *mut FrameworkObject, id: u32) -> *mut u8 {
        assert_eq!(id, 0x4a80);
        object.cast::<u8>().add(0x80)
    }
    unsafe extern "C" fn reject(_: *mut FrameworkObject, _: u32) -> *mut u8 { core::ptr::null_mut() }
    unsafe extern "C" fn previous(target: *mut OptionalVtableSlot18Target) -> u32 {
        target.cast::<u8>().add(0x70).cast::<u32>().read()
    }
    unsafe extern "C" fn trace(_: *mut u8) {}
    unsafe extern "C" fn arm(timer: *mut u8) {
        assert_eq!(timer.add(4).cast::<u32>().read(), 500);
        assert_eq!(timer.add(0x20).cast::<u32>().read(), 0x72756e20);
    }
    unsafe extern "C" fn display(owner: *mut u8, kind: u32, resource: u32) {
        if kind == 0x53745374 {
            assert_eq!(resource, if (*owner.cast::<NotesDispatcher>()).mode == 0 { 0x4190 } else { 0x4195 });
        } else { assert_eq!((kind, resource), (0x53747220, 0x41a1)); }
    }

    #[test]
    fn selection_rejection_fast_path_and_mode_boundaries() {
        let _guard = crate::testing::TIMER_OPS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let saved_ops = core::ptr::addr_of!(TIMER_OPS).read();
            let saved_mutex = core::ptr::addr_of!(TIMER_CLASS_MUTEX).read();
            TIMER_OPS.trace_assert = trace;
            TIMER_OPS.arm_timer = arm;
            TIMER_CLASS_MUTEX = Mutex { sem_cell: core::ptr::null_mut(), unused: 0 };
            let mut status_slots = [display as usize; 23];
            let mut target_slots = [previous as usize; 7];
            let mut owner: NotesDispatcher = core::mem::zeroed();
            owner.vtable = status_slots.as_mut_ptr().cast();
            let mut old = Candidate { vtable: target_slots.as_mut_ptr().cast(), bytes: [0; 0x80] };
            let mut vtable = FrameworkObjectVtable { unresolved_00: [0; 5], cast_to_class: reject };
            // Cast result is a distinct interior object; its +0x71 byte is
            // deliberately outside the original candidate prefix.
            #[repr(C)]
            struct Storage { candidate: Candidate, tail: [u8; 0x100] }
            let mut storage = Storage { candidate: Candidate { vtable: &vtable, bytes: [0; 0x80] }, tail: [0; 0x100] };
            let candidate = core::ptr::addr_of_mut!(storage).cast::<FrameworkObject>();
            owner.mode = 9;
            assert_eq!(notes_dispatcher_select(&mut owner, candidate), 0x41a2);
            assert!(owner.target.is_null());
            assert_eq!(owner.mode, 9);
            vtable.cast_to_class = cast;
            candidate.cast::<u8>().add(0x80 + 0x71).write(0xff);
            assert_eq!(notes_dispatcher_select(&mut owner, candidate), 0x41a9);
            assert_eq!(owner.target.cast::<FrameworkObject>(), candidate);
            assert_eq!(owner.mode, 9);
            assert_eq!(owner.timer, [0; 12]);
            candidate.cast::<u8>().add(0x80 + 0x71).write(0);
            for (mode, result, expected) in [(0, 0u32, 1), (1, 0, 0), (2, 0, 0), (u32::MAX, 0, 0), (0, 1, 0), (7, 2, 7)] {
                old.bytes[0x70 - core::mem::size_of::<usize>()..0x74 - core::mem::size_of::<usize>()].copy_from_slice(&result.to_le_bytes());
                owner.target = core::ptr::addr_of_mut!(old).cast();
                owner.mode = mode;
                assert_eq!(notes_dispatcher_select(&mut owner, candidate), 0x41a4);
                assert_eq!(owner.mode, expected);
                assert_eq!(owner.target.cast::<FrameworkObject>(), candidate);
                assert_eq!(owner.timer[1], 500);
                assert_eq!(owner.timer[8], 0x72756e20);
            }
            owner.target = core::ptr::null_mut();
            owner.mode = 5;
            assert_eq!(notes_dispatcher_select(&mut owner, candidate), 0x41a4);
            assert_eq!(owner.mode, 5);
            TIMER_OPS = saved_ops;
            TIMER_CLASS_MUTEX = saved_mutex;
        }
    }
}
