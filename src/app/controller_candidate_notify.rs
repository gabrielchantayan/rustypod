//! Controller candidate notification policy — original `FUN_0817ef14` at
//! **0x0817ef14**.
//!
//! Raw ARM establishes the exact **212-byte** extent: `0x0817ef14..0x0817efe8`,
//! where the next function begins with `push {r4-r8,lr}`. It has five
//! unconditional calls (three plain `bl` and two `blx`) plus one predicated
//! `blxeq`. Starting with the candidate returned from its +0xe8 virtual slot,
//! it follows +0x120 parent links while each node casts to class 0x1100. It
//! then accepts a terminal candidate only when its 0x3b80 cast is absent or
//! its +0x160 predicate returns nonzero, and the candidate's +0x34 identifier
//! differs from the controller's +0x38 identifier. On acceptance, mode zero
//! invokes the controller-owned +0x1e8 notification slot.
//!
//! # Deliberate deviations
//!
//! Host builds replace target-width virtual dispatch and the existing
//! `object_cast_to_class` seam with test-installable operations. Target builds
//! retain the exact volatile 32-bit pointer-field and vtable-slot accesses.

use core::mem::transmute;
use core::ptr::read_volatile;

const INITIAL_CANDIDATE_SLOT: usize = 0xe8;
const PARENT_CANDIDATE_SLOT: usize = 0x120;
const CLASS_PREDICATE_SLOT: usize = 0x160;
const NOTIFY_CANDIDATE_SLOT: usize = 0x1e8;
const CANDIDATE_IDENTIFIER_OFFSET: usize = 0x34;
const CONTROLLER_IDENTIFIER_OFFSET: usize = 0x38;
const CONTROLLER_NOTIFY_OFFSET: usize = 0x34;
const PARENT_CLASS_ID: u32 = 0x1100;
const VALIDATION_CLASS_ID: u32 = 0x3b80;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn target_ptr(at: *const u8) -> *mut u8 {
    unsafe { read_volatile(at.cast::<u32>()) as usize as *mut u8 }
}
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn target_ptr(at: *const u8) -> *mut u8 {
    unsafe { read_volatile(at.cast::<u32>()) as usize as *mut u8 }
}


#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn vtable_slot(receiver: *mut u8, offset: usize) -> usize {
    let vtable = unsafe { target_ptr(receiver) };
    unsafe { read_volatile(vtable.add(offset).cast::<u32>()) as usize }
}
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn cast_object(object: *mut u8, class_id: u32) -> *mut u8 {
    unsafe { crate::app::registry::object_cast_to_class(object.cast(), class_id) }
}


type CandidateDispatch = unsafe extern "C" fn(*mut u8, u32, u32) -> *mut u8;
type ClassPredicate = unsafe extern "C" fn() -> u32;
type CandidateNotify = unsafe extern "C" fn(*mut u8, *mut u8);
type ObjectCast = unsafe extern "C" fn(*mut u8, u32) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_candidate_dispatch(_: *mut u8, _: u32, _: u32) -> *mut u8 { panic!("host tests must install candidate dispatch") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_class_predicate() -> u32 { panic!("host tests must install class predicate") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_candidate_notify(_: *mut u8, _: *mut u8) { panic!("host tests must install candidate notification") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_object_cast(_: *mut u8, _: u32) -> *mut u8 { panic!("host tests must install object cast") }

#[cfg(not(target_os = "none"))]
static mut HOST_INITIAL_CANDIDATE: CandidateDispatch = unavailable_candidate_dispatch;
#[cfg(not(target_os = "none"))]
static mut HOST_PARENT_CANDIDATE: CandidateDispatch = unavailable_candidate_dispatch;
#[cfg(not(target_os = "none"))]
static mut HOST_CLASS_PREDICATE: ClassPredicate = unavailable_class_predicate;
#[cfg(not(target_os = "none"))]
static mut HOST_NOTIFY_CANDIDATE: CandidateNotify = unavailable_candidate_notify;
#[cfg(not(target_os = "none"))]
static mut HOST_OBJECT_CAST: ObjectCast = unavailable_object_cast;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn cast_object(object: *mut u8, class_id: u32) -> *mut u8 { unsafe { HOST_OBJECT_CAST(object, class_id) } }

/// Evaluates one controller candidate and optionally notifies the controller.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_candidate_notify(controller: *mut u8, input: *mut u8, mode: u32) -> u32 {
    #[cfg(target_os = "none")]
    let mut candidate: *mut u8 = unsafe { transmute::<usize, CandidateDispatch>(vtable_slot(input, INITIAL_CANDIDATE_SLOT))(input, 1, 1) };
    #[cfg(not(target_os = "none"))]
    let mut candidate = unsafe { HOST_INITIAL_CANDIDATE(input, 1, 1) };
    if candidate.is_null() { return 0; }

    while !unsafe { cast_object(candidate, PARENT_CLASS_ID) }.is_null() {
        #[cfg(target_os = "none")]
        let parent = unsafe { transmute::<usize, CandidateDispatch>(vtable_slot(candidate, PARENT_CANDIDATE_SLOT))(candidate, 1, 1) };
        #[cfg(not(target_os = "none"))]
        let parent = unsafe { HOST_PARENT_CANDIDATE(candidate, 1, 1) };
        if parent.is_null() { break; }
        candidate = parent;
    }

    let validated = unsafe { cast_object(candidate, VALIDATION_CLASS_ID) };
    let predicate_allows = if validated.is_null() { true } else {
        #[cfg(target_os = "none")]
        { (unsafe { transmute::<usize, ClassPredicate>(vtable_slot(validated, CLASS_PREDICATE_SLOT))() }) != 0 }
        #[cfg(not(target_os = "none"))]
        { (unsafe { HOST_CLASS_PREDICATE() }) != 0 }
    };
    if !predicate_allows || unsafe { read_volatile(candidate.add(CANDIDATE_IDENTIFIER_OFFSET).cast::<u32>()) } == unsafe { read_volatile(controller.add(CONTROLLER_IDENTIFIER_OFFSET).cast::<u32>()) } { return 0; }

    if mode == 0 {
        let notify_target = unsafe { target_ptr(controller.add(CONTROLLER_NOTIFY_OFFSET)) };
        #[cfg(target_os = "none")]
        unsafe { transmute::<usize, CandidateNotify>(vtable_slot(notify_target, NOTIFY_CANDIDATE_SLOT))(notify_target, candidate) };
        #[cfg(not(target_os = "none"))]
        unsafe { HOST_NOTIFY_CANDIDATE(notify_target, candidate) };
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const SLAB_LEN: usize = 0x1000;
    const INPUT: usize = 0x100;
    const FIRST: usize = 0x200;
    const LAST: usize = 0x300;
    const MANAGER: usize = 0x400;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::CONTROLLER_CANDIDATE_NOTIFY, SLAB_LEN).map(|p| p as usize));
    static LOCK: Mutex<()> = Mutex::new(());
    static mut FIRST_PTR: *mut u8 = core::ptr::null_mut();
    static mut LAST_PTR: *mut u8 = core::ptr::null_mut();
    static mut NOTIFIED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn initial(_: *mut u8, _: u32, _: u32) -> *mut u8 { unsafe { FIRST_PTR } }
    unsafe extern "C" fn parent(candidate: *mut u8, _: u32, _: u32) -> *mut u8 { if candidate == unsafe { FIRST_PTR } { unsafe { LAST_PTR } } else { core::ptr::null_mut() } }
    unsafe extern "C" fn cast(candidate: *mut u8, class: u32) -> *mut u8 {
        if class == PARENT_CLASS_ID && candidate == unsafe { LAST_PTR } { core::ptr::null_mut() } else if class == VALIDATION_CLASS_ID { core::ptr::null_mut() } else { candidate }
    }
    unsafe extern "C" fn predicate() -> u32 { 1 }
    unsafe extern "C" fn notify(_: *mut u8, candidate: *mut u8) { unsafe { NOTIFIED = candidate; } }

    unsafe extern "C" fn missing_initial(_: *mut u8, _: u32, _: u32) -> *mut u8 { core::ptr::null_mut() }

    unsafe fn fixture() -> Option<*mut u8> {
        let base = (*SLAB)? as *mut u8;
        unsafe {
            base.write_bytes(0, SLAB_LEN);
            FIRST_PTR = base.add(FIRST); LAST_PTR = base.add(LAST); NOTIFIED = core::ptr::null_mut();
            base.add(LAST + CANDIDATE_IDENTIFIER_OFFSET).cast::<u32>().write_volatile(7);
            base.add(CONTROLLER_IDENTIFIER_OFFSET).cast::<u32>().write_volatile(9);
            base.add(CONTROLLER_NOTIFY_OFFSET).cast::<u32>().write_volatile(base.add(MANAGER) as u32);
        }
        Some(base)
    }
    unsafe fn install() { unsafe { HOST_INITIAL_CANDIDATE = initial; HOST_PARENT_CANDIDATE = parent; HOST_OBJECT_CAST = cast; HOST_CLASS_PREDICATE = predicate; HOST_NOTIFY_CANDIDATE = notify; } }

    #[test]
    fn follows_parent_chain_and_notifies_only_in_zero_mode() {
        let _lock = LOCK.lock();
        let Some(controller) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("app/controller_candidate_notify")); return; };
        unsafe { install(); }
        assert_eq!(unsafe { controller_candidate_notify(controller, controller.add(INPUT), 0) }, 1);
        assert_eq!(unsafe { NOTIFIED }, unsafe { LAST_PTR });
        unsafe { NOTIFIED = core::ptr::null_mut(); }
        assert_eq!(unsafe { controller_candidate_notify(controller, controller.add(INPUT), 1) }, 1);
        assert!(unsafe { NOTIFIED }.is_null());
    }

    #[test]
    fn rejects_missing_initial_candidate() {
        let _lock = LOCK.lock();
        let Some(controller) = (unsafe { fixture() }) else { assert!(note_missing_u32_fixture("app/controller_candidate_notify")); return; };
        unsafe { install(); HOST_INITIAL_CANDIDATE = missing_initial; }
        assert_eq!(unsafe { controller_candidate_notify(controller, controller.add(INPUT), 0) }, 0);
        assert!(unsafe { NOTIFIED }.is_null());
    }
}
