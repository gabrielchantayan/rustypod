//! Activate an accepted target selection.
//!
//! `target_selection_activate` — original: `FUN_0828addc` @ **0x0828addc**
//! (104 bytes). Raw `osos.dec` words establish the A32 body from
//! `0x0828addc` through `0x0828ae43`; the two following words are return-code
//! literals and the next independently entered function starts at `0x0828ae4c`.
//! The body contains four plain `bl` instructions and no predicated `bl`
//! instructions: `0x08275b9c`, `0x0828ae4c`, `0x0828b81c`, and `0x0828a8d0`.
//!
//! # Algorithm
//!
//! Ask the opaque target helper whether `target` accepts tag `0x4b00`. On
//! rejection, return `0x41a2` without changing the owner. On acceptance, ask
//! the existing optional-target dispatcher for the current target's result.
//! Result one clears a nonzero owner word at `+0x4e4`, or sets it to one when
//! it was zero. Store `target` at `+0xdc`, invoke the two opaque owner
//! follow-up helpers, then return `0x41a3`.
//!
//! # Deliberate deviation
//!
//! The three unported direct callees retain their verified load addresses on
//! firmware and use replaceable native-width host seams in tests. The already
//! ported `optional_vtable_slot_18_result` is called directly. Target pointer
//! fields are accessed at byte offsets, rather than through a Rust layout, so
//! host pointer width cannot move either target field.

use core::ffi::c_void;

use super::optional_vtable_slot_18_result::{optional_vtable_slot_18_result, OptionalVtableSlot18Owner};

const TARGET_OFFSET: usize = 0xdc;
const ACTIVE_FLAG_OFFSET: usize = 0x4e4;
const ACCEPTED_TARGET_TAG: u32 = 0x4b00;
const REJECTED_STATUS: u32 = 0x41a2;
const ACCEPTED_STATUS: u32 = 0x41a3;

type TargetTagCheck = unsafe extern "C" fn(*mut c_void, u32) -> u32;
type OwnerFollowUp = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn target_tag_check() -> TargetTagCheck {
    unsafe { core::mem::transmute(0x0827_5b9cusize) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_target_tag_check(_target: *mut c_void, _tag: u32) -> u32 {
    panic!("install target-selection host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
pub static mut TARGET_TAG_CHECK: TargetTagCheck = missing_target_tag_check;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn owner_selection_follow_up() -> OwnerFollowUp {
    unsafe { core::mem::transmute(0x0828_b81cusize) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_selection_follow_up(_owner: *mut u8) {
    panic!("install target-selection host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
pub static mut OWNER_SELECTION_FOLLOW_UP: OwnerFollowUp = missing_owner_selection_follow_up;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn owner_target_follow_up() -> OwnerFollowUp {
    unsafe { core::mem::transmute(0x0828_a8d0usize) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_owner_target_follow_up(_owner: *mut u8) {
    panic!("install target-selection host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
pub static mut OWNER_TARGET_FOLLOW_UP: OwnerFollowUp = missing_owner_target_follow_up;

/// Selects an accepted opaque target and runs the retail follow-up sequence.
///
/// # Safety
///
/// `owner` must provide readable and writable target-width words at `+0xdc`
/// and `+0x4e4`; `target` and all selected callbacks must satisfy the opaque
/// retailOS contracts. As in the firmware, no pointer is validated.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn target_selection_activate(owner: *mut u8, target: *mut c_void) -> u32 {
    #[cfg(target_os = "none")]
    let accepted = unsafe { target_tag_check()(target, ACCEPTED_TARGET_TAG) };
    #[cfg(not(target_os = "none"))]
    let accepted = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TARGET_TAG_CHECK))(target, ACCEPTED_TARGET_TAG) };

    if accepted == 0 {
        return REJECTED_STATUS;
    }

    if unsafe { optional_vtable_slot_18_result(owner.cast::<OptionalVtableSlot18Owner>()) } == 1 {
        let active = unsafe { owner.add(ACTIVE_FLAG_OFFSET).cast::<u32>().read() };
        unsafe { owner.add(ACTIVE_FLAG_OFFSET).cast::<u32>().write(u32::from(active == 0)) };
    }
    unsafe { owner.add(TARGET_OFFSET).cast::<*mut c_void>().write_unaligned(target) };

    #[cfg(target_os = "none")]
    unsafe { owner_selection_follow_up()(owner) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OWNER_SELECTION_FOLLOW_UP))(owner) };

    #[cfg(target_os = "none")]
    unsafe { owner_target_follow_up()(owner) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OWNER_TARGET_FOLLOW_UP))(owner) };

    ACCEPTED_STATUS
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut TAG_CHECK_RESULT: u32 = 0;
    static mut TAG_CHECK_TARGET: usize = 0;
    static mut TAG_CHECK_TAG: u32 = 0;
    static mut FOLLOW_UP_SEQUENCE: [u8; 2] = [0; 2];
    static mut FOLLOW_UP_COUNT: usize = 0;

    unsafe extern "C" fn tag_check(target: *mut c_void, tag: u32) -> u32 {
        unsafe {
            TAG_CHECK_TARGET = target as usize;
            TAG_CHECK_TAG = tag;
            TAG_CHECK_RESULT
        }
    }

    unsafe extern "C" fn selection_follow_up(_owner: *mut u8) {
        unsafe {
            FOLLOW_UP_SEQUENCE[FOLLOW_UP_COUNT] = 1;
            FOLLOW_UP_COUNT += 1;
        }
    }

    unsafe extern "C" fn target_follow_up(_owner: *mut u8) {
        unsafe {
            FOLLOW_UP_SEQUENCE[FOLLOW_UP_COUNT] = 2;
            FOLLOW_UP_COUNT += 1;
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench(tag_result: u32) -> Bench {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            TAG_CHECK_RESULT = tag_result;
            TAG_CHECK_TARGET = 0;
            TAG_CHECK_TAG = 0;
            FOLLOW_UP_SEQUENCE = [0; 2];
            FOLLOW_UP_COUNT = 0;
            TARGET_TAG_CHECK = tag_check;
            OWNER_SELECTION_FOLLOW_UP = selection_follow_up;
            OWNER_TARGET_FOLLOW_UP = target_follow_up;
        }
        Bench { _lock: lock }
    }

    fn owner_with_current_target(current: *mut c_void, active: u32) -> std::vec::Vec<u8> {
        let mut owner = std::vec![0u8; ACTIVE_FLAG_OFFSET + core::mem::size_of::<u32>()];
        unsafe {
            owner.as_mut_ptr().add(TARGET_OFFSET).cast::<*mut c_void>().write_unaligned(current);
            owner.as_mut_ptr().add(ACTIVE_FLAG_OFFSET).cast::<u32>().write(active);
        }
        owner
    }

    #[test]
    fn rejected_target_leaves_owner_and_skips_follow_ups() {
        let _bench = bench(0);
        let target = 0x1234usize as *mut c_void;
        let mut owner = owner_with_current_target(core::ptr::null_mut(), 7);

        assert_eq!(unsafe { target_selection_activate(owner.as_mut_ptr(), target) }, REJECTED_STATUS);
        assert_eq!(unsafe { TAG_CHECK_TARGET }, target as usize);
        assert_eq!(unsafe { TAG_CHECK_TAG }, ACCEPTED_TARGET_TAG);
        assert_eq!(unsafe { owner.as_ptr().add(TARGET_OFFSET).cast::<*const c_void>().read_unaligned() }, core::ptr::null());
        assert_eq!(unsafe { owner.as_ptr().add(ACTIVE_FLAG_OFFSET).cast::<u32>().read() }, 7);
        assert_eq!(unsafe { FOLLOW_UP_COUNT }, 0);
    }

    #[test]
    fn accepted_target_toggles_zero_active_flag_and_orders_follow_ups() {
        let _bench = bench(1);
        let target = 0x5678usize as *mut c_void;
        let mut owner = owner_with_current_target(core::ptr::null_mut(), 0);

        assert_eq!(unsafe { target_selection_activate(owner.as_mut_ptr(), target) }, ACCEPTED_STATUS);
        assert_eq!(unsafe { owner.as_ptr().add(TARGET_OFFSET).cast::<*const c_void>().read_unaligned() }, target.cast_const());
        assert_eq!(unsafe { owner.as_ptr().add(ACTIVE_FLAG_OFFSET).cast::<u32>().read() }, 1);
        assert_eq!(unsafe { FOLLOW_UP_SEQUENCE }, [1, 2]);
    }

    #[test]
    fn accepted_target_clears_any_nonzero_active_flag() {
        let _bench = bench(1);
        let target = 0x9abcusize as *mut c_void;
        let mut owner = owner_with_current_target(core::ptr::null_mut(), u32::MAX);

        assert_eq!(unsafe { target_selection_activate(owner.as_mut_ptr(), target) }, ACCEPTED_STATUS);
        assert_eq!(unsafe { owner.as_ptr().add(ACTIVE_FLAG_OFFSET).cast::<u32>().read() }, 0);
    }
}
