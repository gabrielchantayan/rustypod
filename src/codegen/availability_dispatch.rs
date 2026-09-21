//! `cg_wait_and_dispatch` — original: `FUN_082bcd2c` @ **0x082bcd2c**.
//!
//! Raw `osos.dec` words establish the 196-byte extent
//! `0x082bcd2c..0x082bcdf0`; two trailing literals occupy
//! `0x082bcdf0/0x082bcdf4`, and the next independently linked function begins
//! at `0x082bcdf8`. A complete aligned decode finds **5 inbound direct `bl`
//! calls**: four plain and one predicated (`blmi`). Its body contains six
//! plain `bl` instructions and one predicated (`blne`) mailbox post.
//! The routine polls two availability predicates. When both clear, it marks
//! the shared dispatch state active, posts its optional mailbox, and sleeps
//! 100 ticks until either predicate becomes nonzero. It then clears the mark,
//! performs a setup gate, requires the target object, invokes its optional
//! `+0x08` callback with the state payload, and returns its optional `+0x24`
//! callback's result for `dispatch_arg`.
//!
//! Deliberate deviations: the unported second predicate and setup gate remain
//! literal retailOS veneers on ARM and host callback seams. The first
//! predicate is the direct Rust port at `0x082bcf38`. Host callback targets
//! use native-width function pointers, while firmware accesses the verified
//! target-width words at `+0x08` and `+0x24`.

use core::ptr;

const DISPATCH_STATE: *mut DispatchState = 0x089c_aae4 as *mut DispatchState;
const MAILBOX_SLOT: *mut u32 = 0x089c_a964 as *mut u32;
const TARGET_MISSING: u32 = 0x11;
const RETRY_TICKS: u32 = 100;

#[repr(C)]
struct DispatchState {
    active: u32,
    target: u32,
    payload: u32,
}

pub type AvailabilityPredicate = unsafe extern "C" fn() -> u32;
pub type SetupGate = unsafe extern "C" fn() -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn available() -> u32 { 1 }
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn setup_ok() -> u32 { 0 }

#[cfg(not(target_arch = "arm"))]
pub static mut CG_FIRST_AVAILABILITY: AvailabilityPredicate = available;
#[cfg(not(target_arch = "arm"))]
pub static mut CG_SECOND_AVAILABILITY: AvailabilityPredicate = available;
#[cfg(not(target_arch = "arm"))]
pub static mut CG_DISPATCH_SETUP: SetupGate = setup_ok;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_cg_second_availability() -> u32;
    fn retail_cg_dispatch_setup() -> u32;
}
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_cg_first_availability() -> u32 { ptr::read_volatile(ptr::addr_of!(CG_FIRST_AVAILABILITY))() }
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_cg_second_availability() -> u32 { ptr::read_volatile(ptr::addr_of!(CG_SECOND_AVAILABILITY))() }
#[cfg(not(target_arch = "arm"))]
unsafe fn retail_cg_dispatch_setup() -> u32 { ptr::read_volatile(ptr::addr_of!(CG_DISPATCH_SETUP))() }
#[cfg(target_arch = "arm")]
unsafe fn first_availability() -> u32 { crate::codegen::first_availability::cg_first_availability() }
#[cfg(not(target_arch = "arm"))]
unsafe fn first_availability() -> u32 { retail_cg_first_availability() }

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_cg_second_availability
retail_cg_second_availability:
    ldr pc, [pc, #-4]
    .word 0x082bc4b8
    .globl retail_cg_dispatch_setup
retail_cg_dispatch_setup:
    ldr pc, [pc, #-4]
    .word 0x080e4b6c
"#);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn state() -> *mut DispatchState { DISPATCH_STATE }
#[cfg(not(target_os = "none"))]
static mut HOST_STATE: DispatchState = DispatchState { active: 0, target: 0, payload: 0 };
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn state() -> *mut DispatchState { ptr::addr_of_mut!(HOST_STATE) }

#[cfg(target_os = "none")]
unsafe fn post_mailbox() {
    if ptr::read_volatile(MAILBOX_SLOT) != 0 {
        crate::kernel::kobj::mailbox_slot_post(MAILBOX_SLOT.cast());
    }
}
#[cfg(not(target_os = "none"))]
unsafe fn post_mailbox() {}

#[cfg(target_os = "none")]
unsafe fn sleep_retry() { crate::kernel::task::task_sleep(RETRY_TICKS); }
#[cfg(not(target_os = "none"))]
unsafe fn sleep_retry() {}

#[cfg(target_os = "none")]
unsafe fn dispatch_target(target: u32, payload: u32, arg: u32) -> u32 {
    let words = target as *const u32;
    let begin: u32 = ptr::read_volatile(words.add(2));
    if begin != 0 { core::mem::transmute::<u32, unsafe extern "C" fn(u32)>(begin)(payload); }
    let dispatch: u32 = ptr::read_volatile(words.add(9));
    if dispatch == 0 { 0 } else { core::mem::transmute::<u32, unsafe extern "C" fn(u32) -> u32>(dispatch)(arg) }
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostDispatchTarget {
    pub _before_begin: [u32; 2],
    pub begin: Option<unsafe extern "C" fn(u32)>,
    pub _before_dispatch: [u32; 6],
    pub dispatch: Option<unsafe extern "C" fn(u32) -> u32>,
}
#[cfg(not(target_os = "none"))]
unsafe fn dispatch_target(target: u32, _payload: u32, _arg: u32) -> u32 { target }

/// Availability wait and target callback dispatch at 0x082bcd2c.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_wait_and_dispatch(dispatch_arg: u32) -> u32 {
    let state = state();
    if first_availability() == 0 && retail_cg_second_availability() == 0 {
        ptr::write_volatile(ptr::addr_of_mut!((*state).active), 1);
        post_mailbox();
        while first_availability() == 0 && retail_cg_second_availability() == 0 { sleep_retry(); }
        return 0;
    }
    ptr::write_volatile(ptr::addr_of_mut!((*state).active), 0);
    let status = retail_cg_dispatch_setup();
    if status != 0 { return status; }
    let target = ptr::read_volatile(ptr::addr_of!((*state).target));
    if target == 0 { return TARGET_MISSING; }
    dispatch_target(target, ptr::read_volatile(ptr::addr_of!((*state).payload)), dispatch_arg)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut FIRST: u32 = 1;
    static mut FIRST_READS: u32 = 0;
    static mut SECOND: u32 = 1;
    static mut SETUP: u32 = 0;
    unsafe extern "C" fn first() -> u32 { FIRST }
    unsafe extern "C" fn second() -> u32 { SECOND }
    unsafe extern "C" fn setup() -> u32 { SETUP }

    fn reset() {
        unsafe {
            HOST_STATE = DispatchState { active: 7, target: 0, payload: 0 };
            FIRST = 1; FIRST_READS = 0; SECOND = 1; SETUP = 0;
            CG_FIRST_AVAILABILITY = first; CG_SECOND_AVAILABILITY = second; CG_DISPATCH_SETUP = setup;
        }
    }

    #[test]
    fn returns_setup_error_after_clearing_active_mark() {
        let _guard = LOCK.lock(); reset();
        unsafe { SETUP = 0x42; assert_eq!(cg_wait_and_dispatch(9), 0x42); assert_eq!(HOST_STATE.active, 0); }
    }

    #[test]
    fn requires_target_after_successful_setup() {
        let _guard = LOCK.lock(); reset();
        unsafe { assert_eq!(cg_wait_and_dispatch(9), TARGET_MISSING); assert_eq!(HOST_STATE.active, 0); }
    }

    unsafe extern "C" fn delayed_first() -> u32 {
        FIRST_READS += 1;
        if FIRST_READS <= 2 { 0 } else { 1 }
    }

    #[test]
    fn marks_active_while_waiting_for_availability() {
        let _guard = LOCK.lock(); reset();
        unsafe {
            FIRST = 0;
            SECOND = 0;
            CG_FIRST_AVAILABILITY = delayed_first;
            assert_eq!(cg_wait_and_dispatch(0), 0);
            assert_eq!(HOST_STATE.active, 1);
        }
    }
}
