//! `vtable_slot_1c_then_slot_08_dispatch` — original `FUN_0827c240` @
//! **0x0827c240** (32 bytes).
//!
//! Raw `osos.dec` establishes the exact A32 extent `0x0827c240..0x0827c25f`:
//! `push {r4,lr}`, indirect `blx` through `receiver.vtable[7]`, then a tail
//! `bx` through the returned object's `vtable[2]`. The next separately linked
//! function begins at `0x0827c260`. Complete aligned A32 B/BL decoding finds
//! three inbound plain `bl` callers (0x08159bec, 0x08159bf4, 0x08159bfc) and
//! no predicated BL callers.
//!
//! # Algorithm
//!
//! Invoke vtable slot `+0x1c` with `receiver`, then invoke slot `+0x08` on the
//! returned object. Both virtual methods have only the observed `r0` ABI.
//!
//! # Deliberate deviations
//!
//! ARM vtable entries are four-byte words while host function pointers are
//! wider, so host tests use pointer-width cells. The virtual method identities
//! are unrecovered and deliberately not invented. Rust represents the terminal
//! `bx` as a final typed call.

const FIRST_DISPATCH_SLOT: usize = 0x1c / 4;
const SECOND_DISPATCH_SLOT: usize = 0x08 / 4;

type FirstDispatch = unsafe extern "C" fn(*mut u8) -> *mut u8;
type SecondDispatch = unsafe extern "C" fn(*mut u8);

/// Dispatches vtable slot `+0x1c`, then slot `+0x08` of its returned object.
///
/// # Safety
///
/// `receiver` and the object returned by its first virtual method must each
/// contain readable vtable pointers and valid entries at the stated slots.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_slot_1c_then_slot_08_dispatch")]
pub unsafe extern "C" fn vtable_slot_1c_then_slot_08_dispatch(receiver: *mut u8) {
    let first_vtable = unsafe { (receiver as *const *const usize).read() };
    let first_entry = unsafe { first_vtable.add(FIRST_DISPATCH_SLOT).read() };
    let first_dispatch: FirstDispatch = unsafe { core::mem::transmute(first_entry) };
    let returned = unsafe { first_dispatch(receiver) };
    let second_vtable = unsafe { (returned as *const *const usize).read() };
    let second_entry = unsafe { second_vtable.add(SECOND_DISPATCH_SLOT).read() };
    let second_dispatch: SecondDispatch = unsafe { core::mem::transmute(second_entry) };
    unsafe { second_dispatch(returned) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FIRST_RECEIVER: usize = 0;
    static mut SECOND_RECEIVER: usize = 0;
    static mut FIRST_CALLS: u32 = 0;
    static mut SECOND_CALLS: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;
    static mut RETURNED_OBJECT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn wrong_first(_receiver: *mut u8) -> *mut u8 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        core::ptr::null_mut()
    }

    unsafe extern "C" fn wrong_second(_receiver: *mut u8) {
        unsafe { WRONG_SLOT_CALLS += 1 };
    }

    unsafe extern "C" fn first_dispatch(receiver: *mut u8) -> *mut u8 {
        unsafe {
            FIRST_RECEIVER = receiver as usize;
            FIRST_CALLS += 1;
            RETURNED_OBJECT
        }
    }

    unsafe extern "C" fn second_dispatch(receiver: *mut u8) {
        unsafe {
            SECOND_RECEIVER = receiver as usize;
            SECOND_CALLS += 1;
        }
    }

    #[repr(C)]
    struct VtableObject {
        vtable: *const usize,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FIRST_RECEIVER = 0;
            SECOND_RECEIVER = 0;
            FIRST_CALLS = 0;
            SECOND_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
            RETURNED_OBJECT = core::ptr::null_mut();
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_the_two_observed_slots_and_forwards_the_returned_object() {
        let _bench = bench();
        let mut first_vtable = [wrong_first as usize; FIRST_DISPATCH_SLOT + 1];
        first_vtable[FIRST_DISPATCH_SLOT] = first_dispatch as usize;
        let mut second_vtable = [wrong_second as usize; SECOND_DISPATCH_SLOT + 1];
        second_vtable[SECOND_DISPATCH_SLOT] = second_dispatch as usize;
        let mut receiver = VtableObject { vtable: first_vtable.as_ptr() };
        let mut returned = VtableObject { vtable: second_vtable.as_ptr() };
        unsafe { RETURNED_OBJECT = (&mut returned as *mut VtableObject).cast() };
        let receiver_ptr = (&mut receiver as *mut VtableObject).cast();

        unsafe { vtable_slot_1c_then_slot_08_dispatch(receiver_ptr) };

        assert_eq!(unsafe { FIRST_RECEIVER }, receiver_ptr as usize);
        assert_eq!(unsafe { SECOND_RECEIVER }, unsafe { RETURNED_OBJECT } as usize);
        assert_eq!(unsafe { FIRST_CALLS }, 1);
        assert_eq!(unsafe { SECOND_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only slots +0x1c and +0x08 dispatch");
    }
}
