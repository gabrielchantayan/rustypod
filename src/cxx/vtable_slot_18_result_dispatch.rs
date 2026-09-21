//! Virtual slot-`+0x18` result dispatcher.
//!
//! `vtable_slot_18_result_dispatch` — original: `FUN_082a7638` @ **0x082a7638**
//! (24 bytes). Raw `osos.dec` words establish the six-instruction A32 body:
//! `push {r4,lr}; ldr r1,[r0]; add lr,pc,#4; ldr r1,[r1,#0x18]; mov pc,r1;
//! pop {r4,pc}`. The preceding function ends at `0x082a7634`; the next real
//! function begins at `0x082a7650`.
//! Complete aligned A32 branch decoding finds exactly three inbound plain `bl`
//! instructions (at `0x083d8ddc`, `0x083d8f24`, and `0x083d9240`) and no
//! predicated `bl` instructions. There are no direct outbound calls: the
//! wrapper invokes the unrecovered virtual method from vtable slot `+0x18`.
//!
//! # Algorithm
//!
//! Calls `receiver.vtable[6]` with `receiver` in `r0`, then returns that
//! method's `r0` result. The synthetic `lr` followed by `pop {pc}` makes this
//! an indirect call rather than a tail dispatch. The receiver, vtable, and
//! entry remain unchecked, matching the firmware fault behavior.
//!
//! # Deliberate deviation
//!
//! ARM vtable cells are four bytes, while host function pointers are wider;
//! host fixtures therefore select word index six from pointer-width cells.
//! Rust expresses the indirect branch and return trampoline as a typed call.
//! The virtual method's concrete identity is not recovered or invented.

/// ARMv5TE vtable word index for byte offset `+0x18`.
const RESULT_DISPATCH_SLOT: usize = 0x18 / 4;

/// ABI of the unrecovered virtual method in vtable slot `+0x18`.
type VtableSlot18Result = unsafe extern "C" fn(*mut u8) -> i32;

/// Calls vtable slot `+0x18` and returns its result.
///
/// # Safety
///
/// `receiver` must contain a readable vtable pointer with a valid slot-six
/// [`VtableSlot18Result`] entry. The retail wrapper performs no NULL checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_slot_18_result_dispatch")]
pub unsafe extern "C" fn vtable_slot_18_result_dispatch(receiver: *mut u8) -> i32 {
    let vtable = unsafe { (receiver as *const *const usize).read() };
    let entry = unsafe { vtable.add(RESULT_DISPATCH_SLOT).read() };
    let dispatch: VtableSlot18Result = unsafe { core::mem::transmute(entry) };
    unsafe { dispatch(receiver) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_RECEIVER: usize = 0;
    static mut DISPATCH_CALLS: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8) -> i32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        -99
    }

    unsafe extern "C" fn record_dispatch(receiver: *mut u8) -> i32 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            DISPATCH_CALLS += 1;
        }
        -7
    }

    #[repr(C)]
    struct VtableObject {
        vtable: *const usize,
        payload: u32,
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_RECEIVER = 0;
            DISPATCH_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_only_slot_0x18_forwards_receiver_and_returns_its_result() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; RESULT_DISPATCH_SLOT + 1];
        vtable[RESULT_DISPATCH_SLOT] = record_dispatch as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr(), payload: 0xa5a5_5a5a };
        let receiver = (&mut object as *mut VtableObject).cast::<u8>();

        let result = unsafe { vtable_slot_18_result_dispatch(receiver) };

        assert_eq!(result, -7);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, receiver as usize);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only slot +0x18 dispatches");
    }
}
