//! Virtual slot-`+0x0c` tail dispatcher.
//!
//! `vtable_slot_12_tail_dispatch` — original: `FUN_08276fd4` @ **0x08276fd4**
//! (12 bytes). Raw ARM establishes the exact extent: `ldr r1, [r0]`, `ldr r1,
//! [r1, #0x0c]`, `bx r1`; the independently linked next function starts at
//! `0x08276fe0`.
//!
//! Decoding every immediate `B`/`BL` word in `osos.dec` finds exactly six
//! inbound direct calls, all unconditional `bl` at `0x081f79fc`, `0x081f8208`,
//! `0x081f826c`, `0x081f8384`, `0x081f9410`, and `0x081fa18c`. There are no
//! predicated `bl` forms or direct tail branches, and no aligned raw data word
//! references this dispatcher.
//!
//! # Algorithm
//!
//! Loads `receiver.vtable[3]` and tail-dispatches it with `receiver` still in
//! `r0`. The receiver, vtable, and slot are deliberately unchecked; invalid
//! pointers retain the firmware fault or invalid-branch behavior.
//!
//! # Deliberate deviation
//!
//! The ARM vtable has four-byte entries; host callback pointers are wider.
//! The host representation selects word index three from pointer-width cells.
//! Rust expresses the terminal `bx` as a final typed call; the virtual method's
//! concrete identity is not recovered or invented.

/// ARMv5TE vtable word index for byte offset `+0x0c`.
const TAIL_DISPATCH_SLOT: usize = 0x0c / 4;

/// ABI of the unrecovered virtual method in vtable slot `+0x0c`.
type VtableSlot12 = unsafe extern "C" fn(*mut u8);

/// Tail-dispatches the receiver's vtable slot `+0x0c`.
///
/// # Safety
///
/// `receiver` must contain a readable vtable pointer with a valid slot-three
/// [`VtableSlot12`] entry. The retail wrapper performs no NULL checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_slot_12_tail_dispatch")]
pub unsafe extern "C" fn vtable_slot_12_tail_dispatch(receiver: *mut u8) {
    let vtable = unsafe { (receiver as *const *const usize).read() };
    let entry = unsafe { vtable.add(TAIL_DISPATCH_SLOT).read() };
    let dispatch: VtableSlot12 = unsafe { core::mem::transmute(entry) };
    unsafe { dispatch(receiver) };
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

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8) {
        unsafe { WRONG_SLOT_CALLS += 1 };
    }

    unsafe extern "C" fn record_dispatch(receiver: *mut u8) {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            DISPATCH_CALLS += 1;
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
            FORWARDED_RECEIVER = 0;
            DISPATCH_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn dispatches_only_vtable_slot_0x0c_and_forwards_receiver() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; TAIL_DISPATCH_SLOT + 1];
        vtable[TAIL_DISPATCH_SLOT] = record_dispatch as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let receiver = (&mut object as *mut VtableObject).cast::<u8>();

        unsafe { vtable_slot_12_tail_dispatch(receiver) };

        assert_eq!(unsafe { FORWARDED_RECEIVER }, receiver as usize);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only slot +0x0c dispatches");
    }
}
