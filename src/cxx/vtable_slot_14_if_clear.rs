//! Conditional virtual slot-`+0x14` dispatcher.
//!
//! `vtable_slot_14_if_clear` — original: `FUN_08135760` @ **0x08135760**
//! (28 bytes). Raw ARM establishes the exact extent from `ldrb r2,[r0,#4]`
//! at `0x08135760` through `bx lr` at `0x08135778`; the separately linked
//! next function begins at `0x0813577c`.
//!
//! Decoding every immediate ARM `B`/`BL` word in `osos.dec` finds six inbound
//! direct `bl` calls, all unconditional, at `0x0810325c`, `0x08147fd4`,
//! `0x08148094`, `0x081a7788`, `0x0820b150`, and `0x0820b18c`. A separate
//! predicated `bne` tail branch at `0x081b68f0` reaches this entry when its
//! wrapper's selected receiver is non-null. There are no aligned raw data-word
//! references to this entry.
//!
//! # Algorithm
//!
//! Reads the receiver byte at `+0x04`. If it is zero, invokes vtable slot
//! `+0x14` as `(receiver, output)` and returns that callback's result. Any
//! nonzero byte returns zero without accessing the vtable or output. The
//! receiver, vtable, and callback have no NULL guards on the dispatching path.
//! Firmware callers use `output` as a low-16-bit result cell; the concrete
//! virtual method identity is unrecovered and deliberately not invented.
//!
//! # Deliberate deviation
//!
//! ARM vtable entries are four-byte words, while host function pointers are
//! pointer-width. The Rust vtable therefore selects word index five from
//! typed host callback cells. Rust represents the ARM `bxeq` terminal branch
//! as a typed callback call.

/// ARMv5TE vtable word index for byte offset `+0x14`.
const CONDITIONAL_DISPATCH_SLOT: usize = 0x14 / 4;

/// ABI of the unrecovered callback at receiver vtable slot `+0x14`.
pub type VtableSlot14U16 = unsafe extern "C" fn(*mut VtableSlot14Receiver, *mut u16) -> u32;

/// Receiver prefix consumed by [`vtable_slot_14_if_clear`].
///
/// On ARM, the vtable word occupies `+0x00` and `dispatch_suppressed` is the
/// byte at `+0x04`. The native-width vtable pointer intentionally stays
/// pointer-width on hosts so callback pointers remain valid.
#[repr(C)]
pub struct VtableSlot14Receiver {
    pub vtable: *const VtableSlot14U16,
    pub dispatch_suppressed: u8,
    pub unresolved_05_07: [u8; 3],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x00] = [0; core::mem::offset_of!(VtableSlot14Receiver, vtable)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(VtableSlot14Receiver, dispatch_suppressed)];

/// Invokes the receiver's `+0x14` vtable slot only while its flag byte is zero.
///
/// # Safety
///
/// When `dispatch_suppressed` is zero, `receiver` must be non-NULL and point
/// to a readable [`VtableSlot14Receiver`] with a valid vtable slot five; the
/// callback must accept `receiver` and `output`. As in the firmware, neither
/// pointer is validated on that path.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_14_if_clear(
    receiver: *mut VtableSlot14Receiver,
    output: *mut u16,
) -> u32 {
    if unsafe { (*receiver).dispatch_suppressed } != 0 {
        return 0;
    }

    let callback = unsafe { (*receiver).vtable.add(CONDITIONAL_DISPATCH_SLOT).read() };
    unsafe { callback(receiver, output) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_RECEIVER: usize = 0;
    static mut FORWARDED_OUTPUT: usize = 0;
    static mut DISPATCH_CALLS: usize = 0;
    static mut WRONG_SLOT_CALLS: usize = 0;

    unsafe extern "C" fn wrong_slot(_receiver: *mut VtableSlot14Receiver, _output: *mut u16) -> u32 {
        unsafe { WRONG_SLOT_CALLS += 1 };
        0
    }

    unsafe extern "C" fn record_dispatch(receiver: *mut VtableSlot14Receiver, output: *mut u16) -> u32 {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            FORWARDED_OUTPUT = output as usize;
            DISPATCH_CALLS += 1;
            output.write(0x1234);
        }
        0xa5a5_5a5a
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    fn bench() -> Bench {
        let lock = DISPATCH_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FORWARDED_RECEIVER = 0;
            FORWARDED_OUTPUT = 0;
            DISPATCH_CALLS = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn clear_flag_dispatches_only_slot_14_and_forwards_both_arguments() {
        let _bench = bench();
        let mut vtable = [wrong_slot as VtableSlot14U16; CONDITIONAL_DISPATCH_SLOT + 1];
        vtable[CONDITIONAL_DISPATCH_SLOT] = record_dispatch;
        let mut receiver = VtableSlot14Receiver {
            vtable: vtable.as_ptr(),
            dispatch_suppressed: 0,
            unresolved_05_07: [0xa5; 3],
        };
        let mut output = 0xffff;

        assert_eq!(unsafe { vtable_slot_14_if_clear(&mut receiver, &mut output) }, 0xa5a5_5a5a);
        assert_eq!(unsafe { FORWARDED_RECEIVER }, (&mut receiver as *mut VtableSlot14Receiver) as usize);
        assert_eq!(unsafe { FORWARDED_OUTPUT }, (&mut output as *mut u16) as usize);
        assert_eq!(output, 0x1234);
        assert_eq!(unsafe { DISPATCH_CALLS }, 1);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x14 dispatches");
    }

    #[test]
    fn nonzero_flag_returns_zero_without_reading_vtable_or_output() {
        let _bench = bench();
        let mut receiver = VtableSlot14Receiver {
            vtable: core::ptr::null(),
            dispatch_suppressed: u8::MAX,
            unresolved_05_07: [0; 3],
        };

        assert_eq!(unsafe { vtable_slot_14_if_clear(&mut receiver, core::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { DISPATCH_CALLS }, 0);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0);
    }
}
