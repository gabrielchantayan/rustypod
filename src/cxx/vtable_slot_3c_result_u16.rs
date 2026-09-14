//! Virtual slot-`+0x3c` low-16-bit result wrapper.
//!
//! `vtable_slot_3c_result_u16` — original: `FUN_083d611c` @ **0x083d611c**
//! (28 bytes). Raw ARM establishes the exact extent from `push {r3,lr}` at
//! `0x083d611c` through `pop {ip,pc}` at `0x083d6134`; the independently
//! linked successor begins at `0x083d6138`.
//!
//! Decoding every aligned immediate ARM `B`/`BL` word in `osos.dec` finds
//! exactly five inbound direct calls, all unconditional plain `bl` at
//! `0x0813edac`, `0x0813edd8`, `0x081d16b4`, `0x081deb08`, and `0x081deb34`.
//! There are no predicated call forms or direct tail branches. The wrapper
//! invokes an indirect `blx` through vtable word 15 (`+0x3c`).
//!
//! # Algorithm
//!
//! Saves incoming `r3` as an initialized u32 result cell, invokes
//! `receiver.vtable[15](receiver, index, &mut result)`, then returns the low
//! 16 bits of that cell. Incoming `r2` is discarded when it is replaced with
//! the result-cell pointer. Receiver, vtable, and callback have no NULL
//! guards. The concrete virtual method identity is unrecovered and
//! deliberately not invented.
//!
//! # Deliberate deviation
//!
//! Target vtable entries are 32-bit words, while host function pointers are
//! wider. Rust therefore selects word index 15 in a host-sized vtable and
//! performs the equivalent typed callback call.

/// ARMv5TE vtable word index for byte offset `+0x3c`.
const RESULT_U16_SLOT: usize = 0x3c / 4;

/// ABI of the unrecovered virtual method in vtable slot `+0x3c`.
pub type VtableSlot3cResultU16 = unsafe extern "C" fn(*mut u8, u32, *mut u32);

/// Calls vtable slot `+0x3c` and returns the low 16 bits of its result cell.
///
/// # Safety
///
/// `receiver` must be readable and contain a readable vtable pointer whose
/// word-15 entry is a valid [`VtableSlot3cResultU16`]. The callback must
/// accept `receiver`, `index`, and the writable result cell. No pointer is
/// validated, matching retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_slot_3c_result_u16(
    receiver: *mut u8,
    index: u32,
    _discarded_r2: u32,
    initial_result: u32,
) -> u32 {
    let vtable = unsafe { (receiver as *const *const usize).read() };
    let entry = unsafe { vtable.add(RESULT_U16_SLOT).read() };
    let method: VtableSlot3cResultU16 = unsafe { core::mem::transmute(entry) };
    let mut result = initial_result;
    unsafe { method(receiver, index, &mut result) };
    result as u16 as u32
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static DISPATCH_LOCK: Mutex<()> = Mutex::new(());
    static mut FORWARDED_RECEIVER: usize = 0;
    static mut FORWARDED_INDEX: u32 = 0;
    static mut INITIAL_RESULT: u32 = 0;
    static mut WRONG_SLOT_CALLS: u32 = 0;

    unsafe extern "C" fn result_method(receiver: *mut u8, index: u32, result: *mut u32) {
        unsafe {
            FORWARDED_RECEIVER = receiver as usize;
            FORWARDED_INDEX = index;
            INITIAL_RESULT = result.read();
            result.write(0x5a3c_7e19);
        }
    }

    unsafe extern "C" fn wrong_slot(_receiver: *mut u8, _index: u32, _result: *mut u32) {
        unsafe {
            WRONG_SLOT_CALLS += 1;
        }
    }

    unsafe extern "C" fn leave_result_unchanged(
        _receiver: *mut u8,
        _index: u32,
        _result: *mut u32,
    ) {
    }

    /// An object with exactly the wrapper's required vtable field.
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
            FORWARDED_INDEX = 0;
            INITIAL_RESULT = 0;
            WRONG_SLOT_CALLS = 0;
        }
        Bench { _lock: lock }
    }

    #[test]
    fn forwards_receiver_index_and_initialized_result_cell() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; RESULT_U16_SLOT + 1];
        vtable[RESULT_U16_SLOT] = result_method as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let receiver = (&mut object as *mut VtableObject).cast::<u8>();

        let result = unsafe {
            vtable_slot_3c_result_u16(receiver, u32::MAX, 0xdead_beef, 0x2468_ace0)
        };

        assert_eq!(unsafe { FORWARDED_RECEIVER }, receiver as usize);
        assert_eq!(unsafe { FORWARDED_INDEX }, u32::MAX);
        assert_eq!(unsafe { INITIAL_RESULT }, 0x2468_ace0);
        assert_eq!(result, 0x7e19);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x3c dispatches");
    }

    #[test]
    fn returns_the_seeded_low_u16_when_callback_leaves_cell_unchanged() {
        let _bench = bench();
        let mut vtable = [wrong_slot as usize; RESULT_U16_SLOT + 1];
        vtable[RESULT_U16_SLOT] = leave_result_unchanged as usize;
        let mut object = VtableObject { vtable: vtable.as_ptr() };
        let receiver = (&mut object as *mut VtableObject).cast::<u8>();

        let result = unsafe {
            vtable_slot_3c_result_u16(receiver, 7, 0xdead_beef, 0xface_1234)
        };

        assert_eq!(result, 0x1234);
        assert_eq!(unsafe { WRONG_SLOT_CALLS }, 0, "only vtable slot +0x3c dispatches");
    }
}
