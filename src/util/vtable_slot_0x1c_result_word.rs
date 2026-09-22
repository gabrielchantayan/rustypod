//! vtable_slot_0x1c_result_word — original: `FUN_08268e34` @
//! **0x08268e34** (20 bytes, `0x08268e34..0x08268e48`).
//!
//! Raw ARM words establish a five-instruction tail dispatch: copy the object
//! pointer, load its vtable from `+0x00`, load the callback argument from
//! `+0x04`, load vtable slot `+0x1c`, then `bx` the slot. The body contains no
//! direct `bl` or `blx`; raw-image decoding finds three inbound plain `bl`
//! calls at 0x08269318, 0x082696e4, and 0x082caa64, and no predicated callers.
//!
//! # Algorithm
//!
//! Invoke the object's virtual method at vtable slot `+0x1c`, passing the
//! object's word at `+0x04`, and return that method's result word.
//!
//! # Deliberate deviations
//!
//! The concrete object and virtual method are not identified. On the target,
//! both are read as volatile 32-bit words at the verified retail offsets. Host
//! tests use native-width `#[repr(C)]` fields so callback pointers are not
//! truncated; this preserves the slot relationship rather than target byte
//! offsets on a 64-bit host.

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct VtableSlot1cObject {
    pub vtable: *const VtableSlot1c,
    pub callback_argument: *mut u8,
}

/// Recovered host representation of the vtable through slot `+0x1c`.
#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct VtableSlot1c {
    pub unresolved_00_to_18: [usize; 7],
    pub result_word: unsafe extern "C" fn(*mut u8) -> u32,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch(object: *mut u8) -> u32 {
    type Method = unsafe extern "C" fn(u32) -> u32;

    let object_words = object.cast::<u32>();
    let vtable = object_words.read_volatile() as usize as *const u32;
    let callback_argument = object_words.add(1).read_volatile();
    let method = vtable.add(7).read_volatile() as usize;
    core::mem::transmute::<usize, Method>(method)(callback_argument)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch(object: *mut u8) -> u32 {
    let object = &*object.cast::<VtableSlot1cObject>();
    ((*object.vtable).result_word)(object.callback_argument)
}

/// Tail-dispatches vtable slot `+0x1c` with the object's `+0x04` word.
///
/// # Safety
///
/// `object` must reference the recovered object layout and its vtable slot
/// `+0x1c` must be a valid function accepting the object's `+0x04` word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_slot_0x1c_result_word(object: *mut u8) -> u32 {
    dispatch(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut OBSERVED_ARGUMENT: *mut u8 = core::ptr::null_mut();
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn record_argument(argument: *mut u8) -> u32 {
        OBSERVED_ARGUMENT = argument;
        CALLS += 1;
        0x8256_8e34
    }

    #[test]
    fn dispatches_slot_seven_with_the_second_object_word() {
        let mut argument = [0xa5u8; 4];
        let vtable = VtableSlot1c {
            unresolved_00_to_18: [0; 7],
            result_word: record_argument,
        };
        let mut object = VtableSlot1cObject {
            vtable: &vtable,
            callback_argument: argument.as_mut_ptr(),
        };

        unsafe {
            OBSERVED_ARGUMENT = core::ptr::null_mut();
            CALLS = 0;
            assert_eq!(vtable_slot_0x1c_result_word(core::ptr::addr_of_mut!(object).cast()), 0x8256_8e34);
            assert_eq!(OBSERVED_ARGUMENT, argument.as_mut_ptr());
            assert_eq!(CALLS, 1);
        }
    }
}
