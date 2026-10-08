//! Dispatch the receiver's current signed 16-bit value.
//!
//! retailOS `0x0812eaf4`, true size 24 bytes [0x0812eaf4,0x0812eb0c).
//! Six raw A32 words end in BX r2; the next entry starts PUSH {r4-r6,lr}.
//! Verified whole-image aligned decoding: two incoming plain BLs at
//! 0x0828b2bc and 0x0828b2c4, zero predicated BLs. Body has no BL/BLX.
//! Read the word at +0x58, sign-extend its low halfword, and tail-dispatch
//! vtable slot +0x164 with the original receiver and signed value. Callers
//! use class 0x3b80; the virtual method's concrete identity is unverified.
//!
//! Deliberate deviations: native repr(C) pointers widen on hosts while field
//! and vtable indices retain target layout. Incidental virtual return values
//! are not exposed: verified callers use this as a void operation.

#[repr(C)]
pub struct CurrentValueVtable {
    pub unresolved: [usize; 0x164 / 4],
    pub dispatch: unsafe extern "C" fn(*mut CurrentValueReceiver, i32),
}

#[repr(C)]
pub struct CurrentValueReceiver {
    pub vtable: *const CurrentValueVtable,
    pub unresolved: [u32; 21],
    pub current_value: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x58] = [(); core::mem::offset_of!(CurrentValueReceiver, current_value)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0x164] = [(); core::mem::offset_of!(CurrentValueVtable, dispatch)];

/// # Safety
/// Receiver must be readable through +0x5b and its vtable slot +0x164 must
/// hold a valid method accepting this receiver and a signed 32-bit value.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn current_value_virtual_dispatch(receiver: *mut CurrentValueReceiver) {
    let value = (*receiver).current_value as i16 as i32;
    ((*(*receiver).vtable).dispatch)(receiver, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn record(receiver: *mut CurrentValueReceiver, value: i32) {
        (*receiver).unresolved[0] += 1;
        (*receiver).unresolved[1] = value as u32;
        // A real virtual method may change the value; the next call must reload it.
        (*receiver).current_value = (*receiver).current_value.wrapping_add(1);
    }

    #[test]
    fn sign_extends_every_halfword_ignores_upper_bits_and_reloads_after_dispatch() {
        let vtable = CurrentValueVtable { unresolved: [0; 89], dispatch: record };
        let mut receiver = CurrentValueReceiver {
            vtable: &vtable, unresolved: [0x12345678; 21], current_value: 0,
        };
        for upper in [0, 0x12340000, 0xffff0000] {
            for low in 0..=u16::MAX as u32 {
                receiver.current_value = upper | low;
                receiver.unresolved[0] = 0;
                for count in 1..=2 {
                    let before = receiver.current_value;
                    unsafe { current_value_virtual_dispatch(&mut receiver); }
                    assert_eq!(receiver.unresolved[0], count);
                    assert_eq!(receiver.unresolved[1] as i32,
                        if before & 0x8000 == 0 { (before & 0xffff) as i32 }
                        else { (before & 0xffff) as i32 - 65536 });
                    assert_eq!(receiver.current_value, before.wrapping_add(1));
                    assert_eq!(&receiver.unresolved[2..], &[0x12345678; 19]);
                    assert_eq!(receiver.vtable, &vtable as *const _);
                }
            }
        }
    }
}
