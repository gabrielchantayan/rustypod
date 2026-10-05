//! Voice-memo decimal split — `FUN_081a4554` @ **0x081a4554**.
//!
//! True extent: **36 bytes**, 0x081a4554..0x081a4578; the next function
//! starts with push {r4,r5,r6,lr}. Raw aligned A32 decoding finds two
//! inbound plain BLs (0x081a342c, 0x081a3458), zero predicated inbound BLs,
//! and one outgoing plain BL to __rt_udiv @ 0x08036f14, no predicated BLs.
//!
//! Ignore the controller, divide the unsigned value by ten, and write the
//! low quotient byte before the remainder byte. The voice-memo caller uses
//! these bytes to select decimal digit images for calendar fields. Values
//! above 255 remain full-width inputs; the quotient store truncates to u8.
//!
//! Deviation: reuse __rt_udivmod's explicit remainder output instead of the
//! original pre-EABI r1 result, requiring a local u32 remainder slot.

use crate::runtime::rt_div::__rt_udivmod;

/// # Safety
/// Both outputs must be writable for one byte. They may alias; in that case
/// the remainder overwrites the quotient. The controller is never accessed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn voice_memo_decimal_split(
    _controller: *mut u8, value: u32, quotient: *mut u8, remainder: *mut u8,
) {
    let mut rem = 0;
    let quot = __rt_udivmod(value, 10, &mut rem);
    quotient.write(quot as u8);
    remainder.write(rem as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_inputs_and_full_width_boundaries() {
        let check = |value| {
            let mut out = [0xa5u8; 6];
            unsafe {
                voice_memo_decimal_split(core::ptr::null_mut(), value,
                    out.as_mut_ptr().add(1), out.as_mut_ptr().add(4));
            }
            assert_eq!(out, [0xa5, (value / 10) as u8, 0xa5, 0xa5,
                (value % 10) as u8, 0xa5], "value={value}");
        };
        for value in 0..=255 { check(value); }
        for value in [256, 2559, 2560, 2561, 65535, 0x8000_0000, u32::MAX] {
            check(value);
        }
    }

    #[test]
    fn aliased_outputs_leave_remainder() {
        for value in [0, 9, 10, 99, 255, 2560, u32::MAX] {
            let mut out = [0xa5u8; 3];
            let slot = unsafe { out.as_mut_ptr().add(1) };
            unsafe { voice_memo_decimal_split(core::ptr::null_mut(), value, slot, slot); }
            assert_eq!(out, [0xa5, (value % 10) as u8, 0xa5]);
        }
    }
}
