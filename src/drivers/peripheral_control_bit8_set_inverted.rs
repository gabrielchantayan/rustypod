//! Inverted boolean update of peripheral control bit 8.
//!
//! Original: `FUN_080a63b8` @ `0x080a63b8`, true extent 36 bytes:
//! 32 instruction bytes and the register-base literal at 0x080a63d8.
//! The next real function begins at 0x080a63dc (MOV followed by tail B).
//! Whole-image aligned ARM-word decoding verifies two plain inbound BLs
//! (0x0814ec68, 0x0814f760), zero predicated inbound BLs, and no outgoing
//! BLs of either kind. Read 0x38900008, clear bit 8, set it only when the
//! argument is zero, write the word back, and return zero. All other bits
//! are preserved. The peripheral and bit's hardware meaning are unidentified.
//!
//! Deliberate deviations: volatile word accesses express MMIO semantics;
//! host builds substitute isolated register storage. No callee seams.

use core::ptr;

#[cfg(not(target_os = "none"))]
static mut HOST_REGISTERS: [u32; 4] = [0; 4];

#[inline(always)]
fn control() -> *mut u32 {
    #[cfg(target_os = "none")]
    { 0x3890_0008 as *mut u32 }
    #[cfg(not(target_os = "none"))]
    { unsafe { ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>().add(2) } }
}

/// Set control bit 8 for zero; clear it for every nonzero input.
///
/// # Safety
/// The MMIO register must be accessible and updates must be serialized.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn peripheral_control_bit8_set_inverted(value: u32) -> u32 {
    let register = control();
    let mut word = ptr::read_volatile(register) & !0x100;
    if value == 0 {
        word |= 0x100;
    }
    ptr::write_volatile(register, word);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_other_bits_across_zero_nonzero_transitions() {
        unsafe {
            let base = ptr::addr_of_mut!(HOST_REGISTERS).cast::<u32>();
            for initial in [0, 0x100, u32::MAX, 0xffff_feff, 0xa55a_1234] {
                base.write(0x1234_5678);
                base.add(1).write(0x8765_4321);
                base.add(2).write(initial);
                base.add(3).write(0xdead_beef);
                for input in [0, 0, 1, 1, 0, 2, 0x100, 0x8000_0000, u32::MAX, 0] {
                    assert_eq!(peripheral_control_bit8_set_inverted(input), 0);
                    let expected = if input == 0 { initial | 0x100 } else { initial & !0x100 };
                    assert_eq!(base.add(2).read(), expected);
                    assert_eq!(base.read(), 0x1234_5678);
                    assert_eq!(base.add(1).read(), 0x8765_4321);
                    assert_eq!(base.add(3).read(), 0xdead_beef);
                }
            }
        }
    }
}
