//! Object flag take-and-clear — `FUN_081fc620` @ `0x081fc620`.
//!
//! True extent: 24 bytes (`0x081fc620..0x081fc638`); `push {r4, r5, r6, lr}`
//! begins the next distinct function at `0x081fc638`. The six raw ARM words
//! are `ldr r3,[r0,#0x44]; mov r2,r0; and r0,r3,r1; bic r1,r3,r1;
//! str r1,[r2,#0x44]; bx lr`. Four direct callers use plain unconditional
//! `bl` (0x082077d0, 0x082078ac, 0x082078e4, and 0x08207a4c); none is
//! predicated.
//!
//! Reads the object's target-width flag word at +0x44, clears every requested
//! bit in that word, and returns the requested bits that were set. Deliberate
//! deviation: the object remains opaque and is byte-addressed so +0x44 keeps
//! its target offset on 64-bit hosts.

const FLAGS_OFFSET: usize = 0x44;

/// Clears `mask` from the +0x44 flag word of `object` and returns the bits
/// that were present before the clear.
///
/// # Safety
///
/// `object` must be valid to read and write an aligned `u32` at byte offset
/// +0x44. This is the original's unguarded access contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_flags_take(object: *mut u8, mask: u32) -> u32 {
    let flags = object.add(FLAGS_OFFSET).cast::<u32>();
    let previous = unsafe { flags.read() };
    unsafe { flags.write(previous & !mask) };
    previous & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_and_clears_requested_present_bits() {
        let mut object = [0u32; 18];
        object[17] = 0xa5a5_00f3;

        assert_eq!(unsafe { object_flags_take(object.as_mut_ptr().cast(), 0x00f0_00ff) }, 0x00a0_00f3);
        assert_eq!(object[17], 0xa505_0000);
    }

    #[test]
    fn absent_bits_return_zero_without_changing_flags() {
        let mut object = [0u32; 18];
        object[17] = 0x0000_0010;

        assert_eq!(unsafe { object_flags_take(object.as_mut_ptr().cast(), 0x8000_0001) }, 0);
        assert_eq!(object[17], 0x0000_0010);
    }

    #[test]
    fn empty_mask_preserves_all_flags() {
        let mut object = [0u32; 18];
        object[17] = 0xffff_ffff;

        assert_eq!(unsafe { object_flags_take(object.as_mut_ptr().cast(), 0) }, 0);
        assert_eq!(object[17], 0xffff_ffff);
    }
}
