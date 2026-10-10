//! File descriptor export — `FUN_0806b440` @ **0x0806b440**.
//!
//! True extent: **72 bytes**, including two literals at +0x40/+0x44;
//! the next real function starts with PUSH at 0x0806b488. Raw whole-image
//! A32 decoding finds **2 incoming plain BLs**, **0 predicated BLs**, and
//! **0 outgoing BLs**. The only outgoing call is a conditional tail B to
//! 0x080e2e20; Ghidra incorrectly incorporates that converter's body.
//!
//! Require byte +0x16 to equal one and word +0x0c to be FILE (0x46494c45)
//! or MFIL (0x4d46494c). Otherwise return -50 without touching output.
//! Accepted objects pass their tag, embedded descriptor at +0xc0, and
//! output to the stock converter, returning its status unchanged.
//! Deviations: Rust expresses wrapping tag comparisons as equality;
//! LLVM chooses the frame/tail-call form. The unported converter remains
//! a fixed-address target seam; host accepted calls require a supplied
//! converter through the private testable core, not a fake conversion.

/// ABI recovered from the raw tail branch to 0x080e2e20.
#[cfg(target_os = "none")]
type ExportDescriptor = unsafe extern "C" fn(u32, *const u8, *mut u8) -> i32;

#[inline(always)]
unsafe fn export_with(
    object: *const u8,
    output: *mut u8,
    convert: impl FnOnce(u32, *const u8, *mut u8) -> i32,
) -> i32 {
    if object.add(0x16).read() != 1 {
        return -50;
    }
    let kind = object.add(0x0c).cast::<u32>().read();
    if kind != 0x4649_4c45 && kind != 0x4d46_494c {
        return -50;
    }
    convert(kind, object.add(0xc0), output)
}

/// Export the descriptor of an initialized FILE or MFIL object.
///
/// # Safety
/// `object` must be word-aligned and readable through +0x16. On accepted
/// paths its descriptor at +0xc0 and the 516-byte writable `output` must
/// satisfy the stock converter's contracts. There is no NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn file_descriptor_export(object: *const u8, output: *mut u8) -> i32 {
    export_with(object, output, |kind, descriptor, destination| {
        #[cfg(target_os = "none")]
        {
            let convert: ExportDescriptor = core::mem::transmute(0x080e_2e20usize);
            convert(kind, descriptor, destination)
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (kind, descriptor, destination);
            panic!("stock descriptor converter 0x080e2e20 is unavailable on host")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_every_other_state_without_reading_tag_or_output() {
        for state in 0u8..=255 {
            if state == 1 { continue; }
            let mut object = [0u32; 6];
            unsafe {
                object.as_mut_ptr().cast::<u8>().add(0x16).write(state);
                assert_eq!(file_descriptor_export(object.as_ptr().cast(), core::ptr::null_mut()), -50);
            }
        }
    }

    #[test]
    fn tag_gate_matches_wrapping_arm_comparisons() {
        let tags = [0, u32::MAX, 0x4649_4c44, 0x4649_4c45, 0x4649_4c46,
                    0x4d46_494b, 0x4d46_494c, 0x4d46_494d, 0xb9b6_b3bb];
        for kind in tags {
            let mut object = [0u32; 64];
            object[3] = kind;
            let mut output = [0xa5u8; 516];
            unsafe {
                object.as_mut_ptr().cast::<u8>().add(0x16).write(1);
                let expected = kind.wrapping_add(0xb9b6_b3bb) == 0
                    || kind.wrapping_add(0xb9b6_b3bb).wrapping_add(0xf903_02f9) == 0;
                let mut accepted = false;
                let result = export_with(object.as_ptr().cast(), output.as_mut_ptr(), |_, _, _| {
                    accepted = true;
                    -108
                });
                assert_eq!(accepted, expected, "tag {kind:08x}");
                assert_eq!(result, if expected { -108 } else { -50 });
                assert_eq!(output, [0xa5; 516]);
            }
        }
    }
}
