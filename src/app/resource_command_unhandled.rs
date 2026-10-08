//! Unhandled resource command — `FUN_081438e0` @ 0x081438e0.
//!
//! True extent [0x081438e0, 0x081438e8), 8 bytes: raw A32 words
//! e3a00000 / e12fff1e (`mov r0, #0; bx lr`). The next independent
//! constant-zero leaf starts at 0x081438e8, not Ghidra's next listed entry.
//! Verified incoming calls: two plain BLs (0x0815a794, 0x081b2164), zero
//! predicated BLs. Outgoing calls: zero plain or predicated BLs.
//! Both callers pass object/resource/command/value in r0..r3 and an output
//! pointer on the stack when falling back from their handled commands.
//! Return zero (unhandled), ignoring all arguments and leaving output intact.
//! No callee seams or deliberate behavioral deviations. ARM match review
//! confirms the exported symbol: LLVM adds `push {fp, lr}; mov fp, sp` and
//! returns with `pop {fp, pc}` around the original `mov r0, #0`.

use core::ffi::c_void;

/// Reject a resource command without accessing the object or output pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn resource_command_unhandled(
    _object: *mut c_void,
    _resource: u32,
    _command: u32,
    _value: u32,
    _output: *mut u32,
) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unhandled_commands_preserve_output_and_object() {
        let mut object = [0xa5a5_a5a5u32; 4];
        let mut output = [0x1234_5678u32, 0xffff_ffff, 0x8765_4321];
        for resource in [0, 1, 0x8000_0000, u32::MAX] {
            for command in [0, 27999, 0x8000_0000, u32::MAX] {
                assert_eq!(resource_command_unhandled(
                    object.as_mut_ptr().cast(), resource, command, u32::MAX,
                    &mut output[1],
                ), 0);
                assert_eq!(object, [0xa5a5_a5a5; 4]);
                assert_eq!(output, [0x1234_5678, 0xffff_ffff, 0x8765_4321]);
            }
        }
    }

    #[test]
    fn ignored_pointers_need_not_be_valid_or_aligned() {
        for address in [0usize, 1, usize::MAX] {
            assert_eq!(resource_command_unhandled(
                address as *mut c_void, u32::MAX, 0, 0,
                address as *mut u32,
            ), 0);
        }
    }
}
