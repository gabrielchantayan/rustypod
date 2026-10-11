//! Opaque parameter-descriptor value — `FUN_080604ac` @ `0x080604ac` (12 bytes).
//!
//! Raw words are `e59f0000 eaff6bec 0890b608`: load r0 with the descriptor
//! address, then tail-branch to `parameter_descriptor_value` at `0x0803b468`.
//! The next function begins at `0x080604b8` with `e92d4038`; Ghidra's eight
//! bytes omit the literal. Whole-image ARM decoding finds two inbound plain
//! BLs at `0x0805fa08` and `0x082d4270`, zero predicated BLs. The body has
//! no BLs. Callers treat the result as an allocation, but its concrete type
//! is unknown. Preserve r1/r2 and the live r3 resolver context. No deliberate
//! behavioral deviations; host tests use the existing resolver seam.

use super::parameter_descriptor_value::parameter_descriptor_value;

/// Resolves the opaque descriptor shared with the retail allocation releaser.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_parameter_descriptor_value(
    _incoming_descriptor: *const u8,
    incoming_r1: u32,
    incoming_r2: u32,
    opaque_context: u32,
) -> u32 {
    parameter_descriptor_value(
        0x0890_b608 as *const u8,
        incoming_r1,
        incoming_r2,
        opaque_context,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::parameter_descriptor_value::{
        ParameterDescriptorValueOps, PARAMETER_DESCRIPTOR_VALUE_OPS,
        PARAMETER_DESCRIPTOR_VALUE_OPS_LOCK,
    };

    unsafe extern "C" fn resolve(
        out: *mut u32,
        _descriptor: *const u8,
        _callback: *const u8,
        context: u32,
    ) -> i32 {
        // Leave the initialized output untouched for the positive/no-store case.
        if context != 2 { out.write(u32::MAX); }
        context as i32
    }

    struct Restore(ParameterDescriptorValueOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { PARAMETER_DESCRIPTOR_VALUE_OPS = self.0; }
        }
    }

    #[test]
    fn signed_status_and_unwritten_output_boundaries() {
        let _lock = PARAMETER_DESCRIPTOR_VALUE_OPS_LOCK.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let _restore = Restore(core::ptr::read_volatile(
                core::ptr::addr_of!(PARAMETER_DESCRIPTOR_VALUE_OPS),
            ));
            PARAMETER_DESCRIPTOR_VALUE_OPS = ParameterDescriptorValueOps { resolve };
            for (status, expected) in [
                (i32::MIN, 0), (-1, 0), (0, 0), (1, u32::MAX),
                (2, 0), (i32::MAX, u32::MAX),
            ] {
                assert_eq!(opaque_parameter_descriptor_value(
                    core::ptr::null(), 0, 0, status as u32,
                ), expected, "status {status}");
            }
        }
    }
}
