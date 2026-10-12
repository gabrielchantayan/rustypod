//! Owned-buffer descriptor value — `FUN_0803a24c` @ `0x0803a24c` (12 bytes).
//!
//! Raw words `e59f0000 ea000484 0890619c` load descriptor 0x0890619c
//! into r0 and tail-branch to the existing parameter_descriptor_value at
//! 0x0803b468. True extent is [0x0803a24c,0x0803a258), including the literal;
//! the successor is an independent B veneer. Whole-image ARM word decoding
//! finds two plain incoming BLs (0x0808897c, 0x082d43a8), zero predicated
//! BLs, and no outgoing BLs. Callers populate the returned owned buffer via
//! owned_buffer_assign. Preserve incoming r1/r2 and the live r3 context.
//! No behavioral deviations; host tests reuse the existing resolver seam.

use super::parameter_descriptor_value::parameter_descriptor_value;

/// Resolves the retail owned-buffer descriptor, returning zero on failure.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owned_buffer_descriptor_value(
    _incoming_descriptor: *const u8,
    incoming_r1: u32,
    incoming_r2: u32,
    opaque_context: u32,
) -> u32 {
    parameter_descriptor_value(
        0x0890_619c as *const u8,
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
        // A positive resolver may succeed without storing an output.
        if context != 2 { out.write(0xffff_fffc); }
        context as i32
    }

    struct Restore(ParameterDescriptorValueOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { PARAMETER_DESCRIPTOR_VALUE_OPS = self.0; }
        }
    }

    #[test]
    fn signed_failure_discards_output_and_unwritten_success_is_zero() {
        let _lock = PARAMETER_DESCRIPTOR_VALUE_OPS_LOCK.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let _restore = Restore(core::ptr::read_volatile(
                core::ptr::addr_of!(PARAMETER_DESCRIPTOR_VALUE_OPS),
            ));
            PARAMETER_DESCRIPTOR_VALUE_OPS = ParameterDescriptorValueOps { resolve };
            for (status, expected) in [
                (i32::MIN, 0), (-1, 0), (0, 0), (1, 0xffff_fffc),
                (2, 0), (i32::MAX, 0xffff_fffc),
            ] {
                assert_eq!(owned_buffer_descriptor_value(
                    core::ptr::null(), 0, 0, status as u32,
                ), expected, "status {status}");
            }
        }
    }
}
