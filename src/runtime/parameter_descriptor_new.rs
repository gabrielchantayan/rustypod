//! Parameter descriptor initialization — `FUN_0803b39c` @ `0x0803b39c`.
//!
//! True extent `0x0803b39c..0x0803b3a4`: 8 bytes, ending at an independent
//! PUSH entry. Words `e3a02000 ea0261b4` clear r2 and tail-branch to the
//! unported parameter descriptor resolver at `0x080d3a78`. Whole-image ARM
//! word decoding finds two plain inbound BLs (0x0803ac64, 0x0803adfc), zero
//! predicated BLs; the adapter itself contains no BL, only one tail B.
//! The resolver's zero mode initializes the output before descriptor dispatch.
//! Preserve the caller's live r3 context and the resolver's signed status.
//! Deliberate deviations: an absolute Rust function pointer replaces the B;
//! host tests reuse the existing parameter_descriptor_value resolver seam.

/// Initialize a descriptor value in zero mode, returning the exact status.
///
/// # Safety
/// Output and descriptor must satisfy the retail resolver's contract, including
/// any descriptor-specific callback and allocation requirements. Context is the
/// incoming r3 value; incoming r2 is ignored, not moved into r3.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parameter_descriptor_new(
    output: *mut u32,
    descriptor: *const u8,
    _incoming_r2: u32,
    context: u32,
) -> i32 {
    #[cfg(not(test))]
    let resolve: unsafe extern "C" fn(*mut u32, *const u8, *const u8, u32) -> i32 =
        core::mem::transmute(0x080d_3a78usize);
    #[cfg(test)]
    let resolve = core::ptr::read_volatile(core::ptr::addr_of!(
        super::parameter_descriptor_value::PARAMETER_DESCRIPTOR_VALUE_OPS
    )).resolve;
    resolve(output, descriptor, core::ptr::null(), context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::parameter_descriptor_value::{
        PARAMETER_DESCRIPTOR_VALUE_OPS, PARAMETER_DESCRIPTOR_VALUE_OPS_LOCK,
        ParameterDescriptorValueOps,
    };

    // Rejecting initialization callbacks can return any signed status; the
    // adapter must not normalize that result like parameter_descriptor_value.
    unsafe extern "C" fn rejecting_resolver(
        output: *mut u32, descriptor: *const u8, mode: *const u8, context: u32,
    ) -> i32 {
        assert!(mode.is_null());
        output.write(0);
        assert_eq!(context, 0x89ab_cdef);
        (descriptor as *const i32).read()
    }

    #[test]
    fn initialization_keeps_zero_and_negative_statuses_distinct() {
        let _lock = PARAMETER_DESCRIPTOR_VALUE_OPS_LOCK.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        struct Restore(ParameterDescriptorValueOps);
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { PARAMETER_DESCRIPTOR_VALUE_OPS = self.0; } }
        }
        unsafe {
            let _restore = Restore(core::ptr::read_volatile(
                core::ptr::addr_of!(PARAMETER_DESCRIPTOR_VALUE_OPS)));
            PARAMETER_DESCRIPTOR_VALUE_OPS = ParameterDescriptorValueOps {
                resolve: rejecting_resolver,
            };
            for status in [i32::MIN, -1, 0, 1, 2, i32::MAX] {
                let mut output = 0xfeed_face;
                assert_eq!(parameter_descriptor_new(&mut output,
                    core::ptr::addr_of!(status).cast(), 0xffff_ffff, 0x89ab_cdef), status);
                assert_eq!(output, 0);
            }
        }
    }
}
