//! Global parameter-descriptor value veneer — `FUN_0803a550` @ `0x0803a550` (12 bytes).
//!
//! Raw ARM extent is `0x0803a550..0x0803a55c`: load the address of the global
//! parameter descriptor at `0x089062ec` into r0, then tail-branch to
//! [`parameter_descriptor_value`](super::parameter_descriptor_value::parameter_descriptor_value)
//! at `0x0803b468`. The trailing literal is part of the function; Ghidra's
//! reported eight-byte extent omits it. Every ARM B/BL word in `osos.dec` was
//! decoded: six call sites, all unconditional plain `bl` (none predicated), at
//! `0x0805f788`, `0x0805f7dc`, `0x0805f994`, `0x08060100`, `0x0806f0ec`, and
//! `0x082b4dc8`. The veneer overwrites only r0, preserving r1, r2, and r3 for
//! the target wrapper; r3 remains its opaque resolver context. Rust writes a
//! call expression, and LLVM lowers it to a tail branch after preserving its
//! frame. There are no deliberate behavioral deviations.

use super::parameter_descriptor_value::parameter_descriptor_value;

/// Global parameter descriptor whose address is loaded by the retail veneer.
const GLOBAL_PARAMETER_DESCRIPTOR: *const u8 = 0x0890_62ec as *const u8;

/// Resolves the value of the global parameter descriptor — original:
/// `FUN_0803a550` @ `0x0803a550` (12 bytes).
///
/// Replaces the incoming r0 with the global descriptor address, preserves the
/// otherwise-unused r1/r2 words, and forwards the live r3 opaque context to
/// [`parameter_descriptor_value`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn global_parameter_descriptor_value(
    _incoming_descriptor: *const u8,
    incoming_r1: u32,
    incoming_r2: u32,
    opaque_context: u32,
) -> u32 {
    parameter_descriptor_value(
        GLOBAL_PARAMETER_DESCRIPTOR,
        incoming_r1,
        incoming_r2,
        opaque_context,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::runtime::parameter_descriptor_value::{
        ParameterDescriptorValueOps, PARAMETER_DESCRIPTOR_VALUE_OPS,
        PARAMETER_DESCRIPTOR_VALUE_OPS_LOCK,
    };
    use std::sync::MutexGuard;

    static mut STATUS: i32 = 0;
    static mut RESOLVED_VALUE: u32 = 0;
    static mut CALLS: usize = 0;
    static mut SEEN_DESCRIPTOR: *const u8 = core::ptr::null();
    static mut SEEN_CALLBACK: *const u8 = 1 as *const u8;
    static mut SEEN_CONTEXT: u32 = 0;

    struct TestOps {
        _lock: MutexGuard<'static, ()>,
        saved: ParameterDescriptorValueOps,
    }

    impl Drop for TestOps {
        fn drop(&mut self) {
            unsafe { PARAMETER_DESCRIPTOR_VALUE_OPS = self.saved };
        }
    }

    fn install_recording_resolver() -> TestOps {
        let lock = PARAMETER_DESCRIPTOR_VALUE_OPS_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(PARAMETER_DESCRIPTOR_VALUE_OPS));
            PARAMETER_DESCRIPTOR_VALUE_OPS = ParameterDescriptorValueOps {
                resolve: recording_resolve,
            };
            core::ptr::addr_of_mut!(CALLS).write(0);
            core::ptr::addr_of_mut!(SEEN_DESCRIPTOR).write(core::ptr::null());
            core::ptr::addr_of_mut!(SEEN_CALLBACK).write(1 as *const u8);
            core::ptr::addr_of_mut!(SEEN_CONTEXT).write(0);
            TestOps { _lock: lock, saved }
        }
    }

    unsafe extern "C" fn recording_resolve(
        out: *mut u32,
        descriptor: *const u8,
        callback: *const u8,
        opaque_context: u32,
    ) -> i32 {
        let calls = core::ptr::addr_of!(CALLS).read();
        core::ptr::addr_of_mut!(CALLS).write(calls + 1);
        core::ptr::addr_of_mut!(SEEN_DESCRIPTOR).write(descriptor);
        core::ptr::addr_of_mut!(SEEN_CALLBACK).write(callback);
        core::ptr::addr_of_mut!(SEEN_CONTEXT).write(opaque_context);
        out.write(core::ptr::read_volatile(core::ptr::addr_of!(RESOLVED_VALUE)));
        core::ptr::read_volatile(core::ptr::addr_of!(STATUS))
    }

    #[test]
    fn substitutes_global_descriptor_and_forwards_live_context() {
        let _ops = install_recording_resolver();

        unsafe {
            core::ptr::addr_of_mut!(STATUS).write(1);
            core::ptr::addr_of_mut!(RESOLVED_VALUE).write(0xd15c_a11e);
            assert_eq!(
                global_parameter_descriptor_value(
                    0x1234_5000usize as *const u8,
                    0x0102_0304,
                    0x0506_0708,
                    0xcafe_babe,
                ),
                0xd15c_a11e,
            );
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_DESCRIPTOR, GLOBAL_PARAMETER_DESCRIPTOR);
            assert!(SEEN_CALLBACK.is_null());
            assert_eq!(SEEN_CONTEXT, 0xcafe_babe);
        }
    }

    #[test]
    fn preserves_descriptor_wrapper_nonpositive_status_gate() {
        let _ops = install_recording_resolver();

        for status in [0, -1, i32::MIN] {
            unsafe {
                core::ptr::addr_of_mut!(STATUS).write(status);
                core::ptr::addr_of_mut!(RESOLVED_VALUE).write(0xffff_ffff);
                assert_eq!(
                    global_parameter_descriptor_value(
                        core::ptr::null(),
                        0,
                        u32::MAX,
                        0x89ab_cdef,
                    ),
                    0,
                    "status {status}",
                );
                assert_eq!(SEEN_DESCRIPTOR, GLOBAL_PARAMETER_DESCRIPTOR);
                assert_eq!(SEEN_CONTEXT, 0x89ab_cdef);
            }
        }
        assert_eq!(unsafe { CALLS }, 3);
    }
}
