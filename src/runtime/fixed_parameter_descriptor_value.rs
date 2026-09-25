//! Fixed parameter-descriptor value veneer — `FUN_0805108c` @ `0x0805108c` (12 bytes).
//!
//! Raw ARM extent is `0x0805108c..0x08051098`: load the fixed descriptor
//! address `0x08939b88` into r0, then tail-branch to
//! [`parameter_descriptor_value`](super::parameter_descriptor_value::parameter_descriptor_value)
//! at `0x0803b468`. The trailing literal is part of this veneer; Ghidra's
//! reported eight-byte extent omits it. Raw decoding finds three inbound direct
//! calls, all unconditional plain `bl` (none predicated), at `0x0807511c`,
//! `0x080b251c`, and `0x08396b5c`. The veneer overwrites only r0, preserving
//! r1, r2, and r3 for the target wrapper; r3 remains its opaque resolver
//! context. Rust expresses the transfer as a call; LLVM may lower it to a tail
//! branch after preserving its frame. There are no deliberate deviations.

use super::parameter_descriptor_value::parameter_descriptor_value;

/// Fixed descriptor whose address is loaded into r0 by the retail veneer.
const FIXED_PARAMETER_DESCRIPTOR: *const u8 = 0x0893_9b88 as *const u8;

/// Resolves the fixed parameter descriptor value — original: `FUN_0805108c`
/// @ `0x0805108c` (12 bytes).
///
/// Replaces the incoming r0 with the fixed descriptor address, preserves the
/// otherwise-unused r1/r2 words, and forwards the live r3 opaque context to
/// [`parameter_descriptor_value`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fixed_parameter_descriptor_value(
    _incoming_descriptor: *const u8,
    incoming_r1: u32,
    incoming_r2: u32,
    opaque_context: u32,
) -> u32 {
    parameter_descriptor_value(
        FIXED_PARAMETER_DESCRIPTOR,
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
    static mut VALUE: u32 = 0;
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
        let lock = PARAMETER_DESCRIPTOR_VALUE_OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            let saved = core::ptr::read_volatile(core::ptr::addr_of!(PARAMETER_DESCRIPTOR_VALUE_OPS));
            PARAMETER_DESCRIPTOR_VALUE_OPS = ParameterDescriptorValueOps { resolve: recording_resolve };
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
        out.write(core::ptr::read_volatile(core::ptr::addr_of!(VALUE)));
        core::ptr::read_volatile(core::ptr::addr_of!(STATUS))
    }

    #[test]
    fn substitutes_fixed_descriptor_and_forwards_live_context() {
        let _ops = install_recording_resolver();
        unsafe {
            core::ptr::addr_of_mut!(STATUS).write(1);
            core::ptr::addr_of_mut!(VALUE).write(0xa5a5_5a5a);
            assert_eq!(
                fixed_parameter_descriptor_value(
                    0x1234_5000usize as *const u8,
                    0x1111_1111,
                    0x2222_2222,
                    0x3344_5566,
                ),
                0xa5a5_5a5a,
            );
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_DESCRIPTOR, FIXED_PARAMETER_DESCRIPTOR);
            assert!(SEEN_CALLBACK.is_null());
            assert_eq!(SEEN_CONTEXT, 0x3344_5566);
        }
    }

    #[test]
    fn retains_target_wrapper_nonpositive_status_gate() {
        let _ops = install_recording_resolver();
        unsafe {
            for status in [0, -1, i32::MIN] {
                core::ptr::addr_of_mut!(STATUS).write(status);
                core::ptr::addr_of_mut!(VALUE).write(0xffff_ffff);
                assert_eq!(
                    fixed_parameter_descriptor_value(core::ptr::null(), 0, 0, 0),
                    0,
                    "status {status}",
                );
            }
            assert_eq!(CALLS, 3);
        }
    }
}
