//! Parameter descriptor value resolution — `FUN_0803b468` @ `0x0803b468` (44 bytes).
//!
//! Raw ARM extent is `0x0803b468..0x0803b494`: zero a stack output word, call
//! the unported descriptor resolver at `0x080d3a78`, then return that word
//! only when the resolver's signed status is positive; otherwise return zero.
//! Every ARM B/BL word in `osos.dec` was decoded: 14 call sites, all plain
//! unconditional `bl` (none predicated). The original sets r2 to NULL and
//! deliberately leaves its incoming r3 live for the resolver's fourth
//! argument. This port exposes the otherwise undeclared incoming registers so
//! that r3 reaches the unported resolver unchanged. The host-only seam is the
//! deliberate deviation required to observe that unmapped firmware call.

/// Unported generic descriptor resolver called by the stock wrapper.
const RETAIL_PARAMETER_DESCRIPTOR_RESOLVE: usize = 0x080d_3a78;

/// ABI of the unported generic descriptor resolver at `0x080d3a78`.
#[cfg(test)]
pub type ParameterDescriptorResolveFn =
    unsafe extern "C" fn(*mut u32, *const u8, *const u8, u32) -> i32;

/// Host-only replacement for the unported descriptor resolver.
#[cfg(test)]
#[derive(Clone, Copy)]
pub struct ParameterDescriptorValueOps {
    pub resolve: ParameterDescriptorResolveFn,
}

#[cfg(test)]
unsafe extern "C" fn unavailable_parameter_descriptor_resolve(
    _out: *mut u32,
    _descriptor: *const u8,
    _callback: *const u8,
    _opaque_context: u32,
) -> i32 {
    unreachable!("host tests must install a descriptor resolver")
}

/// Host-test seam for the direct retail resolver edge.
#[cfg(test)]
pub static mut PARAMETER_DESCRIPTOR_VALUE_OPS: ParameterDescriptorValueOps =
    ParameterDescriptorValueOps {
        resolve: unavailable_parameter_descriptor_resolve,
    };

#[cfg(test)]
#[inline(always)]
unsafe fn parameter_descriptor_value_ops() -> ParameterDescriptorValueOps {
    core::ptr::read_volatile(core::ptr::addr_of!(PARAMETER_DESCRIPTOR_VALUE_OPS))
}

/// parameter_descriptor_value — original: `FUN_0803b468` @ `0x0803b468`
/// (44 bytes).
///
/// Calls the generic descriptor resolver with a zeroed output word, a NULL
/// callback, and the caller's live r3 context. Returns the resolved word only
/// when the signed resolver status is greater than zero; all other statuses
/// return zero, even if the resolver wrote an output value.
#[cfg(not(test))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parameter_descriptor_value(
    descriptor: *const u8,
    _incoming_r1: u32,
    _incoming_r2: u32,
    opaque_context: u32,
) -> u32 {
    let mut value = 0;
    let resolve: unsafe extern "C" fn(*mut u32, *const u8, *const u8, u32) -> i32 =
        core::mem::transmute(RETAIL_PARAMETER_DESCRIPTOR_RESOLVE);
    let status = resolve(
        core::ptr::addr_of_mut!(value),
        descriptor,
        core::ptr::null(),
        opaque_context,
    );
    if status > 0 { value } else { 0 }
}

/// Host-test counterpart of [`parameter_descriptor_value`].
#[cfg(test)]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parameter_descriptor_value(
    descriptor: *const u8,
    _incoming_r1: u32,
    _incoming_r2: u32,
    opaque_context: u32,
) -> u32 {
    let mut value = 0;
    let status = (parameter_descriptor_value_ops().resolve)(
        core::ptr::addr_of_mut!(value),
        descriptor,
        core::ptr::null(),
        opaque_context,
    );
    if status > 0 { value } else { 0 }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
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
        let lock = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
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
    fn returns_output_only_for_positive_signed_status() {
        let _ops = install_recording_resolver();
        let descriptor = 0x1234_5000usize as *const u8;

        for (status, expected) in [
            (1, 0xa5a5_5a5a),
            (i32::MAX, 0xa5a5_5a5a),
            (0, 0),
            (-1, 0),
            (i32::MIN, 0),
        ] {
            unsafe {
                core::ptr::addr_of_mut!(STATUS).write(status);
                core::ptr::addr_of_mut!(RESOLVED_VALUE).write(0xa5a5_5a5a);
                assert_eq!(
                    parameter_descriptor_value(descriptor, 0x1111_1111, 0x2222_2222, 0x3344_5566),
                    expected,
                    "status {status}"
                );
            }
        }

        assert_eq!(unsafe { CALLS }, 5, "one resolver call per invocation");
    }

    #[test]
    fn forwards_descriptor_null_callback_and_live_context() {
        let _ops = install_recording_resolver();
        let descriptor = 0x89ab_c000usize as *const u8;

        unsafe {
            core::ptr::addr_of_mut!(STATUS).write(1);
            core::ptr::addr_of_mut!(RESOLVED_VALUE).write(0xfeed_face);
            assert_eq!(
                parameter_descriptor_value(descriptor, 0x0102_0304, 0x0506_0708, 0xcafe_babe),
                0xfeed_face
            );
            assert_eq!(CALLS, 1);
            assert_eq!(SEEN_DESCRIPTOR, descriptor);
            assert!(SEEN_CALLBACK.is_null());
            assert_eq!(SEEN_CONTEXT, 0xcafe_babe);
        }
    }
}
