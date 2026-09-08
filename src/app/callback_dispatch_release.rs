//! `callback_dispatch_release` — original: `FUN_08124c60` @ `0x08124c60`
//! (56 bytes, `0x08124c60..0x08124c98`; the next separately linked function
//! starts at `0x08124c98`).
//!
//! Raw ARM calls the unported `FUN_08124ff4` with the supplied context and
//! callback, fixed dispatch flags `{1, 0}`, and the third argument as its stack
//! fifth argument. It saves that result, then, only for a non-NULL callback,
//! invokes the callback's vtable slot `+0x04` with the callback as its sole
//! argument; the saved helper result is returned unchanged.
//!
//! **19 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`.
//! The call sites are 0x081014b0, 0x08101938, 0x08142cc0, 0x0814713c,
//! 0x0817edd8, 0x0817ffac, 0x0817ffd0, 0x081812e4, 0x081814f0, 0x08181554,
//! 0x08181648, 0x0818166c, 0x08184050, 0x081b2e34, 0x081b354c, 0x081f9080,
//! 0x081f9df8, 0x081f9f24, and 0x08288aec.
//!
//! Deliberate deviation: `FUN_08124ff4` is not ported. Target builds call its
//! fixed retailOS address; host tests use a volatile dispatch seam. The vtable
//! is structurally widened on 64-bit hosts, while retaining the target slot's
//! `+0x04` role.

use core::ptr::addr_of;

const RETAIL_VALUE_DISPATCH: usize = 0x0812_4ff4;

/// Object whose first word points to a vtable with a finalization entry.
#[repr(C)]
pub struct DispatchValue {
    pub vtable: *const DispatchValueVtable,
}

/// Recovered part of a dispatched value's vtable.
///
/// The finalizer is slot `+0x04` on the 32-bit target. Its host position is
/// naturally pointer-width sized, so the named slot models the role rather
/// than a host byte offset.
#[repr(C)]
pub struct DispatchValueVtable {
    pub unresolved_00: usize,
    pub finalize: unsafe extern "C" fn(*mut DispatchValue),
}

/// ABI of the unported retail dispatcher at `0x08124ff4`.
pub type ValueDispatch = unsafe extern "C" fn(
    *mut u8,
    *mut DispatchValue,
    u32,
    u32,
    u32,
) -> u32;

/// Host seam for the unported value dispatcher.
#[derive(Clone, Copy)]
pub struct DispatchAndDestroyValueOps {
    pub dispatch: ValueDispatch,
}

#[cfg(target_os = "none")]
unsafe fn retail_value_dispatch(
    context: *mut u8,
    value: *mut DispatchValue,
    dispatch_enabled: u32,
    reserved: u32,
    extra: u32,
) -> u32 {
    let dispatch: ValueDispatch = core::mem::transmute(RETAIL_VALUE_DISPATCH);
    dispatch(context, value, dispatch_enabled, reserved, extra)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_value_dispatch(
    _context: *mut u8,
    _value: *mut DispatchValue,
    _dispatch_enabled: u32,
    _reserved: u32,
    _extra: u32,
) -> u32 {
    panic!("install value-dispatch host operations before calling this wrapper")
}

/// Host default before a test installs the retail dispatch equivalent.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_DISPATCH_AND_DESTROY_VALUE_OPS: DispatchAndDestroyValueOps =
    DispatchAndDestroyValueOps { dispatch: missing_value_dispatch };

/// Host-side dispatcher seam. Target builds always call `0x08124ff4`.
#[cfg(not(target_os = "none"))]
pub static mut DISPATCH_AND_DESTROY_VALUE_OPS: DispatchAndDestroyValueOps =
    DEFAULT_DISPATCH_AND_DESTROY_VALUE_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_value_dispatch(
    context: *mut u8,
    value: *mut DispatchValue,
    dispatch_enabled: u32,
    reserved: u32,
    extra: u32,
) -> u32 {
    let dispatch = core::ptr::read_volatile(addr_of!(DISPATCH_AND_DESTROY_VALUE_OPS.dispatch));
    dispatch(context, value, dispatch_enabled, reserved, extra)
}

/// Calls `FUN_08124ff4` for `value`, then invokes its vtable slot `+0x04`
/// release entry when it is non-NULL.
///
/// The raw function fixes the helper flags to `1` and `0`, preserving `extra`
/// as the helper's fifth ABI argument. It returns the helper's result, not any
/// value left in `r0` by the release entry.
///
/// # Safety
///
/// `context` and `value` must meet the unported helper's requirements. A
/// non-NULL `value` must point to a readable vtable with a valid slot `+0x04`
/// release entry; stock code has no vtable or slot NULL guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_dispatch_release(
    context: *mut u8,
    value: *mut DispatchValue,
    extra: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    let result = retail_value_dispatch(context, value, 1, 0, extra);
    #[cfg(not(target_os = "none"))]
    let result = host_value_dispatch(context, value, 1, 0, extra);

    if !value.is_null() {
        let vtable = core::ptr::read_volatile(addr_of!((*value).vtable));
        ((*vtable).finalize)(value);
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCH_CALL: Option<(*mut u8, *mut DispatchValue, u32, u32, u32)> = None;
    static mut FINALIZE_CALL: *mut DispatchValue = core::ptr::null_mut();
    static mut ORDER: [u8; 2] = [0; 2];
    static mut ORDER_LEN: usize = 0;

    unsafe fn record_order(event: u8) {
        ORDER[ORDER_LEN] = event;
        ORDER_LEN += 1;
    }

    unsafe extern "C" fn record_dispatch(
        context: *mut u8,
        value: *mut DispatchValue,
        dispatch_enabled: u32,
        reserved: u32,
        extra: u32,
    ) -> u32 {
        DISPATCH_CALL = Some((context, value, dispatch_enabled, reserved, extra));
        record_order(1);
        0x7a31_c0de
    }

    unsafe extern "C" fn record_finalize(value: *mut DispatchValue) {
        FINALIZE_CALL = value;
        record_order(2);
    }

    static VTABLE: DispatchValueVtable = DispatchValueVtable {
        unresolved_00: 0,
        finalize: record_finalize,
    };

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(DISPATCH_CALL).write(None);
            addr_of_mut!(FINALIZE_CALL).write(core::ptr::null_mut());
            addr_of_mut!(ORDER).write([0; 2]);
            addr_of_mut!(ORDER_LEN).write(0);
            addr_of_mut!(DISPATCH_AND_DESTROY_VALUE_OPS).write(DispatchAndDestroyValueOps {
                dispatch: record_dispatch,
            });
        }
        guard
    }

    fn restore_default(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(DISPATCH_AND_DESTROY_VALUE_OPS)
                .write(DEFAULT_DISPATCH_AND_DESTROY_VALUE_OPS);
        }
        drop(guard);
    }

    #[test]
    fn dispatches_fixed_flags_then_finalizes_and_preserves_result() {
        let guard = install_recorder();
        let mut context = [0u8; 4];
        let mut value = DispatchValue { vtable: &VTABLE };

        let result = unsafe {
            callback_dispatch_release(context.as_mut_ptr(), addr_of_mut!(value), 0x9e37_79b9)
        };

        unsafe {
            assert_eq!(
                addr_of!(DISPATCH_CALL).read(),
                Some((context.as_mut_ptr(), addr_of_mut!(value), 1, 0, 0x9e37_79b9))
            );
            assert_eq!(addr_of!(FINALIZE_CALL).read(), addr_of_mut!(value));
            assert_eq!(addr_of!(ORDER).read(), [1, 2]);
        }
        assert_eq!(result, 0x7a31_c0de);
        restore_default(guard);
    }

    #[test]
    fn forwards_null_value_without_a_finalizer_dispatch() {
        let guard = install_recorder();
        let mut context = [0u8; 4];

        let result = unsafe {
            callback_dispatch_release(context.as_mut_ptr(), core::ptr::null_mut(), 0)
        };

        unsafe {
            assert_eq!(
                addr_of!(DISPATCH_CALL).read(),
                Some((context.as_mut_ptr(), core::ptr::null_mut(), 1, 0, 0))
            );
            assert!(addr_of!(FINALIZE_CALL).read().is_null());
            assert_eq!(addr_of!(ORDER).read(), [1, 0]);
        }
        assert_eq!(result, 0x7a31_c0de);
        restore_default(guard);
    }
}
